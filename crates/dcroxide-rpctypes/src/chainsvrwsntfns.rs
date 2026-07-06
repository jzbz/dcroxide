// SPDX-License-Identifier: ISC
//! Chain server websocket notification definitions (dcrd
//! rpc/jsonrpc/types `chainsvrwsntfns.go`).

use dcroxide_dcrjson::{GoType, Registry, UF_NOTIFICATION, UF_WEBSOCKET_ONLY, UsageFlag};

use crate::chainsvrresults::tx_raw_result;
use crate::{f, method, strukt};

/// dcrd `BlockConnectedNtfnMethod`.
pub const BLOCK_CONNECTED_NTFN_METHOD: &str = "blockconnected";
/// dcrd `BlockDisconnectedNtfnMethod`.
pub const BLOCK_DISCONNECTED_NTFN_METHOD: &str = "blockdisconnected";
/// dcrd `NewTicketsNtfnMethod`.
pub const NEW_TICKETS_NTFN_METHOD: &str = "newtickets";
/// dcrd `WorkNtfnMethod`.
pub const WORK_NTFN_METHOD: &str = "work";
/// dcrd `TSpendNtfnMethod`.
pub const TSPEND_NTFN_METHOD: &str = "tspend";
/// dcrd `ReorganizationNtfnMethod`.
pub const REORGANIZATION_NTFN_METHOD: &str = "reorganization";
/// dcrd `TxAcceptedNtfnMethod`.
pub const TX_ACCEPTED_NTFN_METHOD: &str = "txaccepted";
/// dcrd `TxAcceptedVerboseNtfnMethod`.
pub const TX_ACCEPTED_VERBOSE_NTFN_METHOD: &str = "txacceptedverbose";
/// dcrd `RelevantTxAcceptedNtfnMethod`.
pub const RELEVANT_TX_ACCEPTED_NTFN_METHOD: &str = "relevanttxaccepted";
/// dcrd `WinningTicketsNtfnMethod`.
pub const WINNING_TICKETS_NTFN_METHOD: &str = "winningtickets";
/// dcrd `MixMessageNtfnMethod`.
pub const MIX_MESSAGE_NTFN_METHOD: &str = "mixmessage";

/// The `BlockConnectedNtfn` type.
pub fn block_connected_ntfn() -> GoType {
    strukt(
        "BlockConnectedNtfn",
        vec![
            f("Header", GoType::String).with_json_tag("header"),
            f("SubscribedTxs", GoType::String.slice()).with_json_tag("subscribedtxs"),
        ],
    )
}

/// The `BlockDisconnectedNtfn` type.
pub fn block_disconnected_ntfn() -> GoType {
    strukt(
        "BlockDisconnectedNtfn",
        vec![f("Header", GoType::String).with_json_tag("header")],
    )
}

/// The `NewTicketsNtfn` type.
pub fn new_tickets_ntfn() -> GoType {
    strukt(
        "NewTicketsNtfn",
        vec![
            f("Hash", GoType::String),
            f("Height", GoType::Int32),
            f("StakeDiff", GoType::Int64),
            f("Tickets", GoType::String.slice()),
        ],
    )
}

/// The `WorkNtfn` type.
pub fn work_ntfn() -> GoType {
    strukt(
        "WorkNtfn",
        vec![
            f("Data", GoType::String).with_json_tag("data"),
            f("Target", GoType::String).with_json_tag("target"),
            f("Reason", GoType::String).with_json_tag("reason"),
        ],
    )
}

/// The `TSpendNtfn` type.
pub fn tspend_ntfn() -> GoType {
    strukt(
        "TSpendNtfn",
        vec![f("TSpend", GoType::String).with_json_tag("tspend")],
    )
}

/// The `ReorganizationNtfn` type.
pub fn reorganization_ntfn() -> GoType {
    strukt(
        "ReorganizationNtfn",
        vec![
            f("OldHash", GoType::String).with_json_tag("oldhash"),
            f("OldHeight", GoType::Int32).with_json_tag("oldheight"),
            f("NewHash", GoType::String).with_json_tag("newhash"),
            f("NewHeight", GoType::Int32).with_json_tag("newheight"),
        ],
    )
}

/// The `TxAcceptedNtfn` type.
pub fn tx_accepted_ntfn() -> GoType {
    strukt(
        "TxAcceptedNtfn",
        vec![
            f("TxID", GoType::String).with_json_tag("txid"),
            f("Amount", GoType::Float64).with_json_tag("amount"),
        ],
    )
}

/// The `TxAcceptedVerboseNtfn` type.
pub fn tx_accepted_verbose_ntfn() -> GoType {
    strukt(
        "TxAcceptedVerboseNtfn",
        vec![f("RawTx", tx_raw_result()).with_json_tag("rawtx")],
    )
}

/// The `RelevantTxAcceptedNtfn` type.
pub fn relevant_tx_accepted_ntfn() -> GoType {
    strukt(
        "RelevantTxAcceptedNtfn",
        vec![f("Transaction", GoType::String).with_json_tag("transaction")],
    )
}

/// The `WinningTicketsNtfn` type.
pub fn winning_tickets_ntfn() -> GoType {
    strukt(
        "WinningTicketsNtfn",
        vec![
            f("BlockHash", GoType::String),
            f("BlockHeight", GoType::Int32),
            f(
                "Tickets",
                GoType::Map(Box::new(GoType::String), Box::new(GoType::String)),
            ),
        ],
    )
}

/// The `MixMessageNtfn` type.
pub fn mix_message_ntfn() -> GoType {
    strukt(
        "MixMessageNtfn",
        vec![
            f("Command", GoType::String).with_json_tag("command"),
            f("Payload", GoType::String).with_json_tag("payload"),
        ],
    )
}

/// Register every websocket notification exactly as dcrd's
/// `chainsvrwsntfns.go` `init` function does.
pub fn register_chain_svr_ws_ntfns(registry: &mut Registry) {
    let flags = UsageFlag(UF_WEBSOCKET_ONLY.0 | UF_NOTIFICATION.0);
    let regs: Vec<(&str, GoType)> = vec![
        (BLOCK_CONNECTED_NTFN_METHOD, block_connected_ntfn()),
        (BLOCK_DISCONNECTED_NTFN_METHOD, block_disconnected_ntfn()),
        (WORK_NTFN_METHOD, work_ntfn()),
        (TSPEND_NTFN_METHOD, tspend_ntfn()),
        (NEW_TICKETS_NTFN_METHOD, new_tickets_ntfn()),
        (REORGANIZATION_NTFN_METHOD, reorganization_ntfn()),
        (TX_ACCEPTED_NTFN_METHOD, tx_accepted_ntfn()),
        (TX_ACCEPTED_VERBOSE_NTFN_METHOD, tx_accepted_verbose_ntfn()),
        (
            RELEVANT_TX_ACCEPTED_NTFN_METHOD,
            relevant_tx_accepted_ntfn(),
        ),
        (WINNING_TICKETS_NTFN_METHOD, winning_tickets_ntfn()),
        (MIX_MESSAGE_NTFN_METHOD, mix_message_ntfn()),
    ];
    for (name, typ) in regs {
        registry.must_register(&method(name), &typ.ptr(), flags);
    }
}
