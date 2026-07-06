// SPDX-License-Identifier: ISC
//! Websocket-only chain server command definitions (dcrd
//! rpc/jsonrpc/types `chainsvrwscmds.go`).

use dcroxide_dcrjson::{GoType, Registry, UF_WEBSOCKET_ONLY};

use crate::{f, method, strukt};

/// The `AuthenticateCmd` type (dcrd `authenticate`).
pub fn authenticate_cmd() -> GoType {
    strukt(
        "AuthenticateCmd",
        vec![
            f("Username", GoType::String),
            f("Passphrase", GoType::String),
        ],
    )
}

/// The `OutPoint` type: a transaction outpoint in a transaction
/// filter.
pub fn out_point() -> GoType {
    strukt(
        "OutPoint",
        vec![
            f("Hash", GoType::String).with_json_tag("hash"),
            f("Tree", GoType::Int8).with_json_tag("tree"),
            f("Index", GoType::Uint32).with_json_tag("index"),
        ],
    )
}

/// The `LoadTxFilterCmd` type (dcrd `loadtxfilter`).
pub fn load_tx_filter_cmd() -> GoType {
    strukt(
        "LoadTxFilterCmd",
        vec![
            f("Reload", GoType::Bool),
            f("Addresses", GoType::String.slice()),
            f("OutPoints", out_point().slice()),
        ],
    )
}

/// The `NotifyBlocksCmd` type (dcrd `notifyblocks`).
pub fn notify_blocks_cmd() -> GoType {
    strukt("NotifyBlocksCmd", vec![])
}

/// The `NotifyWorkCmd` type (dcrd `notifywork`).
pub fn notify_work_cmd() -> GoType {
    strukt("NotifyWorkCmd", vec![])
}

/// The `NotifyTSpendCmd` type (dcrd `notifytspend`).
pub fn notify_tspend_cmd() -> GoType {
    strukt("NotifyTSpendCmd", vec![])
}

/// The `NotifyWinningTicketsCmd` type (dcrd `notifywinningtickets`).
pub fn notify_winning_tickets_cmd() -> GoType {
    strukt("NotifyWinningTicketsCmd", vec![])
}

/// The `NotifyNewTicketsCmd` type (dcrd `notifynewtickets`).
pub fn notify_new_tickets_cmd() -> GoType {
    strukt("NotifyNewTicketsCmd", vec![])
}

/// The `RebroadcastWinnersCmd` type (dcrd `rebroadcastwinners`).
pub fn rebroadcast_winners_cmd() -> GoType {
    strukt("RebroadcastWinnersCmd", vec![])
}

/// The `StopNotifyBlocksCmd` type (dcrd `stopnotifyblocks`).
pub fn stop_notify_blocks_cmd() -> GoType {
    strukt("StopNotifyBlocksCmd", vec![])
}

/// The `StopNotifyWorkCmd` type (dcrd `stopnotifywork`).
pub fn stop_notify_work_cmd() -> GoType {
    strukt("StopNotifyWorkCmd", vec![])
}

/// The `StopNotifyTSpendCmd` type (dcrd `stopnotifytspend`).
pub fn stop_notify_tspend_cmd() -> GoType {
    strukt("StopNotifyTSpendCmd", vec![])
}

/// The `NotifyNewTransactionsCmd` type (dcrd `notifynewtransactions`).
pub fn notify_new_transactions_cmd() -> GoType {
    strukt(
        "NotifyNewTransactionsCmd",
        vec![f("Verbose", GoType::Bool.ptr()).with_default("false")],
    )
}

/// The `NotifyMixMessagesCmd` type (dcrd `notifymixmessages`).
pub fn notify_mix_messages_cmd() -> GoType {
    strukt("NotifyMixMessagesCmd", vec![])
}

/// The `StopNotifyMixMessagesCmd` type (dcrd
/// `stopnotifymixmessages`).
pub fn stop_notify_mix_messages_cmd() -> GoType {
    strukt("StopNotifyMixMessagesCmd", vec![])
}

/// The `SessionCmd` type (dcrd `session`).
pub fn session_cmd() -> GoType {
    strukt("SessionCmd", vec![])
}

/// The `StopNotifyNewTransactionsCmd` type (dcrd
/// `stopnotifynewtransactions`).
pub fn stop_notify_new_transactions_cmd() -> GoType {
    strukt("StopNotifyNewTransactionsCmd", vec![])
}

/// The `RescanCmd` type (dcrd `rescan`).
pub fn rescan_cmd() -> GoType {
    strukt("RescanCmd", vec![f("BlockHashes", GoType::String.slice())])
}

/// Register every websocket-only command exactly as dcrd's
/// `chainsvrwscmds.go` `init` function does.
pub fn register_chain_svr_ws_cmds(registry: &mut Registry) {
    let flags = UF_WEBSOCKET_ONLY;
    let regs: Vec<(&str, GoType)> = vec![
        ("authenticate", authenticate_cmd()),
        ("loadtxfilter", load_tx_filter_cmd()),
        ("notifyblocks", notify_blocks_cmd()),
        ("notifywork", notify_work_cmd()),
        ("notifytspend", notify_tspend_cmd()),
        ("notifynewtransactions", notify_new_transactions_cmd()),
        ("notifynewtickets", notify_new_tickets_cmd()),
        ("notifywinningtickets", notify_winning_tickets_cmd()),
        ("notifymixmessages", notify_mix_messages_cmd()),
        ("rebroadcastwinners", rebroadcast_winners_cmd()),
        ("session", session_cmd()),
        ("stopnotifyblocks", stop_notify_blocks_cmd()),
        ("stopnotifywork", stop_notify_work_cmd()),
        ("stopnotifytspend", stop_notify_tspend_cmd()),
        (
            "stopnotifynewtransactions",
            stop_notify_new_transactions_cmd(),
        ),
        ("stopnotifymixmessages", stop_notify_mix_messages_cmd()),
        ("rescan", rescan_cmd()),
    ];
    for (name, typ) in regs {
        registry.must_register(&method(name), &typ.ptr(), flags);
    }
}
