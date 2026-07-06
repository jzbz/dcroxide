// SPDX-License-Identifier: ISC
//! Websocket-only chain server result definitions (dcrd
//! rpc/jsonrpc/types `chainsvrwsresults.go`).

use dcroxide_dcrjson::GoType;

use crate::{f, strukt};

/// The `SessionResult` type (session).
pub fn session_result() -> GoType {
    strukt(
        "SessionResult",
        vec![f("SessionID", GoType::Uint64).with_json_tag("sessionid")],
    )
}

/// The `RescannedBlock` type: rescan data for a single block.
pub fn rescanned_block() -> GoType {
    strukt(
        "RescannedBlock",
        vec![
            f("Hash", GoType::String).with_json_tag("hash"),
            f("Transactions", GoType::String.slice()).with_json_tag("transactions"),
        ],
    )
}

/// The `RescanResult` type (rescan).
pub fn rescan_result() -> GoType {
    strukt(
        "RescanResult",
        vec![f("DiscoveredData", rescanned_block().slice()).with_json_tag("discovereddata")],
    )
}
