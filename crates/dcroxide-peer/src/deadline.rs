// SPDX-License-Identifier: ISC
//! The stall-detection response deadline table (dcrd peer
//! `maybeAddDeadline`).

use std::collections::HashMap;

use crate::STALL_RESPONSE_TIMEOUT;

/// Potentially add a deadline for the appropriate expected response
/// for the passed wire protocol command (dcrd `maybeAddDeadline`).
/// Pings and getheaders are intentionally ignored, exactly as in
/// dcrd.  Deadlines are unix nanoseconds.
pub fn maybe_add_deadline(
    pending_responses: &mut HashMap<&'static str, i64>,
    msg_cmd: &str,
    now_nanos: i64,
) {
    let deadline = now_nanos.saturating_add(STALL_RESPONSE_TIMEOUT);
    match msg_cmd {
        "version" => {
            // Expects a verack message.
            pending_responses.insert("verack", deadline);
        }
        "mempool" => {
            // Expects an inv message.
            pending_responses.insert("inv", deadline);
        }
        "getblocks" => {
            // Expects an inv message.
            pending_responses.insert("inv", deadline);
        }
        "getdata" => {
            // Expects a block, tx, mix, or notfound message.
            pending_responses.insert("block", deadline);
            pending_responses.insert("tx", deadline);
            pending_responses.insert("mixpairreq", deadline);
            pending_responses.insert("mixkeyxchg", deadline);
            pending_responses.insert("mixcphrtxt", deadline);
            pending_responses.insert("mixslotres", deadline);
            pending_responses.insert("mixdcnet", deadline);
            pending_responses.insert("mixfactpoly", deadline);
            pending_responses.insert("mixconfirm", deadline);
            pending_responses.insert("mixsecrets", deadline);
            pending_responses.insert("notfound", deadline);
        }
        "getminings" => {
            pending_responses.insert("miningstate", deadline);
        }
        "getinitstate" => {
            pending_responses.insert("initstate", deadline);
        }
        _ => {}
    }
}
