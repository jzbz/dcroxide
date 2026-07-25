// SPDX-License-Identifier: ISC
//! Replay of frozen stall-deadline vectors dumped from inside dcrd's
//! peer package at master `452c1a6c`.
//!
//! Master's `pendingDeadlines` arms one deadline per requested
//! inventory vector rather than one per expected response command, so
//! the rows carry the resulting `pendingData`/`pendingCmds` state
//! rendered exactly as `checkDeadlines` would report it — through
//! dcrd's own `invVectSummary`. That makes the summary text part of the
//! comparison, not just the table contents.
//!
//! The generator is `peer/export_deadline_dcroxide_test.go` in the dcrd
//! clone; see the header of `data/deadline_vectors.txt` for the row
//! grammar.

// Index arithmetic over pinned vector rows.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_chainhash::Hash;
use dcroxide_peer::{
    ArmOutcome, MAX_PENDING_INV_BURST, PendingDeadlines, STALL_RESPONSE_TIMEOUT,
    STALL_TICK_INTERVAL, StallReason, check_deadlines, maybe_add_deadline, maybe_remove_deadline,
    settles,
};
use dcroxide_wire::{
    InvType, InvVect, MAX_INV_PER_MSG, Message, MsgGetData, MsgGetInitState, MsgHeaders, MsgInv,
    MsgNotFound,
};

const VECTORS: &str = include_str!("data/deadline_vectors.txt");

/// The dump's deterministic hash: first byte `n`, rest zero.
fn hash_of(n: u8) -> Hash {
    let mut h = [0u8; 32];
    h[0] = n;
    Hash(h)
}

fn inv(inv_type: InvType, n: u8) -> InvVect {
    InvVect {
        inv_type,
        hash: hash_of(n),
    }
}

/// Render the pending tables the way the Go dump does: every
/// `pendingData` entry through dcrd's `invVectSummary`, sorted, then the
/// `pendingCmds` keys, sorted; `-` when a table is empty.
fn summarize(pending: &PendingDeadlines) -> (String, String) {
    let mut data: Vec<String> = pending
        .pending_invs()
        .map(|iv| StallReason::Inventory(*iv).to_string())
        .collect();
    data.sort();
    let mut cmds: Vec<String> = pending.pending_cmds().map(|c| c.to_string()).collect();
    cmds.sort();
    (join_or_dash(&data), join_or_dash(&cmds))
}

fn join_or_dash(xs: &[String]) -> String {
    if xs.is_empty() {
        return "-".to_string();
    }
    xs.join(",")
}

/// The messages the `arm` rows script, by label.
fn arm_message(label: &str) -> Message {
    match label {
        "version" => Message::GetAddr, // stands in for any no-deadline message
        "verack" => Message::VerAck,
        "mempool" => Message::MemPool,
        "getminings" => Message::GetMiningState,
        "getblocks" => Message::GetBlocks(dcroxide_wire::MsgGetBlocks(locator())),
        "getheaders" => Message::GetHeaders(dcroxide_wire::MsgGetHeaders(locator())),
        "ping" => Message::Ping(dcroxide_wire::MsgPing { nonce: 1 }),
        "getaddr" => Message::GetAddr,
        "sendheaders" => Message::SendHeaders,
        "getinitstate" => Message::GetInitState(MsgGetInitState {
            types: vec!["headblocks".to_string()],
        }),
        "getdata-empty" => get_data(&[]),
        "getdata-1block" => get_data(&[inv(InvType::BLOCK, 1)]),
        "getdata-2blocks" => get_data(&[inv(InvType::BLOCK, 1), inv(InvType::BLOCK, 2)]),
        "getdata-mixed" => get_data(&[
            inv(InvType::BLOCK, 1),
            inv(InvType::TX, 2),
            inv(InvType::MIX, 3),
        ]),
        "getdata-dup" => get_data(&[inv(InvType::BLOCK, 1), inv(InvType::BLOCK, 1)]),
        other => panic!("unknown arm label {other}"),
    }
}

/// An empty block locator, for the messages that arm nothing.
fn locator() -> dcroxide_wire::BlockLocator {
    dcroxide_wire::BlockLocator {
        protocol_version: 0,
        block_locator_hashes: Vec::new(),
        hash_stop: Hash([0u8; 32]),
    }
}

/// The block the dump delivered: a version-1 header with an explicit
/// timestamp and every other field zero, and no transactions in either
/// tree.
///
/// The timestamp is pinned rather than left zero because Go's zero
/// `time.Time` is year 1, and `writeBlockHeader` stores
/// `uint32(Timestamp.Unix())` — which wraps to 2288912640, not 0. A
/// field-by-field "all zeroes" header on this side would therefore hash
/// differently from Go's, which the `hash` rows catch.
fn dump_block() -> dcroxide_wire::MsgBlock {
    dcroxide_wire::MsgBlock {
        header: dcroxide_wire::BlockHeader {
            version: 1,
            prev_block: Hash([0u8; 32]),
            merkle_root: Hash([0u8; 32]),
            stake_root: Hash([0u8; 32]),
            vote_bits: 0,
            final_state: [0u8; 6],
            voters: 0,
            fresh_stake: 0,
            revocations: 0,
            pool_size: 0,
            bits: 0,
            sbits: 0,
            height: 0,
            size: 0,
            timestamp: 1_234_567_890,
            nonce: 0,
            extra_data: [0u8; 32],
            stake_version: 0,
        },
        transactions: Vec::new(),
        stransactions: Vec::new(),
    }
}

/// The tx the dump delivered: `wire.NewMsgTx()`, which dcroxide's
/// `Default` is documented as matching (full serialization, version 1,
/// empty inputs and outputs).
fn dump_tx() -> dcroxide_wire::MsgTx {
    dcroxide_wire::MsgTx::default()
}

fn get_data(invs: &[InvVect]) -> Message {
    Message::GetData(MsgGetData {
        inv_list: invs.to_vec(),
    })
}

/// The `clear` rows: what to arm, then what arrives.
fn clear_case(label: &str) -> (Vec<InvVect>, Message, Option<Hash>) {
    let block = dump_block();
    let block_iv = InvVect {
        inv_type: InvType::BLOCK,
        hash: block.block_hash(),
    };
    let tx = dump_tx();
    let tx_iv = InvVect {
        inv_type: InvType::TX,
        hash: tx.tx_hash(),
    };

    match label {
        "block-settles-only-itself" => (
            vec![block_iv, inv(InvType::BLOCK, 9), inv(InvType::TX, 8)],
            Message::Block(block),
            None,
        ),
        "tx-settles-only-itself" => (vec![tx_iv, inv(InvType::BLOCK, 9)], Message::Tx(tx), None),
        "unrequested-block-clears-nothing" => {
            (vec![inv(InvType::BLOCK, 9)], Message::Block(block), None)
        }
        "notfound-clears-every-listed-inv" => (
            vec![
                inv(InvType::BLOCK, 1),
                inv(InvType::TX, 2),
                inv(InvType::MIX, 3),
            ],
            Message::NotFound(MsgNotFound {
                inv_list: vec![inv(InvType::BLOCK, 1), inv(InvType::TX, 2)],
            }),
            None,
        ),
        "headers-clears-nothing" => (
            vec![inv(InvType::BLOCK, 1)],
            Message::Headers(MsgHeaders {
                headers: Vec::new(),
            }),
            None,
        ),
        "inv-clears-nothing" => (
            vec![inv(InvType::BLOCK, 1)],
            Message::Inv(MsgInv {
                inv_list: Vec::new(),
            }),
            None,
        ),
        other => panic!("unknown clear label {other}"),
    }
}

#[test]
fn deadline_tables_match_dcrd_master() {
    let mut counts = std::collections::BTreeMap::new();

    for line in VECTORS.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split('|').collect();
        *counts.entry(f[0]).or_insert(0usize) += 1;

        match f[0] {
            // The constants the port must agree on.
            "const" => {
                let value: i64 = f[2].parse().expect("const value");
                let got = match f[1] {
                    "stallResponseTimeout" => STALL_RESPONSE_TIMEOUT,
                    "stallTickInterval" => STALL_TICK_INTERVAL,
                    "maxInvPerMsg" => MAX_INV_PER_MSG as i64,
                    "maxBurst" => MAX_PENDING_INV_BURST as i64,
                    other => panic!("unknown const {other}"),
                };
                assert_eq!(got, value, "{line}");
            }

            // The hashes dcrd computed, so the block and tx settlement
            // rows below are comparing real values rather than merely
            // being self-consistent.
            "hash" => {
                let want: Hash = f[2].parse().expect("dumped hash");
                let got = match f[1] {
                    "block-v1-empty" => dump_block().block_hash(),
                    "tx-new" => dump_tx().tx_hash(),
                    other => panic!("unknown hash label {other}"),
                };
                assert_eq!(got, want, "{line}");
            }

            // One sent message, and what it armed.
            "arm" => {
                let msg = arm_message(f[1]);
                // The stand-in for "version" only needs to arm nothing.
                if f[1] != "version" {
                    assert_eq!(msg.command(), f[2], "{line}: command");
                }
                let mut pending = PendingDeadlines::new();
                let outcome = maybe_add_deadline(&mut pending, &msg, STALL_RESPONSE_TIMEOUT);
                let (data, cmds) = summarize(&pending);
                assert_eq!(data, f[3], "{line}: pendingData");
                assert_eq!(cmds, f[4], "{line}: pendingCmds");
                let disconnected = outcome == ArmOutcome::ExceededPendingBurst;
                assert_eq!(disconnected.to_string(), f[5], "{line}: disconnect");
            }

            // Arm a getdata, then receive one message.
            "clear" => {
                let mut pending = PendingDeadlines::new();
                if f[1] == "initstate-settles-getinitstate" {
                    let _ = maybe_add_deadline(
                        &mut pending,
                        &Message::GetInitState(MsgGetInitState {
                            types: vec!["headblocks".to_string()],
                        }),
                        STALL_RESPONSE_TIMEOUT,
                    );
                    let received = Message::InitState(dcroxide_wire::MsgInitState::default());
                    assert_eq!(received.command(), f[2], "{line}: command");
                    maybe_remove_deadline(&mut pending, &settles(&received, None));
                    let (data, cmds) = summarize(&pending);
                    assert_eq!(data, f[3], "{line}: pendingData");
                    assert_eq!(cmds, f[4], "{line}: pendingCmds");
                    continue;
                }

                let (arm, received, mix_hash) = clear_case(f[1]);
                let _ = maybe_add_deadline(&mut pending, &get_data(&arm), STALL_RESPONSE_TIMEOUT);
                assert_eq!(received.command(), f[2], "{line}: command");
                maybe_remove_deadline(&mut pending, &settles(&received, mix_hash));
                let (data, cmds) = summarize(&pending);
                assert_eq!(data, f[3], "{line}: pendingData");
                assert_eq!(cmds, f[4], "{line}: pendingCmds");
            }

            // Each mixing message settles its own InvTypeMix entry,
            // keyed by the hash the reader computed for it.
            "clearmix" => {
                let mix_hash = f[3].parse::<Hash>().expect("mix hash");
                let armed = InvVect {
                    inv_type: InvType::MIX,
                    hash: mix_hash,
                };
                let mut pending = PendingDeadlines::new();
                let _ = maybe_add_deadline(
                    &mut pending,
                    &get_data(&[armed, inv(InvType::BLOCK, 9)]),
                    STALL_RESPONSE_TIMEOUT,
                );
                // Every mixing command settles the same way; the label
                // is the command the dump delivered.
                maybe_remove_deadline(&mut pending, &dcroxide_peer::Settles::Inventory(armed));
                let (data, cmds) = summarize(&pending);
                assert_eq!(data, f[4], "{line}: pendingData");
                assert_eq!(cmds, f[5], "{line}: pendingCmds");
            }

            // The maxBurst refusal.
            "burst" => {
                let pre: usize = f[2].parse().expect("pre-armed");
                let requested: usize = f[3].parse().expect("requested");
                let after: usize = f[4].parse().expect("after");
                let disconnected = f[6] == "true";

                let mut pending = PendingDeadlines::new();
                // Pre-arm in a distinct keyspace, matching the dump.
                if pre > 0 {
                    let seed: Vec<InvVect> = (0..pre).map(|i| burst_inv(i, 0xaa)).collect();
                    let outcome =
                        maybe_add_deadline(&mut pending, &get_data(&seed), STALL_RESPONSE_TIMEOUT);
                    assert_eq!(outcome, ArmOutcome::Armed, "{line}: pre-arm must fit");
                }
                assert_eq!(pending.pending_inv_count(), pre, "{line}: pre-armed count");

                let asked: Vec<InvVect> = (0..requested).map(|i| burst_inv(i, 0xbb)).collect();
                let outcome =
                    maybe_add_deadline(&mut pending, &get_data(&asked), STALL_RESPONSE_TIMEOUT);
                assert_eq!(
                    outcome == ArmOutcome::ExceededPendingBurst,
                    disconnected,
                    "{line}: disconnect"
                );
                assert_eq!(
                    pending.pending_inv_count(),
                    after,
                    "{line}: resulting count"
                );
            }

            // checkDeadlines timing, against the dump's error text.
            "check" => {
                const BASE: i64 = 1_000_000;
                const HOUR: i64 = 3_600_000_000_000;
                let mut pending = PendingDeadlines::new();
                let item = inv(InvType::BLOCK, 1);
                let (now, offset) = match f[1] {
                    "before-deadline" => (BASE - 1, 0),
                    "at-deadline" => (BASE, 0),
                    "offset-covers-it" => (BASE + HOUR, HOUR + 1),
                    "offset-exactly-equal" => (BASE + HOUR, HOUR),
                    "offset-one-ns-short" => (BASE + HOUR, HOUR - 1),
                    "initstate-overdue" => {
                        let _ = maybe_add_deadline(
                            &mut pending,
                            &Message::GetInitState(MsgGetInitState {
                                types: vec!["headblocks".to_string()],
                            }),
                            BASE,
                        );
                        let got = check_deadlines(&pending, BASE, 0);
                        assert_eq!(reason_text(got.as_ref()), f[2], "{line}");
                        continue;
                    }
                    "nothing-pending" => {
                        let got = check_deadlines(&pending, BASE + HOUR * 24, 0);
                        assert_eq!(reason_text(got.as_ref()), f[2], "{line}");
                        continue;
                    }
                    other => panic!("unknown check label {other}"),
                };
                let _ = maybe_add_deadline(&mut pending, &get_data(&[item]), BASE);
                let got = check_deadlines(&pending, now, offset);
                assert_eq!(reason_text(got.as_ref()), f[2], "{line}");
            }

            // Every inv type's reason text.
            "reason" => {
                let inv_type = match f[1] {
                    "block" => InvType::BLOCK,
                    "tx" => InvType::TX,
                    "mix" => InvType::MIX,
                    "error" => InvType::ERROR,
                    "filteredblock" => InvType::FILTERED_BLOCK,
                    other => panic!("unknown reason label {other}"),
                };
                let mut pending = PendingDeadlines::new();
                let _ = maybe_add_deadline(&mut pending, &get_data(&[inv(inv_type, 7)]), 0);
                let got = check_deadlines(&pending, 0, 0);
                assert_eq!(reason_text(got.as_ref()), f[2], "{line}");
            }

            other => panic!("unknown row kind {other}"),
        }
    }

    // Every row kind the dump emits must have been exercised.
    assert_eq!(counts.get("const"), Some(&4), "const rows");
    assert_eq!(counts.get("hash"), Some(&2), "hash rows");
    assert_eq!(counts.get("arm"), Some(&15), "arm rows");
    assert_eq!(counts.get("clear"), Some(&7), "clear rows");
    assert_eq!(counts.get("clearmix"), Some(&8), "clearmix rows");
    assert_eq!(counts.get("burst"), Some(&4), "burst rows");
    assert_eq!(counts.get("check"), Some(&7), "check rows");
    assert_eq!(counts.get("reason"), Some(&5), "reason rows");
}

/// The dump's burst keyspace: index in the low three bytes, a tag byte
/// separating the pre-armed set from the requested set.
fn burst_inv(i: usize, tag: u8) -> InvVect {
    let mut h = [0u8; 32];
    h[0] = (i & 0xff) as u8;
    h[1] = ((i >> 8) & 0xff) as u8;
    h[2] = ((i >> 16) & 0xff) as u8;
    h[3] = tag;
    InvVect {
        inv_type: InvType::BLOCK,
        hash: Hash(h),
    }
}

/// dcrd renders no stall as the dump's `-`, and a stall as its error.
fn reason_text(reason: Option<&StallReason>) -> String {
    match reason {
        None => "-".to_string(),
        Some(r) => r.exceeded_text(),
    }
}
