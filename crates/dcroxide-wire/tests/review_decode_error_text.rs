// SPDX-License-Identifier: ISC
//! Differential tests of the decode error *text* for transactions, block
//! headers, blocks and the mixing messages, against dcrd's own
//! `err.Error()` over the same bytes.
//!
//! The text is observable: `decoderawtransaction` and `sendrawtransaction`
//! answer "Could not decode Tx: <text>", `getrawtransaction` and
//! `submitblock` return it as an internal error, and `sendrawmixmessage`
//! answers "Could not decode mix message: <text>".  dcrd's reads over a
//! byte reader return Go's `io.EOF` ("EOF") when a read finds nothing
//! left and `io.ErrUnexpectedEOF` ("unexpected EOF") when it finds part
//! of what it needs, and its coded errors print `Func: Description`.
//! The frame differential's corruption test compares kinds only, which
//! both io errors share and which say nothing of the description, so the
//! text is pinned here, row by row for every coded check.

// Test-harness arithmetic over bounded generator values.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_chainhash::{Hash, hash_b};
use dcroxide_testutil::{Oracle, SplitMix64, hex, oracle_or_skip, unhex};
use dcroxide_wire::{
    BlockHeader, CurrencyNet, MsgBlock, MsgTx, OutPoint, PROTOCOL_VERSION, TxIn, TxOut,
    TxSerializeType, WireError, decode_message_payload, read_message, write_message,
};

fn random_tx(rng: &mut SplitMix64, ser_type: TxSerializeType) -> MsgTx {
    let mut tx = MsgTx {
        ser_type,
        version: 1,
        tx_in: (0..1 + rng.below(2))
            .map(|_| {
                let mut hash = [0u8; 32];
                rng.fill(&mut hash);
                TxIn {
                    previous_out_point: OutPoint {
                        hash: Hash(hash),
                        index: rng.next_u64() as u32,
                        tree: 0,
                    },
                    sequence: rng.next_u64() as u32,
                    value_in: rng.next_u64() as i64,
                    block_height: rng.next_u64() as u32,
                    block_index: rng.next_u64() as u32,
                    signature_script: rng.bytes(4),
                }
            })
            .collect(),
        tx_out: (0..1 + rng.below(2))
            .map(|_| TxOut {
                value: rng.next_u64() as i64,
                version: 0,
                pk_script: rng.bytes(4),
            })
            .collect(),
        lock_time: rng.next_u64() as u32,
        expiry: rng.next_u64() as u32,
    };
    if ser_type == TxSerializeType::OnlyWitness {
        tx.tx_out.clear();
    }
    tx
}

/// dcrd's error text for decoding these bytes as a transaction.
fn oracle_tx_error(oracle: &mut Oracle, bytes: &[u8]) -> Option<String> {
    let resp = oracle.call("msgtx_decode", bytes);
    resp.get("error")
        .and_then(|e| e.as_str())
        .map(ToOwned::to_owned)
}

/// Every prefix of a serialized transaction fails with dcrd's text, which
/// is "EOF" for a cut at a field boundary and "unexpected EOF" for a cut
/// inside a field.
#[test]
fn truncated_tx_errors_match_dcrd_text() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("tx truncation text differential");
    let mut seen = [false; 2];

    for ser_type in [
        TxSerializeType::Full,
        TxSerializeType::NoWitness,
        TxSerializeType::OnlyWitness,
    ] {
        for _ in 0..4 {
            let bytes = random_tx(&mut rng, ser_type).serialize();
            for cut in 0..bytes.len() {
                let prefix = &bytes[..cut];
                let ours = MsgTx::from_bytes(prefix).expect_err("a strict prefix is short");
                let theirs = oracle_tx_error(&mut oracle, prefix)
                    .unwrap_or_else(|| panic!("dcrd decoded the prefix {}", hex(prefix)));
                assert_eq!(ours.to_string(), theirs, "{ser_type:?} cut at {cut}");
                seen[usize::from(ours == WireError::Eof)] = true;
            }
        }
    }
    assert_eq!(seen, [true, true], "both io errors exercised");
}

/// The coded transaction errors print dcrd's `MessageError` text.
#[test]
fn coded_tx_errors_match_dcrd_text() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    // The version field (version 1, serialization type in the upper
    // half), an eight-byte zero amount, and a four-byte zero field.
    const FULL: &str = "01000000";
    const WITNESS_ONLY: &str = "01000200";
    const AMOUNT: &str = "0000000000000000";
    const U32: &str = "00000000";
    // A varint one past the maximum message payload of 32 MiB.
    const TOO_LONG: &str = "fe01000002";
    // A canonical varint of 2^32, past every count limit.
    const TOO_MANY: &str = "ff0000000001000000";
    let cases = [
        // Empty input and a bare version, both cut at a field boundary.
        String::new(),
        FULL.to_owned(),
        // Unknown serialization type.
        "01000300".to_owned(),
        // Non-canonical varints, one per discriminant.
        format!("{FULL}fd0100"),
        format!("{FULL}fe01000000"),
        format!("{FULL}ff0100000000000000"),
        // Too many inputs and outputs in the prefix.
        format!("{FULL}{TOO_MANY}"),
        format!("{FULL}00{TOO_MANY}"),
        // Too many inputs in a witness-only serialization.
        format!("{WITNESS_ONLY}{TOO_MANY}"),
        // A witness input count that differs from the prefix's.
        format!("{FULL}0000{U32}{U32}01"),
        // An output script and a signature script longer than the
        // maximum message payload.
        format!("{FULL}0001{AMOUNT}0000{TOO_LONG}"),
        format!("{WITNESS_ONLY}01{AMOUNT}{U32}{U32}{TOO_LONG}"),
    ];
    for case in &cases {
        let bytes = unhex(case);
        let ours = MsgTx::from_bytes(&bytes).expect_err("malformed");
        let theirs =
            oracle_tx_error(&mut oracle, &bytes).unwrap_or_else(|| panic!("dcrd decoded {case}"));
        assert_eq!(ours.to_string(), theirs, "{case}");
    }
}

/// Block header prefixes, read field by field in both implementations.
#[test]
fn truncated_header_errors_match_dcrd_text() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("header truncation text differential");
    let mut bytes = vec![0u8; 180];
    rng.fill(&mut bytes);
    for cut in 0..bytes.len() {
        let prefix = &bytes[..cut];
        let ours = BlockHeader::from_bytes(prefix).expect_err("a strict prefix is short");
        let resp = oracle.call("blockheader_decode", prefix);
        let theirs = resp["error"].as_str().expect("dcrd rejects the prefix");
        assert_eq!(ours.to_string(), theirs, "cut at {cut}");
    }
}

/// A mainnet frame around the payload, so dcrd decodes exactly these
/// bytes as the command's message.
fn frame(command: &str, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(24 + payload.len());
    frame.extend_from_slice(&CurrencyNet::MAIN_NET.0.to_le_bytes());
    let mut cmd = [0u8; 12];
    cmd[..command.len()].copy_from_slice(command.as_bytes());
    frame.extend_from_slice(&cmd);
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&hash_b(payload)[..4]);
    frame.extend_from_slice(payload);
    frame
}

/// dcrd's error text for a payload of the command, from `ReadMessage`
/// or, when that accepts it, from writing the message back out with
/// `WriteMessage`; `None` when both succeed.
fn oracle_payload_error(oracle: &mut Oracle, command: &str, payload: &[u8]) -> Option<String> {
    let frame = frame(command, payload);
    let mut req = Vec::with_capacity(8 + frame.len());
    req.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    req.extend_from_slice(&CurrencyNet::MAIN_NET.0.to_be_bytes());
    req.extend_from_slice(&frame);
    let resp = oracle.call("wire_msg", &req);
    resp.get("error")
        .and_then(|e| e.as_str())
        .map(ToOwned::to_owned)
}

/// The port's counterpart of [`oracle_payload_error`]: the read error,
/// or the write error for a message that reads.
fn payload_error(command: &str, payload: &[u8]) -> Option<WireError> {
    let net = CurrencyNet::MAIN_NET;
    match read_message(&frame(command, payload), PROTOCOL_VERSION, net) {
        Ok((msg, _)) => write_message(&msg, PROTOCOL_VERSION, net).err(),
        Err(err) => Some(err),
    }
}

/// dcrd's error text for a block payload.
fn oracle_block_error(oracle: &mut Oracle, payload: &[u8]) -> String {
    oracle_payload_error(oracle, "block", payload)
        .unwrap_or_else(|| panic!("dcrd decoded the block payload {}", hex(payload)))
}

/// Block prefixes and the block's own transaction count limits.
#[test]
fn block_errors_match_dcrd_text() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("block text differential");
    let mut header = vec![0u8; 180];
    rng.fill(&mut header);
    let (header, _) = BlockHeader::from_bytes(&header).expect("any 180 bytes decode");
    let block = MsgBlock {
        header,
        transactions: vec![random_tx(&mut rng, TxSerializeType::Full)],
        stransactions: vec![random_tx(&mut rng, TxSerializeType::Full)],
    };
    let bytes = block.serialize();

    let decode = |payload: &[u8]| {
        decode_message_payload("block", payload, PROTOCOL_VERSION).expect_err("malformed")
    };
    for cut in 0..bytes.len() {
        let prefix = &bytes[..cut];
        assert_eq!(
            decode(prefix).to_string(),
            oracle_block_error(&mut oracle, prefix),
            "cut at {cut}"
        );
    }

    // Too many regular transactions, and too many stake transactions after
    // an empty regular tree.
    let mut too_many = bytes[..180].to_vec();
    too_many.extend_from_slice(&unhex("fe00000100"));
    let mut too_many_stake = bytes[..180].to_vec();
    too_many_stake.extend_from_slice(&unhex("00fe00000100"));
    for payload in [too_many, too_many_stake] {
        let ours = decode(&payload);
        assert!(matches!(ours, WireError::TooManyTxs { .. }), "{ours:?}");
        assert_eq!(
            ours.to_string(),
            oracle_block_error(&mut oracle, &payload),
            "{}",
            hex(&payload[180..])
        );
    }
}

/// The coded errors of the eight mixing message decoders print dcrd's
/// `MessageError` text, which `sendrawmixmessage` returns: one row per
/// check each `BtcDecode` (and `readMixVects`, `readMixVect`,
/// `ReadVarBytes`, `ReadAsciiVarString`, `readTxOut`) makes, plus the
/// one encode check a decodable message can fail, a `mixdcnet` with no
/// mixed messages, which dcrd's `WriteMessage` rejects.
#[test]
fn coded_mix_errors_match_dcrd_text() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let zeros = |n: usize| "00".repeat(n);
    // Signature and identity, then session ID and run.
    let sig_id = zeros(64 + 33);
    let session_run = format!("{sig_id}{}", zeros(32 + 4));
    let amount = zeros(8);
    let negative = "ffffffffffffffff";
    // 513 (MaxMixPeers and MaxMixPairReqUTXOs + 1), 1025 (MaxMixMcount +
    // 1), and a length one past the maximum message payload.
    let peers = "fd0102";
    let mcount = "fd0104";
    let too_long = "fe01000002";
    // A mixpairreq through its input value: expiry, amount, an empty
    // script class, tx version, lock time and message count.
    let pr_head = format!("{sig_id}{}{amount}00{}{amount}", zeros(4), zeros(2 + 4 + 4));
    let outpoint = zeros(32 + 4 + 1);
    // A mixkeyxchg through its commitment: epoch, position, ECDH and
    // sntrup4591761 public keys, and the commitment.
    let ke_head = format!("{session_run}{}", zeros(8 + 4 + 33 + 1218 + 32));
    let secrets_head = format!("{session_run}{}", zeros(32));
    // An empty full-serialization transaction: no inputs or outputs, lock
    // time, expiry and no witnesses.
    let empty_tx = format!("01000000{}", zeros(1 + 1 + 4 + 4 + 1));

    let cases: Vec<(&str, String)> = vec![
        ("mixpairreq", String::new()),
        ("mixpairreq", format!("{sig_id}{}{negative}", zeros(4))),
        ("mixpairreq", format!("{sig_id}{}{amount}21", zeros(4))),
        ("mixpairreq", format!("{sig_id}{}{amount}0180", zeros(4))),
        ("mixpairreq", format!("{sig_id}{}{amount}fd0100", zeros(4))),
        (
            "mixpairreq",
            format!("{sig_id}{}{amount}00{}{negative}", zeros(4), zeros(10)),
        ),
        ("mixpairreq", format!("{pr_head}{peers}")),
        ("mixpairreq", format!("{pr_head}01{outpoint}fd0140")),
        ("mixpairreq", format!("{pr_head}01{outpoint}0022")),
        ("mixpairreq", format!("{pr_head}01{outpoint}000041")),
        ("mixpairreq", format!("{pr_head}0002")),
        ("mixpairreq", format!("{pr_head}0001{amount}0000{too_long}")),
        ("mixkeyxchg", format!("{ke_head}{peers}")),
        ("mixcphrtxt", format!("{session_run}{peers}")),
        ("mixslotres", format!("{session_run}00")),
        ("mixslotres", format!("{session_run}{mcount}")),
        ("mixslotres", format!("{session_run}0100")),
        ("mixslotres", format!("{session_run}01{peers}")),
        ("mixslotres", format!("{session_run}010121")),
        ("mixslotres", format!("{session_run}010100{peers}")),
        ("mixfactpoly", format!("{session_run}{mcount}")),
        ("mixfactpoly", format!("{session_run}0121")),
        ("mixfactpoly", format!("{session_run}00{peers}")),
        ("mixdcnet", format!("{session_run}01{mcount}14")),
        ("mixdcnet", format!("{session_run}{mcount}0114")),
        ("mixdcnet", format!("{session_run}010115")),
        ("mixdcnet", format!("{session_run}00{peers}")),
        ("mixdcnet", format!("{session_run}0000")),
        ("mixconfirm", format!("{session_run}01000300")),
        ("mixconfirm", format!("{session_run}{empty_tx}{peers}")),
        ("mixsecrets", format!("{secrets_head}{mcount}")),
        ("mixsecrets", format!("{secrets_head}0121")),
        ("mixsecrets", format!("{secrets_head}00{mcount}14")),
        ("mixsecrets", format!("{secrets_head}000115")),
        ("mixsecrets", format!("{secrets_head}0000{peers}")),
    ];
    let mut coded = 0;
    for (command, case) in &cases {
        let payload = unhex(case);
        let ours = payload_error(command, &payload)
            .unwrap_or_else(|| panic!("{command} {case}: the port accepted"));
        let theirs = oracle_payload_error(&mut oracle, command, &payload)
            .unwrap_or_else(|| panic!("{command} {case}: dcrd accepted"));
        assert_eq!(ours.to_string(), theirs, "{command} {case}");
        coded += usize::from(!ours.kind_name().is_empty());
    }
    assert_eq!(
        coded,
        cases.len() - 1,
        "every row but the empty one is coded"
    );
}
