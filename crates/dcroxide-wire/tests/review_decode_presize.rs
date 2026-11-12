// SPDX-License-Identifier: ISC
//! The inventory, headers and hash-list decoders size their lists once,
//! from the declared count, as dcrd's `make(..., 0, count)` does
//! (`msginv.go`, `msggetdata.go`, `msgnotfound.go`, `msgheaders.go`,
//! `msgminingstate.go`, `msginitstate.go`), capped by what the payload's
//! remaining bytes could hold.  They used to start empty and regrow as
//! they read: a 50,000-entry `inv` went through about fourteen
//! reallocations and copies.  The DC-net vectors of `mixdcnet` and
//! `mixsecrets` are sized the same way, after dcrd's `make([]MixVect, x)`
//! and `make(MixVect, y)`.
//!
//! The reservation is not observable on the wire, so these tests pin it
//! through the decoded list's capacity: a list that decodes is reserved
//! exactly its length, and a count the bytes cannot back fails with the
//! same error as before.

use dcroxide_chainhash::{Hash, hash_h};
use dcroxide_wire::{
    BlockHeader, INIT_STATE_VERSION, InvType, InvVect, MAX_BLOCK_HEADERS_PER_MSG, MAX_INV_PER_MSG,
    MAX_MIX_MCOUNT, MIX_MSG_SIZE, Message, MixVect, MsgGetData, MsgHeaders, MsgInitState, MsgInv,
    MsgMiningState, MsgMixDCNet, MsgMixSecrets, MsgNotFound, PROTOCOL_VERSION, WireError,
    decode_message_payload, decode_message_payload_prefix, write_var_int,
};

fn inv_list(n: u32) -> Vec<InvVect> {
    (0..n)
        .map(|i| InvVect {
            inv_type: InvType::TX,
            hash: hash_h(&i.to_le_bytes()),
        })
        .collect()
}

fn hashes(n: u32) -> Vec<Hash> {
    (0..n).map(|i| hash_h(&i.to_be_bytes())).collect()
}

fn header(i: u32) -> BlockHeader {
    BlockHeader {
        version: 6,
        prev_block: hash_h(&i.to_le_bytes()),
        merkle_root: Hash([1; 32]),
        stake_root: Hash([2; 32]),
        vote_bits: 1,
        final_state: [3; 6],
        voters: 5,
        fresh_stake: 1,
        revocations: 0,
        pool_size: 40_960,
        bits: 0x1a2b_3c4d,
        sbits: 1_000,
        height: i,
        size: 1_000,
        timestamp: 1_700_000_000 ^ i,
        nonce: i,
        extra_data: [4; 32],
        stake_version: 9,
    }
}

/// Encode `msg` and decode it back at the current protocol version.
fn round_trip(msg: &Message) -> Message {
    let payload = msg.encode_payload(PROTOCOL_VERSION).expect("encode");
    let decoded =
        decode_message_payload(msg.command(), &payload, PROTOCOL_VERSION).expect("decode");
    assert_eq!(&decoded, msg, "{} round trip", msg.command());
    decoded
}

/// Every list that decodes is reserved once, to exactly its length.
/// The counts are chosen off the growth sizes (4, 8, ..., 1024), which
/// the old grow-as-you-read decoders overshot.
#[test]
fn decoded_lists_are_reserved_exactly() {
    for n in [3, 5, 1_000] {
        for msg in [
            Message::Inv(MsgInv {
                inv_list: inv_list(n),
            }),
            Message::GetData(MsgGetData {
                inv_list: inv_list(n),
            }),
            Message::NotFound(MsgNotFound {
                inv_list: inv_list(n),
            }),
        ] {
            let list = match round_trip(&msg) {
                Message::Inv(m) => m.inv_list,
                Message::GetData(m) => m.inv_list,
                Message::NotFound(m) => m.inv_list,
                other => panic!("unexpected {}", other.command()),
            };
            assert_eq!(list.capacity(), list.len(), "{} of {n}", msg.command());
        }

        let msg = Message::Headers(MsgHeaders {
            headers: (0..n).map(header).collect(),
        });
        let Message::Headers(decoded) = round_trip(&msg) else {
            panic!("headers decoded as another message");
        };
        assert_eq!(
            decoded.headers.capacity(),
            decoded.headers.len(),
            "headers of {n}"
        );
    }

    // The hash lists are capped at 8, 40 and 7 entries.
    let msg = Message::MiningState(MsgMiningState {
        version: 1,
        height: 100,
        block_hashes: hashes(3),
        vote_hashes: hashes(5),
    });
    let Message::MiningState(decoded) = round_trip(&msg) else {
        panic!("miningstate decoded as another message");
    };
    assert_eq!(decoded.block_hashes.capacity(), 3);
    assert_eq!(decoded.vote_hashes.capacity(), 5);

    let msg = Message::InitState(MsgInitState {
        block_hashes: hashes(5),
        vote_hashes: hashes(33),
        tspend_hashes: hashes(7),
    });
    const { assert!(PROTOCOL_VERSION >= INIT_STATE_VERSION) };
    let Message::InitState(decoded) = round_trip(&msg) else {
        panic!("initstate decoded as another message");
    };
    assert_eq!(decoded.block_hashes.capacity(), 5);
    assert_eq!(decoded.vote_hashes.capacity(), 33);
    assert_eq!(decoded.tspend_hashes.capacity(), 7);
}

/// Trailing bytes a prefix decode leaves unread do not inflate the
/// reservation past the declared count.
#[test]
fn trailing_bytes_do_not_inflate_the_reservation() {
    let msg = Message::Inv(MsgInv {
        inv_list: inv_list(3),
    });
    let mut payload = msg.encode_payload(PROTOCOL_VERSION).expect("encode");
    payload.extend_from_slice(&[0xAA; 36 * 10]);
    let Message::Inv(decoded) =
        decode_message_payload_prefix("inv", &payload, PROTOCOL_VERSION).expect("decode")
    else {
        panic!("inv decoded as another message");
    };
    assert_eq!(decoded.inv_list.capacity(), 3);
}

/// A count the bytes cannot back fails exactly as it did before the
/// reservation was capped.
#[test]
fn unbacked_counts_fail_as_before() {
    for (command, count) in [
        ("inv", MAX_INV_PER_MSG),
        ("getdata", MAX_INV_PER_MSG),
        ("notfound", MAX_INV_PER_MSG),
        ("headers", MAX_BLOCK_HEADERS_PER_MSG),
    ] {
        let mut payload = Vec::new();
        write_var_int(&mut payload, count);
        assert_eq!(
            decode_message_payload(command, &payload, PROTOCOL_VERSION),
            Err(WireError::Eof),
            "{command} declaring {count} with nothing behind it"
        );
        // One whole element and part of the next.
        let one = match command {
            "headers" => 181,
            _ => 36,
        };
        payload.extend_from_slice(&vec![0u8; one + 10]);
        assert_eq!(
            decode_message_payload(command, &payload, PROTOCOL_VERSION),
            Err(WireError::UnexpectedEof),
            "{command} declaring {count} with one element and a part"
        );
    }
}

fn dcnet(dc_net: Vec<MixVect>) -> Message {
    Message::MixDCNet(MsgMixDCNet {
        signature: [1; 64],
        identity: [2; 33],
        session_id: [3; 32],
        run: 0,
        dc_net,
        seen_slot_reserves: hashes(2),
    })
}

fn secrets(dc_net_msgs: MixVect) -> Message {
    Message::MixSecrets(MsgMixSecrets {
        signature: [1; 64],
        identity: [2; 33],
        session_id: [3; 32],
        run: 0,
        seed: [4; 32],
        slot_reserve_msgs: vec![vec![0x77; 32]],
        dc_net_msgs,
        seen_secrets: hashes(2),
    })
}

/// The decoded DC-net matrix's rows and columns.
fn dcnet_matrix(msg: &Message) -> Vec<MixVect> {
    let Message::MixDCNet(decoded) = round_trip(msg) else {
        panic!("mixdcnet decoded as another message");
    };
    decoded.dc_net
}

/// The DC-net matrix is reserved as dcrd's `make([]MixVect, x)` and
/// `make(MixVect, y)` reserve it (`msgmixdcnet.go`), and a secrets
/// message's single vector likewise (`msgmixsecrets.go`).
#[test]
fn mix_vectors_are_reserved_exactly() {
    for (x, y) in [(1, 1), (3, 5), (2, 1_000)] {
        let matrix = dcnet_matrix(&dcnet(vec![vec![[0x55; MIX_MSG_SIZE]; y]; x]));
        assert_eq!(matrix.capacity(), x, "{x}x{y} rows");
        for row in &matrix {
            assert_eq!(row.capacity(), y, "{x}x{y} columns");
        }
    }

    for n in [3, 253] {
        let Message::MixSecrets(decoded) = round_trip(&secrets(vec![[0x66; MIX_MSG_SIZE]; n]))
        else {
            panic!("mixsecrets decoded as another message");
        };
        assert_eq!(decoded.dc_net_msgs.capacity(), n, "secrets of {n}");
    }
}

/// A matrix with rows and no columns decodes, as it does in dcrd, and
/// round-trips: nothing is sized by dividing by the row width.
#[test]
fn mix_vectors_with_empty_rows_decode() {
    for x in [1, 3, MAX_MIX_MCOUNT as usize] {
        let matrix = dcnet_matrix(&dcnet(vec![MixVect::new(); x]));
        assert_eq!(matrix.len(), x);
        assert_eq!(matrix.capacity(), x, "{x}x0 rows");
        assert!(
            matrix
                .iter()
                .all(|row| row.is_empty() && row.capacity() == 0)
        );
    }

    // The same from hand-built bytes: five rows, no columns, the message
    // size, and no referenced hashes.
    let mut payload = vec![0u8; 133];
    for v in [5, 0, MIX_MSG_SIZE as u64, 0] {
        write_var_int(&mut payload, v);
    }
    let Ok(Message::MixDCNet(decoded)) =
        decode_message_payload("mixdcnet", &payload, PROTOCOL_VERSION)
    else {
        panic!("a 5x0 mixdcnet decodes");
    };
    assert_eq!(decoded.dc_net, vec![MixVect::new(); 5]);
    assert!(decoded.seen_slot_reserves.is_empty());
}

/// A DC-net dimension the bytes cannot back fails exactly as it did
/// before the vectors were reserved.
#[test]
fn unbacked_mix_vectors_fail_as_before() {
    for (x, y) in [(1, MAX_MIX_MCOUNT), (MAX_MIX_MCOUNT, MAX_MIX_MCOUNT)] {
        let mut payload = vec![0u8; 133];
        for v in [x, y, MIX_MSG_SIZE as u64] {
            write_var_int(&mut payload, v);
        }
        assert_eq!(
            decode_message_payload("mixdcnet", &payload, PROTOCOL_VERSION),
            Err(WireError::Eof),
            "{x}x{y} with nothing behind it"
        );
        payload.extend_from_slice(&[0u8; MIX_MSG_SIZE + 10]);
        assert_eq!(
            decode_message_payload("mixdcnet", &payload, PROTOCOL_VERSION),
            Err(WireError::UnexpectedEof),
            "{x}x{y} with one message and a part"
        );
    }

    // Signature, identity, session, run and seed, no slot reservations,
    // then the vector's count and message size.
    let mut payload = vec![0u8; 165];
    for v in [0, MAX_MIX_MCOUNT, MIX_MSG_SIZE as u64] {
        write_var_int(&mut payload, v);
    }
    assert_eq!(
        decode_message_payload("mixsecrets", &payload, PROTOCOL_VERSION),
        Err(WireError::Eof)
    );
    payload.extend_from_slice(&[0u8; MIX_MSG_SIZE + 10]);
    assert_eq!(
        decode_message_payload("mixsecrets", &payload, PROTOCOL_VERSION),
        Err(WireError::UnexpectedEof)
    );
}
