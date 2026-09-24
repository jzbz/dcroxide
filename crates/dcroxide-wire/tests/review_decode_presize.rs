// SPDX-License-Identifier: ISC
//! The inventory, headers and hash-list decoders size their lists once,
//! from the declared count, as dcrd's `make(..., 0, count)` does
//! (`msginv.go`, `msggetdata.go`, `msgnotfound.go`, `msgheaders.go`,
//! `msgminingstate.go`, `msginitstate.go`), capped by what the payload's
//! remaining bytes could hold.  They used to start empty and regrow as
//! they read: a 50,000-entry `inv` went through about fourteen
//! reallocations and copies.
//!
//! The reservation is not observable on the wire, so these tests pin it
//! through the decoded list's capacity: a list that decodes is reserved
//! exactly its length, and a count the bytes cannot back fails with the
//! same error as before.

use dcroxide_chainhash::{Hash, hash_h};
use dcroxide_wire::{
    BlockHeader, INIT_STATE_VERSION, InvType, InvVect, MAX_BLOCK_HEADERS_PER_MSG, MAX_INV_PER_MSG,
    Message, MsgGetData, MsgHeaders, MsgInitState, MsgInv, MsgMiningState, MsgNotFound,
    PROTOCOL_VERSION, WireError, decode_message_payload, decode_message_payload_prefix,
    write_var_int,
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
