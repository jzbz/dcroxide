// SPDX-License-Identifier: ISC
//! dcrd's own ticket database serialization tests
//! (ticketdb/chainio_test.go at stake/v5 v5.0.2) ported: database info
//! rows with the upgrade bit, the best chain state with its winner
//! list, per-block undo data with the packed flag byte, ticket hash
//! lists, and every deserialization error kind, all against dcrd's
//! exact hex vectors.  The live-database test waits for the engine
//! persistence wiring.

use core::str::FromStr;

use dcroxide_chainhash::{Hash, hash_b};
use dcroxide_stake::ticketdb::{
    BestChainState, DatabaseInfo, TicketDbErrorKind, UndoTicketData, deserialize_best_chain_state,
    deserialize_block_undo_data, deserialize_database_info, deserialize_ticket_hashes,
    parse_ticket_value, serialize_best_chain_state, serialize_block_undo_data,
    serialize_database_info, serialize_ticket_hashes, serialize_ticket_value,
};
use dcroxide_stake::tickettreap::Value;
use dcroxide_testutil::unhex;

fn hash_h(b: &[u8]) -> Hash {
    Hash(hash_b(b))
}

/// dcrd `TestDatabaseInfoSerialization`.
#[test]
fn database_info_serialization() {
    let tests = [
        (
            "not upgrade",
            DatabaseInfo {
                version: 1,
                date_unix: 0x57acca95,
                upgrade_started: false,
            },
            "0100000095caac57",
        ),
        (
            "upgrade",
            DatabaseInfo {
                version: 1,
                date_unix: 0x57acca95,
                upgrade_started: true,
            },
            "0100008095caac57",
        ),
    ];
    for (name, info, serialized) in tests {
        let want = unhex(serialized);
        assert_eq!(serialize_database_info(&info), want, "{name}: serialize");
        assert_eq!(
            deserialize_database_info(&want).expect(name),
            info,
            "{name}: deserialize"
        );
    }
}

/// dcrd `TestDbInfoDeserializeErrors`.
#[test]
fn db_info_deserialize_errors() {
    let err = deserialize_database_info(&unhex("0000")).expect_err("short read");
    assert_eq!(err.kind, TicketDbErrorKind::DatabaseInfoShortRead);
    assert_eq!(err.kind.kind_name(), "ErrDatabaseInfoShortRead");
}

/// dcrd `TestBestChainStateSerialization` with its exact hex vector.
#[test]
fn best_chain_state_serialization() {
    let state = BestChainState {
        hash: Hash::from_str("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
            .expect("hash"),
        height: 12323,
        live: 29399,
        missed: 293929392,
        revoked: 349839493,
        per_block: 5,
        next_winners: vec![
            hash_h(&[0x00]),
            hash_h(&[0x01]),
            hash_h(&[0x02]),
            hash_h(&[0x03]),
            hash_h(&[0x04]),
        ],
    };
    let serialized = unhex(
        "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d619000000000023300000d7720000b001851\
         1000000008520da140000000005000ce8d4ef4dd7cd8d62dfded9d4edb0a774ae6a41929a74da23109e8f11\
         139c874a6c419a1e25c85327115c4ace586decddfe2990ed8f3d4d801871158338501d49af37ab5270015fe\
         25276ea5a3bb159d852943df23919522a202205fb7d175cb706d561742ad3671703c247eb927ee8a386369c\
         79644131cdeb2c5c26bf6c5d4c6eb9e38415034f4c93d3304d10bef38bf0ad420eefd0f72f940f11c5857786",
    );
    assert_eq!(serialize_best_chain_state(&state), serialized, "serialize");
    assert_eq!(
        deserialize_best_chain_state(&serialized).expect("deserialize"),
        state,
        "deserialize"
    );
}

/// dcrd `TestBestChainStateDeserializeErrors`.
#[test]
fn best_chain_state_deserialize_errors() {
    let err = deserialize_best_chain_state(&unhex("0000")).expect_err("short read");
    assert_eq!(err.kind, TicketDbErrorKind::ChainStateShortRead);
}

/// dcrd `TestBlockUndoDataSerializing` with its exact hex vector.
#[test]
fn block_undo_data_serializing() {
    let utds = [
        UndoTicketData {
            ticket_hash: hash_h(&[0x00]),
            ticket_height: 123456,
            missed: true,
            revoked: false,
            spent: false,
            expired: true,
        },
        UndoTicketData {
            ticket_hash: hash_h(&[0x01]),
            ticket_height: 122222,
            missed: false,
            revoked: true,
            spent: true,
            expired: false,
        },
    ];
    let serialized = unhex(
        "0ce8d4ef4dd7cd8d62dfded9d4edb0a774ae6a41929a74da23109e8f11139c8740e20100094a6c419a1e25c\
         85327115c4ace586decddfe2990ed8f3d4d801871158338501d6edd010006",
    );
    assert_eq!(serialize_block_undo_data(&utds), serialized, "serialize");
    assert_eq!(
        deserialize_block_undo_data(&serialized).expect("deserialize"),
        utds,
        "deserialize"
    );
}

/// dcrd `TestBlockUndoDataDeserializingErrors`, plus the empty-slice
/// decode.
#[test]
fn block_undo_data_deserializing_errors() {
    let err = deserialize_block_undo_data(&unhex("00")).expect_err("short read");
    assert_eq!(err.kind, TicketDbErrorKind::UndoDataShortRead);
    let err = deserialize_block_undo_data(&[0u8; 49]).expect_err("bad size");
    assert_eq!(err.kind, TicketDbErrorKind::UndoDataCorrupt);
    assert_eq!(
        deserialize_block_undo_data(&[]).expect("empty"),
        Vec::new(),
        "empty input decodes to an empty list"
    );
}

/// dcrd `TestTicketHashesSerializing` with its exact hex vector.
#[test]
fn ticket_hashes_serializing() {
    let ths = [hash_h(&[0x00]), hash_h(&[0x01])];
    let serialized = unhex(
        "0ce8d4ef4dd7cd8d62dfded9d4edb0a774ae6a41929a74da23109e8f11139c874a6c419a1e25c85327115c4\
         ace586decddfe2990ed8f3d4d801871158338501d",
    );
    assert_eq!(serialize_ticket_hashes(&ths), serialized, "serialize");
    assert_eq!(
        deserialize_ticket_hashes(&serialized).expect("deserialize"),
        ths,
        "deserialize"
    );
}

/// dcrd `TestTicketHashesDeserializingErrors`, plus the empty-slice
/// decode.
#[test]
fn ticket_hashes_deserializing_errors() {
    let err = deserialize_ticket_hashes(&unhex("00")).expect_err("short read");
    assert_eq!(err.kind, TicketDbErrorKind::TicketHashesShortRead);
    let err = deserialize_ticket_hashes(&[0u8; 33]).expect_err("bad size");
    assert_eq!(err.kind, TicketDbErrorKind::TicketHashesCorrupt);
    assert_eq!(
        deserialize_ticket_hashes(&[]).expect("empty"),
        Vec::new(),
        "empty input decodes to an empty list"
    );
}

/// Supplementary: the individual ticket bucket row value round trip
/// used by dcrd's `DbPutTicket`/`DbLoadAllTickets`.
#[test]
fn ticket_value_round_trip() {
    let v = serialize_ticket_value(0xdeadbeef, true, false, true, false);
    assert_eq!(&v[0..4], &0xdeadbeef_u32.to_le_bytes(), "height bytes");
    assert_eq!(v[4], 0b0101, "flag byte");
    let parsed = parse_ticket_value(&v).expect("parse");
    assert_eq!(
        parsed,
        Value {
            height: 0xdeadbeef,
            missed: true,
            revoked: false,
            spent: true,
            expired: false,
        }
    );
    let err = parse_ticket_value(&v[..4]).expect_err("short");
    assert_eq!(err.kind, TicketDbErrorKind::LoadAllTickets);
}
