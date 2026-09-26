// SPDX-License-Identifier: ISC
//! The stake node's height gates compare at dcrd's width.
//!
//! dcrd's `blockchain/stake` tickets.go gates every lottery and ticket
//! step on `node.height >= uint32(params.X())` or
//! `uint32(params.StakeValidationBeginHeight()-1)`: the `int64` parameter
//! is truncated to `uint32` and compared with the `uint32` height.  The
//! port compared `i64::from(height)` against the untruncated parameter,
//! which agrees only while the parameter lies in `1..=u32::MAX`.  Outside
//! it the gates flipped: a stake validation height of 0 makes dcrd's
//! `uint32(-1)` gate unreachable, where the port opened it at every
//! height and failed the lottery on an empty pool.
//!
//! Every expected result below was taken from dcrd itself at the parity
//! pin (b9634e01), with a Go test placed in a copy of the
//! `blockchain/stake` package driving `genesisNode`, `ConnectNode`,
//! `DisconnectNode`, `InitDatabaseState`, `LoadBestNode`,
//! `WriteConnectedBestNode` and `WriteDisconnectedBestNode` over the
//! same parameters.  No real network has such parameters, so this pins
//! the width rather than a reachable consensus difference.

use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_stake::ErrorKind;
use dcroxide_stake::stakedb::{
    StakeDbError, db_fetch_best_state, init_database_state, load_best_node,
    write_connected_best_node, write_disconnected_best_node,
};
use dcroxide_stake::ticketnode::{Node, StakeNodeParams};
use tempfile::TempDir;

fn params(stake_validation_begin_height: i64, stake_enable_height: i64) -> StakeNodeParams {
    StakeNodeParams {
        votes_per_block: 5,
        stake_validation_begin_height,
        stake_enable_height,
        ticket_expiry_blocks: 40,
    }
}

fn open_db(dir: &TempDir) -> Database {
    let opts = Options::new(dir.path().join("sdb"), 0x12141c16);
    Database::create(&opts).expect("create")
}

/// dcrd: `1 >= uint32(0-1)` is false, so connecting over an empty pool
/// with a stake validation height of 0 draws no winners and succeeds.
#[test]
fn connect_winner_gate_truncates_svh_minus_one() {
    let genesis = Node::genesis(params(0, 8));
    let node = genesis
        .connect(Hash([1; 32]), &[], &[], &[])
        .expect("dcrd connects: the uint32(-1) gate stays closed");
    assert!(node.winners().is_empty());
    assert_eq!(node.final_state(), [0u8; 6]);
}

/// dcrd: the stake enable gate is `height >= uint32(StakeEnableHeight())`.
/// At -1 it never opens, so an unknown vote is not examined; at 1 << 32
/// it truncates to 0 and opens at once, rejecting the unknown vote.
#[test]
fn connect_enable_gate_truncates_stake_enable_height() {
    let unknown = [Hash([0x77; 32])];

    Node::genesis(params(1000, -1))
        .connect(Hash([1; 32]), &unknown, &[], &[])
        .expect("dcrd connects: the uint32(-1) gate stays closed");

    let err = Node::genesis(params(1000, 1 << 32))
        .connect(Hash([1; 32]), &unknown, &[], &[])
        .expect_err("dcrd rejects: the uint32(1 << 32) gate is open at 0");
    assert_eq!(err.kind, ErrorKind::UnknownTicketSpent);
}

/// dcrd: disconnecting gates on `height >= uint32(StakeValidationBeginHeight())`;
/// at 1 << 32 that is `2 >= 0`, so the parent's lottery runs over an empty
/// pool and fails.  The connects before it keep their `uint32(1<<32 - 1)`
/// gate closed, as dcrd's do.
#[test]
fn disconnect_final_state_gate_truncates_svh() {
    let genesis = Node::genesis(params(1 << 32, 8));
    let node1 = genesis
        .connect(Hash([1; 32]), &[], &[], &[])
        .expect("connect 1");
    let node2 = node1
        .connect(Hash([2; 32]), &[], &[], &[])
        .expect("connect 2");
    assert!(node2.winners().is_empty());

    let err = node2
        .disconnect(Hash([1; 32]), &[], &[])
        .expect_err("dcrd fails: the uint32(1 << 32) gate is open at 0");
    assert_eq!(err.kind, ErrorKind::FindTicketIdxs);
}

/// dcrd: `LoadBestNode` restores winners behind `height >=
/// uint32(StakeValidationBeginHeight()-1)`; at a stake validation height
/// of 0 the genesis tip loads with no winners and a zero final state.
#[test]
fn load_best_node_gate_truncates_svh_minus_one() {
    let p = params(0, 8);
    let dir = TempDir::new().expect("tempdir");
    let db = open_db(&dir);
    let genesis_hash = Hash([0x01; 32]);
    db.update(|tx| {
        init_database_state(tx, p, &genesis_hash, 0).expect("init");
        Ok(())
    })
    .expect("init update");

    let mut loaded: Option<Result<Node, StakeDbError>> = None;
    db.view(|tx| {
        loaded = Some(load_best_node(tx, 0, &genesis_hash, &[0u8; 180], p));
        Ok(())
    })
    .expect("view");
    let node = loaded
        .expect("closure ran")
        .expect("dcrd loads: the uint32(-1) gate stays closed");
    assert!(node.winners().is_empty());
    assert_eq!(node.final_state(), [0u8; 6]);
}

/// dcrd: `WriteConnectedBestNode` and `WriteDisconnectedBestNode` copy
/// the winners behind the same `uint32(StakeValidationBeginHeight()-1)`
/// gate, so at a stake validation height of 0 they write zero winners
/// for the genesis node instead of copying its empty winner list.
#[test]
fn best_node_writes_gate_truncates_svh_minus_one() {
    let p = params(0, 8);
    let dir = TempDir::new().expect("tempdir");
    let db = open_db(&dir);
    let genesis_hash = Hash([0x01; 32]);
    let mut genesis = None;
    db.update(|tx| {
        genesis = Some(init_database_state(tx, p, &genesis_hash, 0).expect("init"));
        Ok(())
    })
    .expect("init update");
    let genesis = genesis.expect("genesis");

    db.update(|tx| {
        write_connected_best_node(tx, &genesis, &genesis_hash).expect("write connected");
        Ok(())
    })
    .expect("connected update");
    db.update(|tx| {
        write_disconnected_best_node(tx, &genesis, &genesis_hash, &[]).expect("write disconnected");
        Ok(())
    })
    .expect("disconnected update");

    let mut state = None;
    db.view(|tx| {
        state = Some(db_fetch_best_state(tx).expect("best state"));
        Ok(())
    })
    .expect("view");
    let state = state.expect("closure ran");
    assert_eq!(state.next_winners, vec![Hash::ZERO; 5]);
}
