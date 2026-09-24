// SPDX-License-Identifier: ISC
//! The ticket database's integrity tripwires.
//!
//! dcrd's `DbDeleteTicket` reads the row before deleting it and fails
//! with `ErrMissingKey` when it is absent
//! (`blockchain/stake/internal/ticketdb/chainio.go`), so every bucket
//! move in `WriteConnectedBestNode` and `WriteDisconnectedBestNode`
//! aborts the block's database update when the on-disk ticket buckets
//! have drifted from the in-memory stake node.  A plain bucket delete
//! succeeds on a missing key, which would commit the drift silently.
//!
//! A missing ticket database bucket has no dcrd counterpart (dcrd
//! dereferences the nil bucket), so the port reports it as
//! `ErrUninitializedBucket` naming the bucket.

use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Error as DbError, Options};
use dcroxide_stake::stakedb::{
    StakeDbError, db_delete_ticket, db_fetch_new_tickets, db_put_ticket, init_database_state,
    write_connected_best_node,
};
use dcroxide_stake::ticketdb::{
    LIVE_TICKETS_BUCKET_NAME, MISSED_TICKETS_BUCKET_NAME, TICKETS_IN_BLOCK_BUCKET_NAME,
    TicketDbErrorKind,
};
use dcroxide_stake::ticketnode::StakeNodeParams;
use tempfile::TempDir;

const PARAMS: StakeNodeParams = StakeNodeParams {
    votes_per_block: 5,
    stake_validation_begin_height: 24,
    stake_enable_height: 8,
    ticket_expiry_blocks: 40,
};

/// A distinct ticket hash per purchase height and index.
fn ticket_hash(height: u8, index: u8) -> Hash {
    let mut h = [0u8; 32];
    h[0] = height;
    h[1] = index;
    h[2] = 0xaa;
    Hash(h)
}

fn open_db(dir: &TempDir) -> Database {
    let opts = Options::new(dir.path().join("sdb"), 0x12141c16);
    Database::create(&opts).expect("create")
}

/// Run `f` in a write transaction and hand back its stake database
/// result; the transaction rolls back so each call sees the same state.
fn in_update<T>(
    db: &Database,
    f: impl FnOnce(&dcroxide_database::Transaction) -> Result<T, StakeDbError>,
) -> Result<T, StakeDbError> {
    let mut out = None;
    let rolled_back = db.update(|tx| {
        out = Some(f(tx));
        Err(DbError {
            kind: dcroxide_database::ErrorKind::Invalid,
            description: String::from("roll back"),
        })
    });
    assert!(rolled_back.is_err(), "the test transaction must roll back");
    out.expect("closure ran")
}

fn ticket_kind(err: StakeDbError) -> (TicketDbErrorKind, String) {
    match err {
        StakeDbError::Ticket(e) => (e.kind, e.description),
        other => panic!("want a ticket database error, got {other:?}"),
    }
}

#[test]
fn deleting_a_missing_ticket_row_fails_like_dcrd() {
    let dir = TempDir::new().expect("tempdir");
    let db = open_db(&dir);
    db.update(|tx| {
        init_database_state(tx, PARAMS, &Hash([0x01; 32]), 0).expect("init");
        Ok(())
    })
    .expect("init update");

    let present = Hash([0x42; 32]);
    let absent = Hash([0x43; 32]);

    // An existing row deletes as before.
    in_update(&db, |tx| {
        db_put_ticket(
            tx,
            LIVE_TICKETS_BUCKET_NAME,
            &present,
            7,
            false,
            false,
            false,
            false,
        )?;
        db_delete_ticket(tx, LIVE_TICKETS_BUCKET_NAME, &present)
    })
    .expect("deleting a present row");

    // A missing row is dcrd's ErrMissingKey, with dcrd's text: the hash
    // prints through `%v`, the byte-reversed hex.
    let err = in_update(&db, |tx| {
        db_delete_ticket(tx, LIVE_TICKETS_BUCKET_NAME, &absent)
    })
    .expect_err("deleting a missing row");
    let (kind, description) = ticket_kind(err);
    assert_eq!(kind, TicketDbErrorKind::MissingKey);
    assert_eq!(description, format!("missing key {absent} to delete"));
}

/// A block that misses a winner the on-disk live bucket does not hold:
/// dcrd's `WriteConnectedBestNode` fails the move from live to missed,
/// so the block's update never commits.
#[test]
fn connecting_over_a_drifted_live_bucket_fails() {
    let dir = TempDir::new().expect("tempdir");
    let db = open_db(&dir);
    let mut node = None;
    db.update(|tx| {
        node = Some(init_database_state(tx, PARAMS, &Hash([0x01; 32]), 0).expect("init"));
        Ok(())
    })
    .expect("init update");
    let mut node = node.expect("genesis");

    // Buy tickets until voting starts, writing each block as dcrd does.
    let mut height = 0u8;
    while i64::from(node.height()) < PARAMS.stake_validation_begin_height - 1 {
        height += 1;
        let tickets: Vec<Hash> = (0..8u8).map(|i| ticket_hash(height, i)).collect();
        node = node
            .connect(Hash([height; 32]), &[], &[], &tickets)
            .expect("connect");
        let block = Hash([height; 32]);
        db.update(|tx| {
            write_connected_best_node(tx, &node, &block).expect("write connected");
            Ok(())
        })
        .expect("update");
    }

    // The next block votes with none of its winners, so every winner
    // moves from live to missed.  Drop one winner's live row first.
    let winners = node.winners().to_vec();
    assert_eq!(winners.len(), usize::from(PARAMS.votes_per_block));
    let next = node
        .connect(Hash([0xee; 32]), &[], &[], &[])
        .expect("connect with every winner missed");
    let drifted = winners[0];
    let err = in_update(&db, |tx| {
        tx.metadata()
            .bucket(LIVE_TICKETS_BUCKET_NAME)
            .expect("live bucket")
            .delete(&drifted.0)
            .map_err(StakeDbError::Db)?;
        write_connected_best_node(tx, &next, &Hash([0xee; 32]))
    })
    .expect_err("the drifted live bucket must stop the write");
    let (kind, description) = ticket_kind(err);
    assert_eq!(kind, TicketDbErrorKind::MissingKey);
    assert_eq!(description, format!("missing key {drifted} to delete"));

    // Without the drift the same write moves the winner to missed.
    in_update(&db, |tx| {
        write_connected_best_node(tx, &next, &Hash([0xee; 32]))?;
        let meta = tx.metadata();
        let live = meta.bucket(LIVE_TICKETS_BUCKET_NAME).expect("live bucket");
        let missed = meta
            .bucket(MISSED_TICKETS_BUCKET_NAME)
            .expect("missed bucket");
        assert!(live.get(&drifted.0).is_none(), "left the live bucket");
        assert!(
            missed.get(&drifted.0).is_some(),
            "entered the missed bucket"
        );
        Ok(())
    })
    .expect("the undrifted write");
}

/// A missing bucket is reported as uninitialized and named, rather than
/// as corrupt undo data.
#[test]
fn a_missing_bucket_is_reported_as_uninitialized() {
    let dir = TempDir::new().expect("tempdir");
    let db = open_db(&dir);
    db.update(|tx| {
        init_database_state(tx, PARAMS, &Hash([0x01; 32]), 0).expect("init");
        Ok(())
    })
    .expect("init update");

    let err = in_update(&db, |tx| {
        tx.metadata()
            .delete_bucket(TICKETS_IN_BLOCK_BUCKET_NAME)
            .map_err(StakeDbError::Db)?;
        db_fetch_new_tickets(tx, 0)
    })
    .expect_err("fetching from a dropped bucket");
    let (kind, description) = ticket_kind(err);
    assert_eq!(kind, TicketDbErrorKind::UninitializedBucket);
    assert_eq!(
        description,
        "required ticket database bucket ticketsinblock is missing"
    );
}
