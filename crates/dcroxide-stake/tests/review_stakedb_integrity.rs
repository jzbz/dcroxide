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
//!
//! A best-node write looks each ticket bucket up once, when a ticket
//! first needs it, where dcrd's `DbPutTicket` and `DbDeleteTicket` look
//! it up for every ticket.  The rows it stages, and where it stops over a
//! missing bucket or a drifted row, must be what one named call a ticket
//! gives.

use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Error as DbError, Options};
use dcroxide_stake::stakedb::{
    StakeDbError, db_delete_ticket, db_fetch_new_tickets, db_put_ticket, init_database_state,
    write_connected_best_node, write_disconnected_best_node,
};
use dcroxide_stake::ticketdb::{
    LIVE_TICKETS_BUCKET_NAME, MISSED_TICKETS_BUCKET_NAME, REVOKED_TICKETS_BUCKET_NAME,
    TICKETS_IN_BLOCK_BUCKET_NAME, TicketDbErrorKind, UndoTicketData,
};
use dcroxide_stake::ticketnode::{Node, StakeNodeParams};
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

// ---------------------------------------------------------------------
// One bucket lookup a write, not one a ticket
// ---------------------------------------------------------------------

/// A stake database and the node it holds, with tickets in all three
/// buckets and a block to connect that moves tickets every way a block
/// can.
struct Staked {
    _dir: TempDir,
    db: Database,
    /// The node the database holds, and its block's hash.
    node: Node,
    hash: Hash,
    /// The next block's node: winners 1 and 3 vote and the other three
    /// miss, two tickets missed earlier are revoked, and three are bought.
    /// Its undo data is in that order.
    next: Node,
    /// `next`'s winners, in lottery order.
    winners: Vec<Hash>,
    /// The two tickets `next` revokes, in order.
    revoked: Vec<Hash>,
    /// The three tickets `next` buys.
    bought: Vec<Hash>,
    /// `next` without its purchases, so that neither its connect nor its
    /// disconnect begins or ends in the live bucket alone.
    quiet: Node,
}

const NEXT_HASH: Hash = Hash([0xee; 32]);

#[allow(
    clippy::arithmetic_side_effects,
    reason = "the heights of a chain a few dozen blocks long"
)]
fn staked() -> Staked {
    let dir = TempDir::new().expect("tempdir");
    let db = open_db(&dir);
    let mut node = None;
    db.update(|tx| {
        node = Some(init_database_state(tx, PARAMS, &Hash([0x01; 32]), 0).expect("init"));
        Ok(())
    })
    .expect("init update");
    let mut node = node.expect("genesis");
    let write = |node: &Node, hash: Hash| {
        db.update(|tx| {
            write_connected_best_node(tx, node, &hash).expect("write connected");
            Ok(())
        })
        .expect("update");
    };

    // Buy tickets until voting starts.
    let mut height = 0u8;
    while i64::from(node.height()) < PARAMS.stake_validation_begin_height - 1 {
        height += 1;
        let tickets: Vec<Hash> = (0..8u8).map(|i| ticket_hash(height, i)).collect();
        node = node
            .connect(Hash([height; 32]), &[], &[], &tickets)
            .expect("connect");
        write(&node, Hash([height; 32]));
    }
    // A block whose winners all miss, then one that revokes two of them,
    // so the missed and revoked buckets hold tickets too.
    let missed = node.winners().to_vec();
    height += 1;
    node = node
        .connect(Hash([height; 32]), &[], &[], &[])
        .expect("connect with every winner missed");
    write(&node, Hash([height; 32]));
    let winners = node.winners().to_vec();
    height += 1;
    node = node
        .connect(Hash([height; 32]), &winners, &missed[3..], &[])
        .expect("connect with two revocations");
    let hash = Hash([height; 32]);
    write(&node, hash);

    let winners = node.winners().to_vec();
    assert_eq!(winners.len(), 5);
    let revoked = missed[..2].to_vec();
    let bought: Vec<Hash> = (0..3u8).map(|i| ticket_hash(0xee, i)).collect();
    let next = node
        .connect(NEXT_HASH, &[winners[1], winners[3]], &revoked, &bought)
        .expect("connect the block under test");
    // Voted and missed winners in lottery order, the revocations, then
    // the purchases: (missed, revoked, spent) of each undo row.
    let moves: Vec<(bool, bool, bool)> = next
        .undo_data()
        .iter()
        .map(|u| (u.missed, u.revoked, u.spent))
        .collect();
    let (miss, vote, revoke, buy) = (
        (true, false, false),
        (false, false, true),
        (true, true, false),
        (false, false, false),
    );
    assert_eq!(
        moves,
        [miss, vote, miss, vote, miss, revoke, revoke, buy, buy, buy]
    );
    let quiet = node
        .connect(NEXT_HASH, &[winners[1], winners[3]], &revoked, &[])
        .expect("connect the block without purchases");
    Staked {
        _dir: dir,
        db,
        node,
        hash,
        next,
        winners,
        revoked,
        bought,
        quiet,
    }
}

/// The ticket moves of dcrd's `WriteConnectedBestNode`
/// (`blockchain/stake/tickets.go:916`) as dcrd makes them: one
/// `DbPutTicket` or `DbDeleteTicket` a move, each looking its bucket up
/// by name.
fn connect_one_named_call_a_ticket(
    tx: &dcroxide_database::Transaction,
    undo_data: &[UndoTicketData],
) -> Result<(), StakeDbError> {
    for u in undo_data {
        let put = |bucket: &[u8], missed: bool| {
            db_put_ticket(
                tx,
                bucket,
                &u.ticket_hash,
                u.ticket_height,
                missed,
                u.revoked,
                u.spent,
                u.expired,
            )
        };
        match (u.missed, u.revoked, u.spent) {
            (false, false, false) => put(LIVE_TICKETS_BUCKET_NAME, u.missed)?,
            (true, true, _) => {
                db_delete_ticket(tx, MISSED_TICKETS_BUCKET_NAME, &u.ticket_hash)?;
                put(REVOKED_TICKETS_BUCKET_NAME, u.missed)?;
            }
            (true, false, _) => {
                db_delete_ticket(tx, LIVE_TICKETS_BUCKET_NAME, &u.ticket_hash)?;
                put(MISSED_TICKETS_BUCKET_NAME, true)?;
            }
            (false, _, true) => db_delete_ticket(tx, LIVE_TICKETS_BUCKET_NAME, &u.ticket_hash)?,
            _ => unreachable!("no such undo row in these tests"),
        }
    }
    Ok(())
}

/// The ticket moves of dcrd's `WriteDisconnectedBestNode`
/// (`blockchain/stake/tickets.go:1021`), likewise.
fn disconnect_one_named_call_a_ticket(
    tx: &dcroxide_database::Transaction,
    child_undo_data: &[UndoTicketData],
) -> Result<(), StakeDbError> {
    for u in child_undo_data.iter().rev() {
        let put = |bucket: &[u8], missed: bool, revoked: bool, spent: bool, expired: bool| {
            db_put_ticket(
                tx,
                bucket,
                &u.ticket_hash,
                u.ticket_height,
                missed,
                revoked,
                spent,
                expired,
            )
        };
        match (u.missed, u.revoked, u.spent) {
            (false, false, false) => {
                db_delete_ticket(tx, LIVE_TICKETS_BUCKET_NAME, &u.ticket_hash)?
            }
            (true, true, _) => {
                db_delete_ticket(tx, REVOKED_TICKETS_BUCKET_NAME, &u.ticket_hash)?;
                put(
                    MISSED_TICKETS_BUCKET_NAME,
                    u.missed,
                    false,
                    u.spent,
                    u.expired,
                )?;
            }
            (true, false, _) => {
                db_delete_ticket(tx, MISSED_TICKETS_BUCKET_NAME, &u.ticket_hash)?;
                put(LIVE_TICKETS_BUCKET_NAME, false, u.revoked, u.spent, false)?;
            }
            (false, _, true) => put(
                LIVE_TICKETS_BUCKET_NAME,
                u.missed,
                u.revoked,
                false,
                u.expired,
            )?,
            _ => unreachable!("no such undo row in these tests"),
        }
    }
    Ok(())
}

/// The three ticket buckets.
const TICKET_BUCKETS: [&[u8]; 3] = [
    LIVE_TICKETS_BUCKET_NAME,
    MISSED_TICKETS_BUCKET_NAME,
    REVOKED_TICKETS_BUCKET_NAME,
];

/// A bucket's rows, or `None` for a bucket that is not there.
type Rows = Option<Vec<(Vec<u8>, Vec<u8>)>>;

/// Every row of the three ticket buckets as the transaction sees them.
fn ticket_rows(tx: &dcroxide_database::Transaction) -> [Rows; 3] {
    TICKET_BUCKETS.map(|name| {
        tx.metadata().bucket(name).map(|bucket| {
            let mut rows = Vec::new();
            bucket
                .for_each(|k, v| {
                    rows.push((k.to_vec(), v.to_vec()));
                    Ok(())
                })
                .expect("walk");
            rows
        })
    })
}

/// What a write did, as seen inside its transaction: how it ended, and
/// the ticket buckets' rows it left staged.
type Outcome = (Result<(), String>, [Rows; 3]);

/// Run `write` in a transaction that first removes the buckets named in
/// `gone` and the live row `drifted`, and report its outcome; the
/// transaction rolls back.
fn outcome(
    db: &Database,
    gone: &[&[u8]],
    drifted: Option<&Hash>,
    write: impl FnOnce(&dcroxide_database::Transaction) -> Result<(), StakeDbError>,
) -> Outcome {
    in_update(db, |tx| {
        let meta = tx.metadata();
        for name in gone {
            meta.delete_bucket(name).map_err(StakeDbError::Db)?;
        }
        if let Some(hash) = drifted {
            let live = meta.bucket(LIVE_TICKETS_BUCKET_NAME).expect("live bucket");
            live.delete(&hash.0).map_err(StakeDbError::Db)?;
        }
        let ended = write(tx).map_err(|err| format!("{err:?}"));
        Ok((ended, ticket_rows(tx)))
    })
    .expect("the damage itself succeeds")
}

/// A connect and a disconnect that move tickets every way stage exactly
/// the rows, and stop with exactly the error and the rows staged so far,
/// that one named call a ticket gives: over a sound database, over one
/// with each ticket bucket missing, with two missing, and with a live row
/// drifted away; for a block that buys tickets and for one that does not.
#[test]
fn a_best_node_write_moves_tickets_as_one_named_call_a_ticket_does() {
    for buys in [true, false] {
        let s = staked();
        let block = if buys { &s.next } else { &s.quiet };
        let damages: Vec<(Vec<&[u8]>, Option<Hash>)> = vec![
            (vec![], None),
            (vec![LIVE_TICKETS_BUCKET_NAME], None),
            (vec![MISSED_TICKETS_BUCKET_NAME], None),
            (vec![REVOKED_TICKETS_BUCKET_NAME], None),
            (
                vec![MISSED_TICKETS_BUCKET_NAME, REVOKED_TICKETS_BUCKET_NAME],
                None,
            ),
            (vec![], Some(s.winners[2])),
            (vec![REVOKED_TICKETS_BUCKET_NAME], Some(s.winners[4])),
        ];
        let mut failures = 0;
        for (gone, drifted) in &damages {
            let want = outcome(&s.db, gone, drifted.as_ref(), |tx| {
                connect_one_named_call_a_ticket(tx, block.undo_data())
            });
            let got = outcome(&s.db, gone, drifted.as_ref(), |tx| {
                write_connected_best_node(tx, block, &NEXT_HASH)
            });
            assert_eq!(
                got, want,
                "connect (buys: {buys}) with {gone:?} gone, {drifted:?} drifted"
            );
            failures += usize::from(want.0.is_err());
        }
        assert_eq!(failures, 6, "every damage but none stops the connect");

        // The same for the disconnect of that block, once it is written.
        s.db.update(|tx| {
            write_connected_best_node(tx, block, &NEXT_HASH).expect("write connected");
            Ok(())
        })
        .expect("update");
        let mut failures = 0;
        for (gone, drifted) in &damages {
            // What the disconnect takes out of the live bucket is a
            // purchase; without one, nothing can have drifted from there.
            let drifted = drifted.and_then(|_| buys.then_some(s.bought[1]));
            let want = outcome(&s.db, gone, drifted.as_ref(), |tx| {
                disconnect_one_named_call_a_ticket(tx, block.undo_data())
            });
            let got = outcome(&s.db, gone, drifted.as_ref(), |tx| {
                write_disconnected_best_node(tx, &s.node, &s.hash, block.undo_data())
            });
            assert_eq!(
                got, want,
                "disconnect (buys: {buys}) with {gone:?} gone, {drifted:?} drifted"
            );
            failures += usize::from(want.0.is_err());
        }
        let want = if buys { 6 } else { 5 };
        assert_eq!(failures, want, "the damages that stop the disconnect");
    }
}

/// A missing ticket bucket stops a write at the first ticket that needs
/// it, with the moves before it staged and none after, and is no error
/// for a write that needs no ticket from it.
#[test]
fn a_missing_ticket_bucket_stops_the_write_where_a_ticket_first_needs_it() {
    let s = staked();
    let missing = |name: &str| {
        Err(format!(
            "Ticket(TicketDbError {{ kind: UninitializedBucket, description: \"required ticket \
             database bucket {name} is missing\" }})"
        ))
    };
    let holds = |rows: &Rows, hash: &Hash| {
        rows.as_ref()
            .expect("the bucket is there")
            .iter()
            .any(|(k, _)| k[..] == hash.0)
    };
    let connect = |gone: &[&[u8]]| {
        outcome(&s.db, gone, None, |tx| {
            write_connected_best_node(tx, &s.next, &NEXT_HASH)
        })
    };
    let (_, [sound_live, sound_missed, _]) = outcome(&s.db, &[], None, |_| Ok(()));

    // No revoked bucket: the write stops at the first revocation's put.
    // Every winner has moved, that revocation's missed row is gone, the
    // second revocation's is not, and nothing was bought.
    let (ended, [live, missed, revoked]) = connect(&[REVOKED_TICKETS_BUCKET_NAME]);
    assert_eq!(ended, missing("revokedtickets"));
    assert!(revoked.is_none());
    for winner in &s.winners {
        assert!(holds(&sound_live, winner) && !holds(&live, winner));
    }
    for winner in [s.winners[0], s.winners[2], s.winners[4]] {
        assert!(holds(&missed, &winner), "a missed winner entered missed");
    }
    assert!(holds(&sound_missed, &s.revoked[0]) && !holds(&missed, &s.revoked[0]));
    assert!(holds(&missed, &s.revoked[1]), "the second revocation ran");
    assert!(!holds(&live, &s.bought[0]), "a purchase ran");

    // No missed bucket: the write stops at the first winner's put, with
    // that winner out of the live bucket and the second still in it.
    let (ended, [live, missed, _]) = connect(&[MISSED_TICKETS_BUCKET_NAME]);
    assert_eq!(ended, missing("missedtickets"));
    assert!(missed.is_none());
    assert!(!holds(&live, &s.winners[0]), "the first winner's delete");
    assert!(holds(&live, &s.winners[1]), "the second winner moved");

    // No live bucket: the write stops before any move.
    let (ended, [live, missed, _]) = connect(&[LIVE_TICKETS_BUCKET_NAME]);
    assert_eq!(ended, missing("livetickets"));
    assert!(live.is_none());
    assert_eq!(missed, sound_missed);

    // A block whose winners all vote moves nothing through the missed or
    // revoked buckets, and is written without them.
    let voted = s
        .node
        .connect(NEXT_HASH, &s.winners, &[], &[])
        .expect("connect with every winner voting");
    let (ended, [live, missed, revoked]) = outcome(
        &s.db,
        &[MISSED_TICKETS_BUCKET_NAME, REVOKED_TICKETS_BUCKET_NAME],
        None,
        |tx| write_connected_best_node(tx, &voted, &NEXT_HASH),
    );
    assert_eq!(ended, Ok(()));
    assert!(missed.is_none() && revoked.is_none());
    for winner in &s.winners {
        assert!(!holds(&live, winner), "a spent winner left the live bucket");
    }
}

/// Write `block` on `parent` and then take it off again, each with every
/// ticket bucket missing in turn, and hold each write to what one named
/// call a ticket gives.  `needs` names the buckets the block's tickets
/// pass through: without one of those the write stops and names it, and
/// without any other it is made.
fn each_bucket_missing_in_turn(
    what: &str,
    db: &Database,
    (parent, parent_hash): (&Node, &Hash),
    block: &Node,
    needs: &[&[u8]],
) {
    let check = |way: &str, gone: &[u8], got: Outcome, want: Outcome| {
        let name = String::from_utf8_lossy(gone);
        assert_eq!(got, want, "{way} of {what} without {name}");
        let ended = if needs.contains(&gone) {
            Err(format!(
                "Ticket(TicketDbError {{ kind: UninitializedBucket, description: \"required \
                 ticket database bucket {name} is missing\" }})"
            ))
        } else {
            Ok(())
        };
        assert_eq!(got.0, ended, "{way} of {what} without {name}");
    };
    for gone in TICKET_BUCKETS {
        let want = outcome(db, &[gone], None, |tx| {
            connect_one_named_call_a_ticket(tx, block.undo_data())
        });
        let got = outcome(db, &[gone], None, |tx| {
            write_connected_best_node(tx, block, &NEXT_HASH)
        });
        check("the connect", gone, got, want);
    }
    db.update(|tx| {
        write_connected_best_node(tx, block, &NEXT_HASH).expect("write connected");
        Ok(())
    })
    .expect("update");
    for gone in TICKET_BUCKETS {
        let want = outcome(db, &[gone], None, |tx| {
            disconnect_one_named_call_a_ticket(tx, block.undo_data())
        });
        let got = outcome(db, &[gone], None, |tx| {
            write_disconnected_best_node(tx, parent, parent_hash, block.undo_data())
        });
        check("the disconnect", gone, got, want);
    }
}

/// Each kind of move on its own: votes alone, misses alone, votes with
/// revocations, purchases alone, and a block that moves no ticket and so
/// needs no bucket at all.  The blocks of the tests above mix the kinds,
/// and there a move that passed over its missing bucket would not show:
/// another ticket of the block reports the same bucket, with the same
/// rows staged.
#[test]
fn each_kind_of_move_alone_stops_over_its_own_missing_bucket() {
    const LIVE: &[u8] = LIVE_TICKETS_BUCKET_NAME;
    const MISSED: &[u8] = MISSED_TICKETS_BUCKET_NAME;
    const REVOKED: &[u8] = REVOKED_TICKETS_BUCKET_NAME;
    let (miss, vote, revoke, buy) = (
        (true, false, false),
        (false, false, true),
        (true, true, false),
        (false, false, false),
    );
    let moves = |block: &Node| -> Vec<(bool, bool, bool)> {
        block
            .undo_data()
            .iter()
            .map(|u| (u.missed, u.revoked, u.spent))
            .collect()
    };

    // Every winner votes: each leaves the live bucket, and comes back to
    // it in the disconnect.
    let s = staked();
    let votes = s
        .node
        .connect(NEXT_HASH, &s.winners, &[], &[])
        .expect("connect with every winner voting");
    assert_eq!(moves(&votes), [vote; 5]);
    each_bucket_missing_in_turn("votes alone", &s.db, (&s.node, &s.hash), &votes, &[LIVE]);

    // Every winner misses: from live to missed, and back.
    let s = staked();
    let misses = s
        .node
        .connect(NEXT_HASH, &[], &[], &[])
        .expect("connect with every winner missed");
    assert_eq!(moves(&misses), [miss; 5]);
    each_bucket_missing_in_turn(
        "misses alone",
        &s.db,
        (&s.node, &s.hash),
        &misses,
        &[LIVE, MISSED],
    );

    // Every winner votes and two tickets are revoked: only a revocation
    // passes through the missed and revoked buckets.
    let s = staked();
    let revocations = s
        .node
        .connect(NEXT_HASH, &s.winners, &s.revoked, &[])
        .expect("connect with votes and revocations");
    assert_eq!(
        moves(&revocations),
        [vote, vote, vote, vote, vote, revoke, revoke]
    );
    each_bucket_missing_in_turn(
        "votes and revocations",
        &s.db,
        (&s.node, &s.hash),
        &revocations,
        &[LIVE, MISSED, REVOKED],
    );

    // Before voting starts a block only buys tickets, or moves none.
    for tickets in [3u8, 0] {
        let dir = TempDir::new().expect("tempdir");
        let db = open_db(&dir);
        let mut node = None;
        db.update(|tx| {
            node = Some(init_database_state(tx, PARAMS, &Hash([0x01; 32]), 0).expect("init"));
            Ok(())
        })
        .expect("init update");
        let genesis = node.expect("genesis");
        let bought: Vec<Hash> = (0..tickets).map(|i| ticket_hash(1, i)).collect();
        let block = genesis
            .connect(NEXT_HASH, &[], &[], &bought)
            .expect("connect before voting starts");
        assert_eq!(moves(&block), vec![buy; usize::from(tickets)]);
        let (what, needs): (&str, &[&[u8]]) = if tickets > 0 {
            ("purchases alone", &[LIVE])
        } else {
            ("a block that moves no ticket", &[])
        };
        each_bucket_missing_in_turn(what, &db, (&genesis, &Hash([0x01; 32])), &block, needs);
    }
}
