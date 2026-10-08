// SPDX-License-Identifier: ISC

//! The ticket database persistence layer: dcrd's
//! `internal/ticketdb` `Db*` functions and the database-coupled
//! entry points from `tickets.go` (`InitDatabaseState`,
//! `LoadBestNode`, `WriteConnectedBestNode`, and
//! `WriteDisconnectedBestNode`) over the dcroxide database, using
//! ffldb's bucket layout and the row formats pinned by the ticket
//! database serialization vectors.  The one departure is the per-height
//! rows' keys, which are big-endian where dcrd's are little-endian (see
//! [`height_key`]).

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use dcroxide_chainhash::Hash;
use dcroxide_database::Transaction;

use crate::ticketdb::{
    BestChainState, CURRENT_DATABASE_VERSION, DatabaseInfo, LIVE_TICKETS_BUCKET_NAME,
    MISSED_TICKETS_BUCKET_NAME, REVOKED_TICKETS_BUCKET_NAME, STAKE_BLOCK_UNDO_DATA_BUCKET_NAME,
    STAKE_CHAIN_STATE_KEY_NAME, STAKE_DB_INFO_BUCKET_NAME, TICKETS_IN_BLOCK_BUCKET_NAME,
    TicketDbError, TicketDbErrorKind, UndoTicketData, deserialize_best_chain_state,
    deserialize_block_undo_data, deserialize_database_info, deserialize_ticket_hashes,
    parse_ticket_value, serialize_best_chain_state, serialize_block_undo_data,
    serialize_database_info, serialize_ticket_hashes, serialize_ticket_value, ticket_db_error,
};
use crate::ticketnode::{Node, StakeNodeParams};
use crate::tickettreap::{Immutable, Key as TreapKey};
use crate::{ErrorKind, RuleError, stake_rule_error};

/// The errors the ticket database layer surfaces: underlying database
/// failures, row-level ticket database errors, and stake rule errors
/// from node reconstruction.
#[derive(Debug)]
pub enum StakeDbError {
    /// An underlying database error.
    Db(dcroxide_database::Error),
    /// A ticket database row error.
    Ticket(TicketDbError),
    /// A stake rule error.
    Rule(RuleError),
}

impl From<dcroxide_database::Error> for StakeDbError {
    fn from(err: dcroxide_database::Error) -> StakeDbError {
        StakeDbError::Db(err)
    }
}

impl From<TicketDbError> for StakeDbError {
    fn from(err: TicketDbError) -> StakeDbError {
        StakeDbError::Ticket(err)
    }
}

impl From<RuleError> for StakeDbError {
    fn from(err: RuleError) -> StakeDbError {
        StakeDbError::Rule(err)
    }
}

/// The key of a height's row in the block undo data and new tickets
/// buckets: the height, big-endian.  It is the one encoder of that key;
/// every read, write and removal of those rows goes through it.
///
/// dcrd writes it little-endian (`dbnamespace.ByteOrder`,
/// `internal/ticketdb/chainio.go:483`, `:498`, `:509`, `:572`, `:588`,
/// `:599`), which files consecutive heights apart -- they differ in the
/// key's first byte -- so every block of a metadata flush lands in a
/// different B-tree leaf and the store copies one cold leaf per block in
/// each bucket.  Big-endian files them in height order, and a flush
/// appends at each bucket's right edge instead.  Both buckets are only
/// ever read and written by point lookup, so the byte order changes
/// nothing but the layout.  The layout is dcroxide's own, and the chain
/// database's version records it
/// (`dcroxide_blockchain::chaindb::CURRENT_DATABASE_VERSION`, ADR-0010);
/// the stake database's own version is dcrd's, since the one chain
/// database version check runs before any of these rows is read.
pub fn height_key(height: u32) -> [u8; 4] {
    height.to_be_bytes()
}

/// Store the database information row (dcrd `DbPutDatabaseInfo`).
pub fn db_put_database_info(tx: &Transaction, dbi: &DatabaseInfo) -> Result<(), StakeDbError> {
    let meta = tx.metadata();
    let bucket = meta
        .bucket(STAKE_DB_INFO_BUCKET_NAME)
        .ok_or_else(|| missing_bucket(STAKE_DB_INFO_BUCKET_NAME))?;
    Ok(bucket.put(STAKE_DB_INFO_BUCKET_NAME, &serialize_database_info(dbi))?)
}

/// Fetch the database information row (dcrd `DbFetchDatabaseInfo`).
pub fn db_fetch_database_info(tx: &Transaction) -> Result<Option<DatabaseInfo>, StakeDbError> {
    let meta = tx.metadata();
    let Some(bucket) = meta.bucket(STAKE_DB_INFO_BUCKET_NAME) else {
        return Ok(None);
    };
    match bucket.get(STAKE_DB_INFO_BUCKET_NAME) {
        None => Ok(None),
        Some(v) => Ok(Some(deserialize_database_info(&v)?)),
    }
}

/// Fetch the best chain state (dcrd `DbFetchBestState`).
pub fn db_fetch_best_state(tx: &Transaction) -> Result<BestChainState, StakeDbError> {
    let v = tx
        .metadata()
        .get(STAKE_CHAIN_STATE_KEY_NAME)
        .ok_or_else(|| {
            ticket_db_error(
                TicketDbErrorKind::MissingKey,
                "missing key for chain state data",
            )
        })?;
    Ok(deserialize_best_chain_state(&v)?)
}

/// Store the best chain state (dcrd `DbPutBestState`).
pub fn db_put_best_state(tx: &Transaction, bcs: &BestChainState) -> Result<(), StakeDbError> {
    Ok(tx
        .metadata()
        .put(STAKE_CHAIN_STATE_KEY_NAME, &serialize_best_chain_state(bcs))?)
}

/// Fetch the block undo data for a height (dcrd
/// `DbFetchBlockUndoData`).
pub fn db_fetch_block_undo_data(
    tx: &Transaction,
    height: u32,
) -> Result<Vec<UndoTicketData>, StakeDbError> {
    let meta = tx.metadata();
    let bucket = meta
        .bucket(STAKE_BLOCK_UNDO_DATA_BUCKET_NAME)
        .ok_or_else(|| missing_bucket(STAKE_BLOCK_UNDO_DATA_BUCKET_NAME))?;
    let v = bucket.get(&height_key(height)).ok_or_else(|| {
        ticket_db_error(
            TicketDbErrorKind::MissingKey,
            "missing key for block undo data",
        )
    })?;
    Ok(deserialize_block_undo_data(&v)?)
}

/// Store the block undo data for a height (dcrd
/// `DbPutBlockUndoData`).
pub fn db_put_block_undo_data(
    tx: &Transaction,
    height: u32,
    utds: &[UndoTicketData],
) -> Result<(), StakeDbError> {
    let meta = tx.metadata();
    let bucket = meta
        .bucket(STAKE_BLOCK_UNDO_DATA_BUCKET_NAME)
        .ok_or_else(|| missing_bucket(STAKE_BLOCK_UNDO_DATA_BUCKET_NAME))?;
    Ok(bucket.put(&height_key(height), &serialize_block_undo_data(utds))?)
}

/// Remove the block undo data for a height (dcrd
/// `DbDropBlockUndoData`).
pub fn db_drop_block_undo_data(tx: &Transaction, height: u32) -> Result<(), StakeDbError> {
    let meta = tx.metadata();
    let bucket = meta
        .bucket(STAKE_BLOCK_UNDO_DATA_BUCKET_NAME)
        .ok_or_else(|| missing_bucket(STAKE_BLOCK_UNDO_DATA_BUCKET_NAME))?;
    Ok(bucket.delete(&height_key(height))?)
}

/// Fetch the maturing ticket hashes for a height (dcrd
/// `DbFetchNewTickets`).
pub fn db_fetch_new_tickets(tx: &Transaction, height: u32) -> Result<Vec<Hash>, StakeDbError> {
    let meta = tx.metadata();
    let bucket = meta
        .bucket(TICKETS_IN_BLOCK_BUCKET_NAME)
        .ok_or_else(|| missing_bucket(TICKETS_IN_BLOCK_BUCKET_NAME))?;
    let v = bucket.get(&height_key(height)).ok_or_else(|| {
        ticket_db_error(TicketDbErrorKind::MissingKey, "missing key for new tickets")
    })?;
    Ok(deserialize_ticket_hashes(&v)?)
}

/// Store the maturing ticket hashes for a height (dcrd
/// `DbPutNewTickets`).
pub fn db_put_new_tickets(tx: &Transaction, height: u32, ths: &[Hash]) -> Result<(), StakeDbError> {
    let meta = tx.metadata();
    let bucket = meta
        .bucket(TICKETS_IN_BLOCK_BUCKET_NAME)
        .ok_or_else(|| missing_bucket(TICKETS_IN_BLOCK_BUCKET_NAME))?;
    Ok(bucket.put(&height_key(height), &serialize_ticket_hashes(ths))?)
}

/// Remove the maturing ticket hashes for a height (dcrd
/// `DbDropNewTickets`).
pub fn db_drop_new_tickets(tx: &Transaction, height: u32) -> Result<(), StakeDbError> {
    let meta = tx.metadata();
    let bucket = meta
        .bucket(TICKETS_IN_BLOCK_BUCKET_NAME)
        .ok_or_else(|| missing_bucket(TICKETS_IN_BLOCK_BUCKET_NAME))?;
    Ok(bucket.delete(&height_key(height))?)
}

/// Remove a ticket row from the given ticket bucket (dcrd
/// `DbDeleteTicket`).  Unlike a plain bucket delete, which succeeds on a
/// missing key, this fails with `ErrMissingKey` when the row is absent,
/// so a bucket move over on-disk ticket state that has drifted from the
/// stake node aborts the block's update rather than committing it.
pub fn db_delete_ticket(
    tx: &Transaction,
    ticket_bucket: &[u8],
    hash: &Hash,
) -> Result<(), StakeDbError> {
    let meta = tx.metadata();
    let bucket = meta
        .bucket(ticket_bucket)
        .ok_or_else(|| missing_bucket(ticket_bucket))?;

    // Check to see if the value exists before we delete it.
    if bucket.get(&hash.0).is_none() {
        return Err(ticket_db_error(
            TicketDbErrorKind::MissingKey,
            &format!("missing key {hash} to delete"),
        )
        .into());
    }
    Ok(bucket.delete(&hash.0)?)
}

/// Store a ticket row in the given ticket bucket (dcrd
/// `DbPutTicket`).
#[allow(clippy::too_many_arguments)]
pub fn db_put_ticket(
    tx: &Transaction,
    ticket_bucket: &[u8],
    hash: &Hash,
    height: u32,
    missed: bool,
    revoked: bool,
    spent: bool,
    expired: bool,
) -> Result<(), StakeDbError> {
    let meta = tx.metadata();
    let bucket = meta
        .bucket(ticket_bucket)
        .ok_or_else(|| missing_bucket(ticket_bucket))?;
    Ok(bucket.put(
        &hash.0,
        &serialize_ticket_value(height, missed, revoked, spent, expired),
    )?)
}

/// Load every ticket row in the bucket into a treap (dcrd
/// `DbLoadAllTickets`).
pub fn db_load_all_tickets(
    tx: &Transaction,
    ticket_bucket: &[u8],
) -> Result<Immutable, StakeDbError> {
    let meta = tx.metadata();
    let bucket = meta
        .bucket(ticket_bucket)
        .ok_or_else(|| missing_bucket(ticket_bucket))?;
    let mut treap = Immutable::new();
    let mut rows: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    bucket.for_each(|k: &[u8], v: &[u8]| {
        rows.push((k.to_vec(), v.to_vec()));
        Ok(())
    })?;
    for (k, v) in rows {
        if k.len() != 32 {
            return Err(ticket_db_error(
                TicketDbErrorKind::LoadAllTickets,
                "invalid ticket key length when loading tickets",
            )
            .into());
        }
        let mut key: TreapKey = [0u8; 32];
        key.copy_from_slice(&k);
        let value = parse_ticket_value(&v)?;
        treap = treap.put(key, value);
    }
    Ok(treap)
}

/// Create every bucket the ticket database requires and store the
/// version information (dcrd `DbCreate`).  The creation date is a
/// parameter since dcrd stamps the current time.
pub fn db_create(tx: &Transaction, date_unix: u32) -> Result<(), StakeDbError> {
    let meta = tx.metadata();
    meta.create_bucket(STAKE_DB_INFO_BUCKET_NAME)?;
    db_put_database_info(
        tx,
        &DatabaseInfo {
            date_unix,
            version: CURRENT_DATABASE_VERSION,
            upgrade_started: false,
        },
    )?;
    meta.create_bucket(LIVE_TICKETS_BUCKET_NAME)?;
    meta.create_bucket(MISSED_TICKETS_BUCKET_NAME)?;
    meta.create_bucket(REVOKED_TICKETS_BUCKET_NAME)?;
    meta.create_bucket(STAKE_BLOCK_UNDO_DATA_BUCKET_NAME)?;
    meta.create_bucket(TICKETS_IN_BLOCK_BUCKET_NAME)?;
    Ok(())
}

/// Initialize the ticket database and return the genesis stake node
/// (dcrd `InitDatabaseState`).
pub fn init_database_state(
    tx: &Transaction,
    params: StakeNodeParams,
    genesis_hash: &Hash,
    date_unix: u32,
) -> Result<Node, StakeDbError> {
    db_create(tx, date_unix)?;

    let genesis = Node::genesis(params);
    db_put_block_undo_data(tx, genesis.height(), genesis.undo_data())?;
    db_put_new_tickets(tx, genesis.height(), genesis.new_tickets())?;

    let next_winners = vec![Hash::ZERO; usize::from(params.votes_per_block)];
    db_put_best_state(
        tx,
        &BestChainState {
            hash: *genesis_hash,
            height: genesis.height(),
            live: genesis.pool_size() as u32,
            missed: genesis.missed_treap().len() as u64,
            revoked: genesis.revoked_treap().len() as u64,
            per_block: params.votes_per_block,
            next_winners,
        },
    )?;
    Ok(genesis)
}

/// Load the best stake node from the database, verifying it matches
/// the provided chain location and recomputing the final lottery
/// state from the tip header (dcrd `LoadBestNode`).
pub fn load_best_node(
    tx: &Transaction,
    height: u32,
    block_hash: &Hash,
    header_bytes: &[u8],
    params: StakeNodeParams,
) -> Result<Node, StakeDbError> {
    let _info = db_fetch_database_info(tx)?.ok_or_else(|| {
        ticket_db_error(
            TicketDbErrorKind::MissingKey,
            "missing database information",
        )
    })?;

    // Compare the tip and make sure it matches.
    let state = db_fetch_best_state(tx)?;
    if state.hash != *block_hash || state.height != height {
        return Err(stake_rule_error(ErrorKind::DatabaseCorrupt, "best state corruption").into());
    }

    // Restore the best node treaps from the database, checking the
    // counts against the best state.
    let live = db_load_all_tickets(tx, LIVE_TICKETS_BUCKET_NAME)?;
    if live.len() != state.live as usize {
        return Err(stake_rule_error(
            ErrorKind::DatabaseCorrupt,
            format!(
                "live tickets corruption (got {} in state but loaded {})",
                state.live,
                live.len()
            ),
        )
        .into());
    }
    let missed = db_load_all_tickets(tx, MISSED_TICKETS_BUCKET_NAME)?;
    if missed.len() as u64 != state.missed {
        return Err(stake_rule_error(
            ErrorKind::DatabaseCorrupt,
            format!(
                "missed tickets corruption (got {} in state but loaded {})",
                state.missed,
                missed.len()
            ),
        )
        .into());
    }
    let revoked = db_load_all_tickets(tx, REVOKED_TICKETS_BUCKET_NAME)?;
    if revoked.len() as u64 != state.revoked {
        return Err(stake_rule_error(
            ErrorKind::DatabaseCorrupt,
            format!(
                "revoked tickets corruption (got {} in state but loaded {})",
                state.revoked,
                revoked.len()
            ),
        )
        .into());
    }

    // Restore the node undo, new tickets data, and next winners.
    let undo = db_fetch_block_undo_data(tx, height)?;
    let tickets = db_fetch_new_tickets(tx, height)?;
    Ok(Node::from_database_state(
        height,
        params,
        live,
        missed,
        revoked,
        undo,
        tickets,
        &state.next_winners,
        header_bytes,
    )?)
}

/// Write a newly connected best node to the database (dcrd
/// `WriteConnectedBestNode`): apply the undo data to the on-disk
/// ticket buckets, store the undo and maturing tickets rows, and
/// update the best state.
pub fn write_connected_best_node(
    tx: &Transaction,
    node: &Node,
    hash: &Hash,
) -> Result<(), StakeDbError> {
    for undo in node.undo_data() {
        match (undo.missed, undo.revoked, undo.spent) {
            // A newly added ticket enters the live bucket.
            (false, false, false) => {
                db_put_ticket(
                    tx,
                    LIVE_TICKETS_BUCKET_NAME,
                    &undo.ticket_hash,
                    undo.ticket_height,
                    undo.missed,
                    undo.revoked,
                    undo.spent,
                    undo.expired,
                )?;
            }
            // Missed and revoked: move from missed to revoked.
            (true, true, _) => {
                db_delete_ticket(tx, MISSED_TICKETS_BUCKET_NAME, &undo.ticket_hash)?;
                db_put_ticket(
                    tx,
                    REVOKED_TICKETS_BUCKET_NAME,
                    &undo.ticket_hash,
                    undo.ticket_height,
                    undo.missed,
                    undo.revoked,
                    undo.spent,
                    undo.expired,
                )?;
            }
            // Missed and previously live: move from live to missed.
            (true, false, _) => {
                db_delete_ticket(tx, LIVE_TICKETS_BUCKET_NAME, &undo.ticket_hash)?;
                db_put_ticket(
                    tx,
                    MISSED_TICKETS_BUCKET_NAME,
                    &undo.ticket_hash,
                    undo.ticket_height,
                    true,
                    undo.revoked,
                    undo.spent,
                    undo.expired,
                )?;
            }
            // Spent: remove from the live bucket.
            (false, _, true) => {
                db_delete_ticket(tx, LIVE_TICKETS_BUCKET_NAME, &undo.ticket_hash)?;
            }
            _ => {
                return Err(stake_rule_error(
                    ErrorKind::MemoryCorruption,
                    "unknown ticket state in undo data",
                )
                .into());
            }
        }
    }

    db_put_block_undo_data(tx, node.height(), node.undo_data())?;
    db_put_new_tickets(tx, node.height(), node.new_tickets())?;

    let mut next_winners = vec![Hash::ZERO; usize::from(node.params().votes_per_block)];
    if node.height() >= node.params().stake_validation_begin_height.wrapping_sub(1) as u32 {
        next_winners.copy_from_slice(node.winners());
    }
    db_put_best_state(
        tx,
        &BestChainState {
            hash: *hash,
            height: node.height(),
            live: node.pool_size() as u32,
            missed: node.missed_treap().len() as u64,
            revoked: node.revoked_treap().len() as u64,
            per_block: node.params().votes_per_block,
            next_winners,
        },
    )?;
    Ok(())
}

/// Write a newly disconnected best node to the database (dcrd
/// `WriteDisconnectedBestNode`): drop rows above the new tip, reverse
/// the child's undo data against the on-disk ticket buckets in
/// reverse order, rewrite the undo and tickets rows, and update the
/// best state.
pub fn write_disconnected_best_node(
    tx: &Transaction,
    node: &Node,
    hash: &Hash,
    child_undo_data: &[UndoTicketData],
) -> Result<(), StakeDbError> {
    // Drop all reversion data above the incoming node.
    let former_best = db_fetch_best_state(tx)?;
    if former_best.height > node.height() {
        let mut h = former_best.height;
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "h > node.height() >= 0 inside the loop, so h >= 1"
        )]
        while h > node.height() {
            db_drop_block_undo_data(tx, h)?;
            db_drop_new_tickets(tx, h)?;
            h -= 1;
        }
    }

    // Apply the child undo data in reverse order since there may be
    // multiple changes for the same ticket.
    for undo in child_undo_data.iter().rev() {
        match (undo.missed, undo.revoked, undo.spent) {
            // A newly added ticket: remove it from the live bucket.
            (false, false, false) => {
                db_delete_ticket(tx, LIVE_TICKETS_BUCKET_NAME, &undo.ticket_hash)?;
            }
            // Missed and revoked: move from revoked back to missed.
            (true, true, _) => {
                db_delete_ticket(tx, REVOKED_TICKETS_BUCKET_NAME, &undo.ticket_hash)?;
                db_put_ticket(
                    tx,
                    MISSED_TICKETS_BUCKET_NAME,
                    &undo.ticket_hash,
                    undo.ticket_height,
                    undo.missed,
                    false,
                    undo.spent,
                    undo.expired,
                )?;
            }
            // Missed and previously live: move from missed back to
            // live; the expired flag is unknown so it is cleared.
            (true, false, _) => {
                db_delete_ticket(tx, MISSED_TICKETS_BUCKET_NAME, &undo.ticket_hash)?;
                db_put_ticket(
                    tx,
                    LIVE_TICKETS_BUCKET_NAME,
                    &undo.ticket_hash,
                    undo.ticket_height,
                    false,
                    undo.revoked,
                    undo.spent,
                    false,
                )?;
            }
            // Spent: reinsert into the live bucket.
            (false, _, true) => {
                db_put_ticket(
                    tx,
                    LIVE_TICKETS_BUCKET_NAME,
                    &undo.ticket_hash,
                    undo.ticket_height,
                    undo.missed,
                    undo.revoked,
                    false,
                    undo.expired,
                )?;
            }
            _ => {
                return Err(stake_rule_error(
                    ErrorKind::MemoryCorruption,
                    "unknown ticket state in undo data",
                )
                .into());
            }
        }
    }

    db_put_block_undo_data(tx, node.height(), node.undo_data())?;
    db_put_new_tickets(tx, node.height(), node.new_tickets())?;

    let mut next_winners = vec![Hash::ZERO; usize::from(node.params().votes_per_block)];
    if node.height() >= node.params().stake_validation_begin_height.wrapping_sub(1) as u32 {
        next_winners.copy_from_slice(node.winners());
    }
    db_put_best_state(
        tx,
        &BestChainState {
            hash: *hash,
            height: node.height(),
            live: node.pool_size() as u32,
            missed: node.missed_treap().len() as u64,
            revoked: node.revoked_treap().len() as u64,
            per_block: node.params().votes_per_block,
            next_winners,
        },
    )?;
    Ok(())
}

/// A required ticket database bucket is absent.  dcrd has no error for
/// this -- it dereferences the nil bucket -- so the port reports its
/// otherwise unused `ErrUninitializedBucket` kind and names the bucket.
fn missing_bucket(name: &[u8]) -> StakeDbError {
    StakeDbError::Ticket(ticket_db_error(
        TicketDbErrorKind::UninitializedBucket,
        &format!(
            "required ticket database bucket {} is missing",
            String::from_utf8_lossy(name)
        ),
    ))
}

#[cfg(test)]
mod height_key_tests {
    use alloc::vec::Vec;

    use dcroxide_chainhash::Hash;
    use dcroxide_database::{Database, Options};

    use super::{
        db_drop_block_undo_data, db_drop_new_tickets, db_fetch_block_undo_data,
        db_fetch_new_tickets, db_put_block_undo_data, db_put_new_tickets, height_key,
    };
    use crate::ticketdb::{
        STAKE_BLOCK_UNDO_DATA_BUCKET_NAME, TICKETS_IN_BLOCK_BUCKET_NAME, UndoTicketData,
    };

    /// Heights whose little-endian bytes sort in another order than the
    /// heights do.
    const HEIGHTS: [u32; 7] = [65_536, 1, 256, 255, 0, 16_777_216, u32::MAX];

    /// The key is the height big-endian and reads back into it.
    #[test]
    fn the_key_is_the_big_endian_height() {
        for height in HEIGHTS {
            let key = height_key(height);
            assert_eq!(key, height.to_be_bytes());
            assert_eq!(u32::from_be_bytes(key), height);
        }
    }

    /// Keys sort in height order.
    #[test]
    fn keys_sort_in_height_order() {
        let mut by_key = HEIGHTS.to_vec();
        by_key.sort_by_key(|&height| height_key(height));
        let mut by_height = HEIGHTS.to_vec();
        by_height.sort_unstable();
        assert_eq!(by_key, by_height);
    }

    /// Each height's rows go in under its key, a walk meets them in
    /// height order, a fetch finds each by its height, and a drop takes
    /// exactly the rows it names.
    #[test]
    fn rows_round_trip_under_the_height_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db =
            Database::create(&Options::new(dir.path().join("db"), 0x12141c16)).expect("create");
        let undo = |height: u32| {
            alloc::vec![UndoTicketData {
                ticket_hash: Hash([height as u8; 32]),
                ticket_height: height,
                missed: true,
                revoked: false,
                spent: false,
                expired: true,
            }]
        };
        let tickets = |height: u32| {
            let mut hash = [0xa5; 32];
            hash[..4].copy_from_slice(&height.to_le_bytes());
            alloc::vec![Hash(hash)]
        };
        db.update(|tx| {
            let meta = tx.metadata();
            meta.create_bucket(STAKE_BLOCK_UNDO_DATA_BUCKET_NAME)?;
            meta.create_bucket(TICKETS_IN_BLOCK_BUCKET_NAME)?;
            for height in HEIGHTS {
                db_put_block_undo_data(tx, height, &undo(height)).expect("put undo");
                db_put_new_tickets(tx, height, &tickets(height)).expect("put tickets");
            }
            Ok(())
        })
        .expect("put the rows");

        let keys = |bucket: &[u8]| {
            let mut keys: Vec<Vec<u8>> = Vec::new();
            db.view(|tx| {
                tx.metadata()
                    .bucket(bucket)
                    .expect("bucket")
                    .for_each(|key, _| {
                        keys.push(key.to_vec());
                        Ok(())
                    })
            })
            .expect("walk");
            keys
        };
        let mut sorted = HEIGHTS.to_vec();
        sorted.sort_unstable();
        let want: Vec<Vec<u8>> = sorted.iter().map(|&h| height_key(h).to_vec()).collect();
        assert_eq!(keys(STAKE_BLOCK_UNDO_DATA_BUCKET_NAME), want);
        assert_eq!(keys(TICKETS_IN_BLOCK_BUCKET_NAME), want);

        db.view(|tx| {
            // Each height reads its own rows, 1 and 16,777,216 (each
            // other's bytes reversed) included.
            for height in HEIGHTS {
                assert_eq!(
                    db_fetch_block_undo_data(tx, height).expect("undo"),
                    undo(height)
                );
                assert_eq!(
                    db_fetch_new_tickets(tx, height).expect("tickets"),
                    tickets(height)
                );
            }
            // A height with no rows is the missing key.
            assert!(db_fetch_block_undo_data(tx, 2).is_err());
            assert!(db_fetch_new_tickets(tx, 2).is_err());
            Ok(())
        })
        .expect("read the rows");

        db.update(|tx| {
            db_drop_block_undo_data(tx, 256).expect("drop undo");
            db_drop_new_tickets(tx, 256).expect("drop tickets");
            Ok(())
        })
        .expect("drop the rows");
        let want: Vec<Vec<u8>> = sorted
            .iter()
            .filter(|&&h| h != 256)
            .map(|&h| height_key(h).to_vec())
            .collect();
        assert_eq!(keys(STAKE_BLOCK_UNDO_DATA_BUCKET_NAME), want);
        assert_eq!(keys(TICKETS_IN_BLOCK_BUCKET_NAME), want);
    }
}
