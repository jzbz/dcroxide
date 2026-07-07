// SPDX-License-Identifier: ISC
//! The ticket database serialization formats (dcrd
//! `blockchain/stake/internal/ticketdb` chainio.go): the stake
//! database info row, the best chain state, per-block undo data,
//! ticket hash lists, and individual ticket rows, all little-endian.
//!
//! The `database.Tx`-coupled put/fetch/create wrappers arrive with the
//! chain engine persistence wiring; the bucket names and version
//! constants they use are exposed here.  In the deserializers Go
//! distinguishes nil from empty slices (nil undo/hash data falls
//! through to a short-read error while an empty non-nil slice decodes
//! to an empty list); the callers only reach these with non-nil data,
//! and the empty-slice behavior is the one reproduced.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use dcroxide_chainhash::Hash;

use crate::tickettreap;

/// The bit flagging an in-progress upgrade in the version row (dcrd
/// `upgradeStartedBit`).
pub const UPGRADE_STARTED_BIT: u32 = 0x8000_0000;

/// The current ticket database version (dcrd
/// `currentDatabaseVersion`).
pub const CURRENT_DATABASE_VERSION: u32 = 1;

/// Bucket and key names used by the ticket database (dcrd
/// `internal/dbnamespace`).
pub const STAKE_DB_INFO_BUCKET_NAME: &[u8] = b"stakedbinfo";
/// The metadata key for the best chain state row.
pub const STAKE_CHAIN_STATE_KEY_NAME: &[u8] = b"stakechainstate";
/// The live tickets bucket.
pub const LIVE_TICKETS_BUCKET_NAME: &[u8] = b"livetickets";
/// The missed tickets bucket.
pub const MISSED_TICKETS_BUCKET_NAME: &[u8] = b"missedtickets";
/// The revoked tickets bucket.
pub const REVOKED_TICKETS_BUCKET_NAME: &[u8] = b"revokedtickets";
/// The per-block undo data bucket.
pub const STAKE_BLOCK_UNDO_DATA_BUCKET_NAME: &[u8] = b"stakeblockundo";
/// The per-block new ticket hashes bucket.
pub const TICKETS_IN_BLOCK_BUCKET_NAME: &[u8] = b"ticketsinblock";

/// The kinds of ticket database errors (dcrd ticketdb `ErrorKind`),
/// named exactly as dcrd names them.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TicketDbErrorKind {
    /// A short read of serialized undo data.
    UndoDataShortRead,
    /// Corrupt serialized undo data.
    UndoDataCorrupt,
    /// A short read of serialized ticket hashes.
    TicketHashesShortRead,
    /// Corrupt serialized ticket hashes.
    TicketHashesCorrupt,
    /// A bucket was not initialized.
    UninitializedBucket,
    /// A required key is missing.
    MissingKey,
    /// A short read of the serialized chain state.
    ChainStateShortRead,
    /// A short read of the serialized database info.
    DatabaseInfoShortRead,
    /// Loading a ticket bucket into a treap failed.
    LoadAllTickets,
}

impl TicketDbErrorKind {
    /// dcrd's name for this kind.
    pub fn kind_name(self) -> &'static str {
        match self {
            TicketDbErrorKind::UndoDataShortRead => "ErrUndoDataShortRead",
            TicketDbErrorKind::UndoDataCorrupt => "ErrUndoDataCorrupt",
            TicketDbErrorKind::TicketHashesShortRead => "ErrTicketHashesShortRead",
            TicketDbErrorKind::TicketHashesCorrupt => "ErrTicketHashesCorrupt",
            TicketDbErrorKind::UninitializedBucket => "ErrUninitializedBucket",
            TicketDbErrorKind::MissingKey => "ErrMissingKey",
            TicketDbErrorKind::ChainStateShortRead => "ErrChainStateShortRead",
            TicketDbErrorKind::DatabaseInfoShortRead => "ErrDatabaseInfoShortRead",
            TicketDbErrorKind::LoadAllTickets => "ErrLoadAllTickets",
        }
    }
}

/// A ticket database error (dcrd ticketdb `DBError`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TicketDbError {
    /// The kind of error.
    pub kind: TicketDbErrorKind,
    /// The human-readable description.
    pub description: String,
}

pub(crate) fn ticket_db_error(kind: TicketDbErrorKind, description: &str) -> TicketDbError {
    TicketDbError {
        kind,
        description: String::from(description),
    }
}

/// The size of the serialized database info row.
const DATABASE_INFO_SIZE: usize = 8;

/// The versioning and creation information for the stake database
/// (dcrd `DatabaseInfo`); the creation date is stored as truncated
/// 32-bit unix seconds.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DatabaseInfo {
    /// The creation date as unix seconds (32-bit on disk).
    pub date_unix: u32,
    /// The database version.
    pub version: u32,
    /// Whether an upgrade was in progress.
    pub upgrade_started: bool,
}

/// Serialize the database info row (dcrd `serializeDatabaseInfo`).
pub fn serialize_database_info(dbi: &DatabaseInfo) -> Vec<u8> {
    let mut version = dbi.version;
    if dbi.upgrade_started {
        version |= UPGRADE_STARTED_BIT;
    }
    let mut val = Vec::with_capacity(DATABASE_INFO_SIZE);
    val.extend_from_slice(&version.to_le_bytes());
    val.extend_from_slice(&dbi.date_unix.to_le_bytes());
    val
}

/// Deserialize the database info row (dcrd
/// `deserializeDatabaseInfo`).
pub fn deserialize_database_info(bytes: &[u8]) -> Result<DatabaseInfo, TicketDbError> {
    if bytes.len() < DATABASE_INFO_SIZE {
        return Err(ticket_db_error(
            TicketDbErrorKind::DatabaseInfoShortRead,
            "short read when deserializing best chain state data",
        ));
    }
    let raw_version = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let upgrade_started = raw_version & UPGRADE_STARTED_BIT > 0;
    let version = raw_version & !UPGRADE_STARTED_BIT;
    let ts = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    Ok(DatabaseInfo {
        version,
        date_unix: ts,
        upgrade_started,
    })
}

/// The minimum size of the serialized best chain state.
const MINIMUM_BEST_CHAIN_STATE_SIZE: usize = 32 + 4 + 4 + 8 + 8 + 2;

/// The best chain state of the ticket database (dcrd ticketdb
/// `BestChainState`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BestChainState {
    /// The hash of the best block.
    pub hash: Hash,
    /// The height of the best block.
    pub height: u32,
    /// The number of live tickets.
    pub live: u32,
    /// The number of missed tickets.
    pub missed: u64,
    /// The number of revoked tickets.
    pub revoked: u64,
    /// The votes per block; the serialized winner list is always this
    /// long, zero-padded past the provided winners.
    pub per_block: u16,
    /// The winning tickets for the next block.
    pub next_winners: Vec<Hash>,
}

/// Serialize the best chain state (dcrd `serializeBestChainState`);
/// panics when `per_block` is less than the number of winners exactly
/// like dcrd, and zero-fills winner slots past the provided list.
pub fn serialize_best_chain_state(state: &BestChainState) -> Vec<u8> {
    assert!(
        state.per_block as usize >= state.next_winners.len(),
        "PerBlock:{} < NextWinners:{}",
        state.per_block,
        state.next_winners.len()
    );
    let len = MINIMUM_BEST_CHAIN_STATE_SIZE + 32 * state.per_block as usize;
    let mut data = vec![0u8; len];
    data[0..32].copy_from_slice(&state.hash.0);
    data[32..36].copy_from_slice(&state.height.to_le_bytes());
    data[36..40].copy_from_slice(&state.live.to_le_bytes());
    data[40..48].copy_from_slice(&state.missed.to_le_bytes());
    data[48..56].copy_from_slice(&state.revoked.to_le_bytes());
    data[56..58].copy_from_slice(&state.per_block.to_le_bytes());
    let mut offset = 58;
    for winner in &state.next_winners {
        data[offset..offset + 32].copy_from_slice(&winner.0);
        offset += 32;
    }
    data
}

/// Deserialize the best chain state (dcrd
/// `deserializeBestChainState`).  Only the minimum size is length
/// checked; reading the winner list past the end of short data panics
/// exactly as dcrd's slice indexing does.
pub fn deserialize_best_chain_state(data: &[u8]) -> Result<BestChainState, TicketDbError> {
    if data.len() < MINIMUM_BEST_CHAIN_STATE_SIZE {
        return Err(ticket_db_error(
            TicketDbErrorKind::ChainStateShortRead,
            "short read when deserializing best chain state data",
        ));
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&data[0..32]);
    let height = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);
    let live = u32::from_le_bytes([data[36], data[37], data[38], data[39]]);
    let mut missed_bytes = [0u8; 8];
    missed_bytes.copy_from_slice(&data[40..48]);
    let missed = u64::from_le_bytes(missed_bytes);
    let mut revoked_bytes = [0u8; 8];
    revoked_bytes.copy_from_slice(&data[48..56]);
    let revoked = u64::from_le_bytes(revoked_bytes);
    let per_block = u16::from_le_bytes([data[56], data[57]]);
    let mut next_winners = Vec::with_capacity(per_block as usize);
    let mut offset = 58;
    for _ in 0..per_block {
        let mut winner = [0u8; 32];
        winner.copy_from_slice(&data[offset..offset + 32]);
        next_winners.push(Hash(winner));
        offset += 32;
    }
    Ok(BestChainState {
        hash: Hash(hash),
        height,
        live,
        missed,
        revoked,
        per_block,
        next_winners,
    })
}

/// The size of a single serialized undo ticket entry.
const UNDO_TICKET_DATA_SIZE: usize = 37;

/// The state of a ticket for per-block undo purposes (dcrd
/// `UndoTicketData`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UndoTicketData {
    /// The hash of the ticket.
    pub ticket_hash: Hash,
    /// The height the ticket matured at.
    pub ticket_height: u32,
    /// Whether the ticket was missed.
    pub missed: bool,
    /// Whether the ticket was revoked.
    pub revoked: bool,
    /// Whether the ticket was spent.
    pub spent: bool,
    /// Whether the ticket was expired.
    pub expired: bool,
}

/// Pack the undo bit flags into a byte (dcrd `undoBitFlagsToByte`).
pub fn undo_bit_flags_to_byte(missed: bool, revoked: bool, spent: bool, expired: bool) -> u8 {
    u8::from(missed) | u8::from(revoked) << 1 | u8::from(spent) << 2 | u8::from(expired) << 3
}

/// Unpack the undo bit flags from a byte (dcrd
/// `undoBitFlagsFromByte`): (missed, revoked, spent, expired).
pub fn undo_bit_flags_from_byte(b: u8) -> (bool, bool, bool, bool) {
    (
        b & 1 > 0,
        b & (1 << 1) > 0,
        b & (1 << 2) > 0,
        b & (1 << 3) > 0,
    )
}

/// Serialize the per-block undo data (dcrd `serializeBlockUndoData`).
pub fn serialize_block_undo_data(utds: &[UndoTicketData]) -> Vec<u8> {
    let mut b = Vec::with_capacity(utds.len() * UNDO_TICKET_DATA_SIZE);
    for utd in utds {
        b.extend_from_slice(&utd.ticket_hash.0);
        b.extend_from_slice(&utd.ticket_height.to_le_bytes());
        b.push(undo_bit_flags_to_byte(
            utd.missed,
            utd.revoked,
            utd.spent,
            utd.expired,
        ));
    }
    b
}

/// Deserialize the per-block undo data (dcrd
/// `deserializeBlockUndoData`); an empty input decodes to an empty
/// list.
pub fn deserialize_block_undo_data(b: &[u8]) -> Result<Vec<UndoTicketData>, TicketDbError> {
    if b.is_empty() {
        return Ok(Vec::new());
    }
    if b.len() < UNDO_TICKET_DATA_SIZE {
        return Err(ticket_db_error(
            TicketDbErrorKind::UndoDataShortRead,
            "short read when deserializing block undo data",
        ));
    }
    if !b.len().is_multiple_of(UNDO_TICKET_DATA_SIZE) {
        return Err(ticket_db_error(
            TicketDbErrorKind::UndoDataCorrupt,
            "corrupt data found when deserializing block undo data",
        ));
    }
    let entries = b.len() / UNDO_TICKET_DATA_SIZE;
    let mut utds = Vec::with_capacity(entries);
    let mut offset = 0;
    for _ in 0..entries {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&b[offset..offset + 32]);
        offset += 32;
        let height = u32::from_le_bytes([b[offset], b[offset + 1], b[offset + 2], b[offset + 3]]);
        offset += 4;
        let (missed, revoked, spent, expired) = undo_bit_flags_from_byte(b[offset]);
        offset += 1;
        utds.push(UndoTicketData {
            ticket_hash: Hash(hash),
            ticket_height: height,
            missed,
            revoked,
            spent,
            expired,
        });
    }
    Ok(utds)
}

/// Serialize a list of ticket hashes (dcrd `serializeTicketHashes`).
pub fn serialize_ticket_hashes(ths: &[Hash]) -> Vec<u8> {
    let mut b = Vec::with_capacity(ths.len() * 32);
    for th in ths {
        b.extend_from_slice(&th.0);
    }
    b
}

/// Deserialize a list of ticket hashes (dcrd
/// `deserializeTicketHashes`); an empty input decodes to an empty
/// list.
pub fn deserialize_ticket_hashes(b: &[u8]) -> Result<Vec<Hash>, TicketDbError> {
    if b.is_empty() {
        return Ok(Vec::new());
    }
    if b.len() < 32 {
        return Err(ticket_db_error(
            TicketDbErrorKind::TicketHashesShortRead,
            "short read when deserializing ticket hashes",
        ));
    }
    if !b.len().is_multiple_of(32) {
        return Err(ticket_db_error(
            TicketDbErrorKind::TicketHashesCorrupt,
            "corrupt data found when deserializing ticket hashes",
        ));
    }
    let mut ths = Vec::with_capacity(b.len() / 32);
    for chunk in b.chunks_exact(32) {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(chunk);
        ths.push(Hash(hash));
    }
    Ok(ths)
}

/// Serialize an individual ticket bucket row value: the ticket height
/// followed by the packed flags byte (the value dcrd's `DbPutTicket`
/// stores).
pub fn serialize_ticket_value(
    height: u32,
    missed: bool,
    revoked: bool,
    spent: bool,
    expired: bool,
) -> [u8; 5] {
    let mut v = [0u8; 5];
    v[0..4].copy_from_slice(&height.to_le_bytes());
    v[4] = undo_bit_flags_to_byte(missed, revoked, spent, expired);
    v
}

/// Parse an individual ticket bucket row value into a treap value; the
/// per-row decoding dcrd's `DbLoadAllTickets` performs.
pub fn parse_ticket_value(v: &[u8]) -> Result<tickettreap::Value, TicketDbError> {
    if v.len() < 5 {
        return Err(ticket_db_error(
            TicketDbErrorKind::LoadAllTickets,
            "short read for ticket value when loading tickets",
        ));
    }
    let height = u32::from_le_bytes([v[0], v[1], v[2], v[3]]);
    let (missed, revoked, spent, expired) = undo_bit_flags_from_byte(v[4]);
    Ok(tickettreap::Value {
        height,
        missed,
        revoked,
        spent,
        expired,
    })
}
