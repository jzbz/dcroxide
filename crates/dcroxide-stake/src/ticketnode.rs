// SPDX-License-Identifier: ISC
//! The ticket pool state machine (dcrd `blockchain/stake` tickets.go):
//! the per-block stake `Node` tracking the live, missed, and revoked
//! ticket treaps, the lottery-driven next winners and final state, and
//! the connect/disconnect transitions with their undo data.
//!
//! The database-coupled entry points (`InitDatabaseState`,
//! `LoadBestNode`, `WriteConnectedBestNode`, `WriteDisconnectedBestNode`)
//! live in `stakedb`; `ResetDatabase` and the `DbRemoveAllBuckets` it
//! calls are not ported, since nothing in dcrd calls `ResetDatabase`,
//! not even its tests, and it is `DbRemoveAllBuckets`'s only caller.
//! Disconnecting always takes the parent undo data and ticket list
//! directly -- the chain fetches the rows itself when the parent node
//! holds none, where dcrd's `disconnectNode` reads them through its
//! `dbTx` -- so dcrd's `ErrMissingDatabaseTx` fallback is
//! unrepresentable here.

use alloc::boxed::Box;
use alloc::format;
use alloc::vec::Vec;

use dcroxide_chainhash::{Hash, hash_b};

use crate::error::ErrorKind;
use crate::lottery::{Hash256Prng, find_ticket_idxs};
use crate::ticketdb::UndoTicketData;
use crate::tickettreap::{Immutable, Key, Value};
use crate::{RuleError, stake_rule_error};

/// The stake parameters the ticket state machine consumes (dcrd
/// `StakeParams`).
#[derive(Copy, Clone, Debug)]
pub struct StakeNodeParams {
    /// The number of votes per block (dcrd `VotesPerBlock`).
    pub votes_per_block: u16,
    /// The height voting begins (dcrd `StakeValidationBeginHeight`).
    pub stake_validation_begin_height: i64,
    /// The height tickets may first be purchased (dcrd
    /// `StakeEnableHeight`).
    pub stake_enable_height: i64,
    /// The number of blocks tickets live before expiring (dcrd
    /// `TicketExpiryBlocks`).
    pub ticket_expiry_blocks: u32,
}

/// A node in the stake state chain (dcrd stake `Node`).
#[derive(Clone)]
pub struct Node {
    height: u32,
    live_tickets: Immutable,
    missed_tickets: Immutable,
    revoked_tickets: Immutable,
    database_undo_update: Vec<UndoTicketData>,
    database_block_tickets: Vec<Hash>,
    next_winners: Vec<Hash>,
    final_state: [u8; 6],
    params: StakeNodeParams,
}

fn hash_in_slice(h: &Hash, list: &[Hash]) -> bool {
    list.contains(h)
}

/// dcrd `safeGet`'s error for a ticket the treap does not hold
/// (tickets.go:470-472).
fn missing_ticket(k: &Key) -> RuleError {
    stake_rule_error(
        ErrorKind::MissingTicket,
        format!(
            "ticket {} was supposed to be in the passed treap, but could not be found",
            Hash(*k)
        ),
    )
}

/// dcrd `safePut`'s error for a ticket the treap holds already
/// (tickets.go:492-494).
fn duplicate_ticket(k: Key) -> RuleError {
    stake_rule_error(
        ErrorKind::DuplicateTicket,
        format!("attempted to insert duplicate key {} into treap", Hash(k)),
    )
}

/// dcrd `safeDelete`'s error for a ticket the treap does not hold
/// (tickets.go:505-507).
fn undeletable_ticket(k: &Key) -> RuleError {
    stake_rule_error(
        ErrorKind::MissingTicket,
        format!(
            "attempted to delete non-existing key {} from treap",
            Hash(*k)
        ),
    )
}

/// Put a ticket the treap must not hold yet (dcrd `safePut`,
/// tickets.go:487-498), in the one descent that finds both whether the
/// ticket is there and where it goes.
fn safe_put(t: &Immutable, k: Key, v: Value) -> Result<Immutable, RuleError> {
    t.put_new(k, v).ok_or_else(|| duplicate_ticket(k))
}

/// Delete a ticket the treap must hold (dcrd `safeDelete`,
/// tickets.go:503-511), in the one descent that finds both whether the
/// ticket is there and the path its removal rebuilds.
fn safe_delete(t: &Immutable, k: &Key) -> Result<Immutable, RuleError> {
    match t.take(k) {
        Some((_, treap)) => Ok(treap),
        None => Err(undeletable_ticket(k)),
    }
}

/// Take the ticket out of the treap, which becomes the treap without
/// it, and return the value it held (dcrd `safeGet` and then
/// `safeDelete`, tickets.go:464-482 and :503-511).
///
/// dcrd looks the ticket up, and `safeDelete` asks whether it is there
/// before deleting it: three descents to one node, where this makes
/// one.  A ticket that is missing is refused with the lookup's error,
/// the first of the two dcrd reaches; the removal's own cannot follow a
/// lookup that found the ticket in the same treap.  A refused ticket
/// leaves the treap as it was.
fn take_ticket(t: &mut Immutable, k: &Key) -> Result<Value, RuleError> {
    t.take_in_place(k).ok_or_else(|| missing_ticket(k))
}

/// [`safe_put`] made in the treap itself: a refused ticket leaves the
/// treap as it was.
fn put_ticket(t: &mut Immutable, k: Key, v: Value) -> Result<(), RuleError> {
    if t.put_new_in_place(k, v) {
        Ok(())
    } else {
        Err(duplicate_ticket(k))
    }
}

/// [`safe_delete`] made in the treap itself, returning the value the
/// ticket held: a refused ticket leaves the treap as it was.
fn delete_ticket(t: &mut Immutable, k: &Key) -> Result<Value, RuleError> {
    t.take_in_place(k).ok_or_else(|| undeletable_ticket(k))
}

/// Put back a ticket a move took out of a treap a moment ago, when the
/// treap it was moving to refused it, and pass that refusal on: the
/// treaps are then a whole number of recorded moves away from the
/// parent's.
fn put_back(t: &mut Immutable, k: Key, held: Value, refusal: RuleError) -> RuleError {
    let restored = t.put_new_in_place(k, held);
    assert!(
        restored,
        "a ticket just taken out of a treap is in it again"
    );
    refusal
}

/// The undo data entry for a ticket that a connect moved and left with
/// the value given (dcrd `UndoTicketData`).
fn undo_entry(ticket_hash: Hash, v: Value) -> UndoTicketData {
    UndoTicketData {
        ticket_hash,
        ticket_height: v.height,
        missed: v.missed,
        revoked: v.revoked,
        spent: v.spent,
        expired: v.expired,
    }
}

/// How a connect moved a ticket between the treaps (dcrd
/// `connectNode`'s transitions, tickets.go:548-700).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Move {
    /// A winner that voted left the live set.
    Spent,
    /// A winner that did not vote, or a live ticket that expired, went
    /// to the missed set.
    Missed,
    /// A missed ticket was revoked.
    Revoked,
    /// A new ticket joined the live set.
    Bought,
}

/// A ticket a connect moved, with the value it held before the move.
#[derive(Copy, Clone, Debug)]
struct TicketMove {
    kind: Move,
    key: Key,
    before: Value,
}

/// Record a move, when the connect keeps a record.
fn record(moves: &mut Option<&mut Vec<TicketMove>>, kind: Move, key: Key, before: Value) {
    if let Some(moves) = moves.as_deref_mut() {
        moves.push(TicketMove { kind, key, before });
    }
}

/// Take a ticket a connect moved into a treap back out of it.
fn take_back(t: &mut Immutable, k: &Key) {
    let taken = t.take_in_place(k);
    assert!(
        taken.is_some(),
        "a ticket a connect moved into a treap is not in it"
    );
}

/// What a connect made in place ([`Node::connect_in_place`]) kept of the
/// parent node it took: every field but the treaps, which became the
/// child's, and a record of every ticket the connect moved, with the
/// value it held.  It rebuilds the parent from the child, should
/// something after the connect fail while the parent is still needed.
#[derive(Debug)]
pub struct ParentRestore {
    height: u32,
    database_undo_update: Vec<UndoTicketData>,
    database_block_tickets: Vec<Hash>,
    next_winners: Vec<Hash>,
    final_state: [u8; 6],
    moves: Vec<TicketMove>,
}

impl ParentRestore {
    /// The parent node again, given the child the connect made of it,
    /// which is left as it is.
    ///
    /// Each recorded move is undone, the last first, on copies of the
    /// child's treaps that share its nodes, so the child's are copied
    /// where they change and never changed.  Every ticket goes back to
    /// the treap it was in with the value it held there, so the parent
    /// answers every lookup, walk and index as before.  The shapes can
    /// differ where heights tie, as a ticket taken out and put back goes
    /// below its equals; nothing reads the shape, and a node regenerated
    /// by [`Node::disconnect`] has the same latitude.
    pub fn rebuild(self, child: &Node) -> Node {
        self.undo_moves(
            child.live_tickets.clone(),
            child.missed_tickets.clone(),
            child.revoked_tickets.clone(),
            child.params,
        )
    }

    /// The parent node from the child's treaps, with the recorded moves
    /// undone.
    fn undo_moves(
        self,
        mut live_tickets: Immutable,
        mut missed_tickets: Immutable,
        mut revoked_tickets: Immutable,
        params: StakeNodeParams,
    ) -> Node {
        for m in self.moves.iter().rev() {
            let source = match m.kind {
                Move::Spent => &mut live_tickets,
                Move::Missed => {
                    take_back(&mut missed_tickets, &m.key);
                    &mut live_tickets
                }
                Move::Revoked => {
                    take_back(&mut revoked_tickets, &m.key);
                    &mut missed_tickets
                }
                Move::Bought => {
                    take_back(&mut live_tickets, &m.key);
                    continue;
                }
            };
            let restored = source.put_new_in_place(m.key, m.before);
            assert!(
                restored,
                "a ticket a connect moved out of a treap is in it again before the move is undone"
            );
        }
        Node {
            height: self.height,
            live_tickets,
            missed_tickets,
            revoked_tickets,
            database_undo_update: self.database_undo_update,
            database_block_tickets: self.database_block_tickets,
            next_winners: self.next_winners,
            final_state: self.final_state,
            params,
        }
    }
}

/// A connect made in place that the block's tickets refused: dcrd's
/// error, and the parent node it was made from, its moves undone.
#[derive(Debug)]
pub struct InPlaceRefusal {
    /// The error [`Node::connect`] returns for the same block.
    pub error: RuleError,
    /// The parent node, holding every ticket it held, as it held it.
    pub parent: Node,
}

/// The winning ticket keys for the given indexes (dcrd lottery.go
/// `fetchWinners`).
pub fn fetch_winners(idxs: &[usize], t: &Immutable) -> Result<Vec<Key>, RuleError> {
    if t.is_empty() {
        return Err(stake_rule_error(
            ErrorKind::MemoryCorruption,
            "missing or empty treap",
        ));
    }
    let mut winners = Vec::with_capacity(idxs.len());
    for &idx in idxs {
        if idx >= t.len() {
            return Err(stake_rule_error(
                ErrorKind::MemoryCorruption,
                format!("idx {idx} out of bounds"),
            ));
        }
        let (k, _) = t.get_by_index(idx);
        winners.push(k);
    }
    Ok(winners)
}

/// The missed tickets as of one stake node, without the list having
/// been built: what dcrd's `MissedTickets` returns, held as the node's
/// immutable missed treap.
///
/// Taking one is a reference-count increment, and the set it names
/// never changes: the treap is persistent, so the node's later
/// transitions, even those of a connect made in place
/// ([`Node::connect_in_place`]), copy every node the handle shares
/// before they change it and leave this treap as it was.  The
/// list is built by [`MissedTickets::to_vec`], and membership answered
/// by [`MissedTickets::contains`], when a caller asks.
#[derive(Clone, Default)]
pub struct MissedTickets(Immutable);

impl MissedTickets {
    /// The number of missed tickets.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are no missed tickets.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether the ticket is in the missed set (dcrd
    /// `ExistsMissedTicket`).
    pub fn contains(&self, ticket: &Hash) -> bool {
        self.0.has(&ticket.0)
    }

    /// All missed tickets in key order (dcrd `MissedTickets`).
    pub fn to_vec(&self) -> Vec<Hash> {
        let mut tickets = Vec::with_capacity(self.0.len());
        self.0.for_each(|k, _| {
            tickets.push(Hash(*k));
            true
        });
        tickets
    }
}

/// Formats as the list [`MissedTickets::to_vec`] returns does.
impl core::fmt::Debug for MissedTickets {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut list = f.debug_list();
        self.0.for_each(|k, _| {
            list.entry(&Hash(*k));
            true
        });
        list.finish()
    }
}

impl core::fmt::Debug for Node {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Node")
            .field("height", &self.height)
            .field("live", &self.live_tickets.len())
            .field("missed", &self.missed_tickets.len())
            .field("revoked", &self.revoked_tickets.len())
            .finish_non_exhaustive()
    }
}

impl Node {
    /// The genesis stake node (dcrd `genesisNode`).
    pub fn genesis(params: StakeNodeParams) -> Node {
        Node {
            height: 0,
            live_tickets: Immutable::new(),
            missed_tickets: Immutable::new(),
            revoked_tickets: Immutable::new(),
            database_undo_update: Vec::new(),
            database_block_tickets: Vec::new(),
            next_winners: Vec::new(),
            final_state: [0u8; 6],
            params,
        }
    }

    /// The undo data for the block this node represents (dcrd
    /// `UndoData`).
    pub fn undo_data(&self) -> &[UndoTicketData] {
        &self.database_undo_update
    }

    /// The new tickets of the block this node represents (dcrd
    /// `NewTickets`).
    pub fn new_tickets(&self) -> &[Hash] {
        &self.database_block_tickets
    }

    /// The tickets spent by the block (dcrd `SpentByBlock`).
    pub fn spent_by_block(&self) -> Vec<Hash> {
        self.database_undo_update
            .iter()
            .filter(|u| u.spent)
            .map(|u| u.ticket_hash)
            .collect()
    }

    /// The tickets missed as of the block (dcrd `MissedByBlock`).
    pub fn missed_by_block(&self) -> Vec<Hash> {
        self.database_undo_update
            .iter()
            .filter(|u| u.missed)
            .map(|u| u.ticket_hash)
            .collect()
    }

    /// The tickets that expired unrevoked as of the block (dcrd
    /// `ExpiredByBlock`).
    pub fn expired_by_block(&self) -> Vec<Hash> {
        self.database_undo_update
            .iter()
            .filter(|u| u.expired && !u.revoked)
            .map(|u| u.ticket_hash)
            .collect()
    }

    /// Whether the ticket is in the live set (dcrd
    /// `ExistsLiveTicket`).
    pub fn exists_live_ticket(&self, ticket: &Hash) -> bool {
        self.live_tickets.has(&ticket.0)
    }

    /// All live tickets in key order (dcrd `LiveTickets`).
    pub fn live_tickets(&self) -> Vec<Hash> {
        let mut tickets = Vec::with_capacity(self.live_tickets.len());
        self.live_tickets.for_each(|k, _| {
            tickets.push(Hash(*k));
            true
        });
        tickets
    }

    /// The number of live tickets in the pool (dcrd `PoolSize`).
    pub fn pool_size(&self) -> usize {
        self.live_tickets.len()
    }

    /// Whether the ticket is in the missed set (dcrd
    /// `ExistsMissedTicket`).
    pub fn exists_missed_ticket(&self, ticket: &Hash) -> bool {
        self.missed_tickets.has(&ticket.0)
    }

    /// All missed tickets in key order (dcrd `MissedTickets`).
    pub fn missed_tickets(&self) -> Vec<Hash> {
        let mut tickets = Vec::with_capacity(self.missed_tickets.len());
        self.missed_tickets.for_each(|k, _| {
            tickets.push(Hash(*k));
            true
        });
        tickets
    }

    /// The missed tickets of this node as a handle on its missed
    /// treap, for a holder that may never need the list
    /// [`Node::missed_tickets`] walks the whole treap to build.
    pub fn missed_ticket_set(&self) -> MissedTickets {
        MissedTickets(self.missed_tickets.clone())
    }

    /// Whether the ticket is in the revoked set (dcrd
    /// `ExistsRevokedTicket`).
    pub fn exists_revoked_ticket(&self, ticket: &Hash) -> bool {
        self.revoked_tickets.has(&ticket.0)
    }

    /// All revoked tickets in key order (dcrd `RevokedTickets`).
    pub fn revoked_tickets(&self) -> Vec<Hash> {
        let mut tickets = Vec::with_capacity(self.revoked_tickets.len());
        self.revoked_tickets.for_each(|k, _| {
            tickets.push(Hash(*k));
            true
        });
        tickets
    }

    /// Whether the ticket ever expired from the perspective of this node:
    /// it is missed or revoked with its expired flag set (dcrd
    /// `ExistsExpiredTicket`).
    pub fn exists_expired_ticket(&self, ticket: &Hash) -> bool {
        if let Some(v) = self.missed_tickets.value(&ticket.0)
            && v.expired
        {
            return true;
        }
        if let Some(v) = self.revoked_tickets.value(&ticket.0)
            && v.expired
        {
            return true;
        }
        false
    }

    /// The stake node parameters.
    pub fn params(&self) -> &StakeNodeParams {
        &self.params
    }

    /// The missed ticket treap (used by the ticket database layer).
    pub(crate) fn missed_treap(&self) -> &Immutable {
        &self.missed_tickets
    }

    /// The revoked ticket treap (used by the ticket database layer).
    pub(crate) fn revoked_treap(&self) -> &Immutable {
        &self.revoked_tickets
    }

    /// Reconstruct a node from database state, recomputing the final
    /// lottery state from the tip header exactly like dcrd
    /// `LoadBestNode` does.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_database_state(
        height: u32,
        params: StakeNodeParams,
        live_tickets: Immutable,
        missed_tickets: Immutable,
        revoked_tickets: Immutable,
        database_undo_update: Vec<crate::ticketdb::UndoTicketData>,
        database_block_tickets: Vec<Hash>,
        state_next_winners: &[Hash],
        header_bytes: &[u8],
    ) -> Result<Node, RuleError> {
        let mut node = Node {
            height,
            live_tickets,
            missed_tickets,
            revoked_tickets,
            database_undo_update,
            database_block_tickets,
            next_winners: Vec::new(),
            final_state: [0u8; 6],
            params,
        };
        if height >= params.stake_validation_begin_height.wrapping_sub(1) as u32 {
            node.next_winners = state_next_winners.to_vec();

            // Calculate the final state from the block header.
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "votes_per_block is a u16, so at most (65535 + 1) * 32"
            )]
            let mut state_buffer =
                Vec::with_capacity((usize::from(params.votes_per_block) + 1) * 32);
            for ticket_hash in &node.next_winners {
                state_buffer.extend_from_slice(&ticket_hash.0);
            }
            let mut prng = Hash256Prng::new(header_bytes);
            find_ticket_idxs(node.live_tickets.len(), params.votes_per_block, &mut prng)?;
            let last_hash = prng.state_hash();
            state_buffer.extend_from_slice(&last_hash.0);
            node.final_state
                .copy_from_slice(&hash_b(&state_buffer)[0..6]);
        }
        Ok(node)
    }

    /// The tickets eligible to vote on the next block (dcrd
    /// `Winners`).
    pub fn winners(&self) -> &[Hash] {
        &self.next_winners
    }

    /// The final state checksum of the lottery (dcrd `FinalState`).
    pub fn final_state(&self) -> [u8; 6] {
        self.final_state
    }

    /// The height of the block this node represents (dcrd `Height`).
    pub fn height(&self) -> u32 {
        self.height
    }

    /// The live tickets that will expire as of the next block, less
    /// any that are winners of this block (dcrd `ExpiringNextBlock`).
    pub fn expiring_next_block(&self) -> Vec<Hash> {
        let next_block_height = self.height.wrapping_add(1);
        let mut to_expire_height: u32 = 0;
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "next_block_height > ticket_expiry_blocks is the condition"
        )]
        if next_block_height > self.params.ticket_expiry_blocks {
            to_expire_height = next_block_height - self.params.ticket_expiry_blocks;
        }
        let winners = &self.next_winners;
        let mut expiring = Vec::new();
        self.live_tickets
            .for_each_by_height(to_expire_height.wrapping_add(1), |k, v| {
                if v.height != to_expire_height {
                    return true;
                }
                let hash = Hash(*k);
                if !winners.contains(&hash) {
                    expiring.push(hash);
                }
                true
            });
        expiring
    }

    /// Connect the stake node for the next block given the block's
    /// lottery IV, spent (voted) tickets, revocations, and new tickets
    /// (dcrd `ConnectNode`/`connectNode`).
    ///
    /// The child starts from clones of this node's treaps.  The first
    /// change to each copies the path it changes, which this node shares,
    /// and the later changes of the same connect find the nodes copied
    /// already the child's own and change them where they stand, where
    /// dcrd copies the path again at every change.  This node is left as
    /// it was, whatever the block holds.
    pub fn connect(
        &self,
        lottery_iv: Hash,
        tickets_voted: &[Hash],
        revoked_tickets: &[Hash],
        new_tickets: &[Hash],
    ) -> Result<Node, RuleError> {
        let mut connected = Node {
            height: self.height.wrapping_add(1),
            live_tickets: self.live_tickets.clone(),
            missed_tickets: self.missed_tickets.clone(),
            revoked_tickets: self.revoked_tickets.clone(),
            database_undo_update: Vec::new(),
            database_block_tickets: new_tickets.to_vec(),
            next_winners: Vec::new(),
            final_state: [0u8; 6],
            params: self.params,
        };
        connected.connect_tickets(
            &self.next_winners,
            lottery_iv,
            tickets_voted,
            revoked_tickets,
            new_tickets,
            None,
        )?;
        Ok(connected)
    }

    /// [`Node::connect`], made of this node: the child takes its treaps
    /// and changes them, so a node no other version holds is changed
    /// where it stands rather than copied, and nothing is left of this
    /// node to free.  For a parent that is dropped once its child is
    /// connected, as during the initial sync.
    ///
    /// The child is the one [`Node::connect`] returns, node for node.  A
    /// treap node another holder shares (a clone of this node, the
    /// missed tickets of a [`MissedTickets`] handle) is copied before it
    /// is changed, so what every other holder sees never changes.  The
    /// [`ParentRestore`] returned beside the child rebuilds this node,
    /// should the block fail after its stake node was made.  A block the
    /// treaps refuse is refused with [`Node::connect`]'s error, and this
    /// node comes back in the [`InPlaceRefusal`], every move the connect
    /// made undone.
    pub fn connect_in_place(
        self,
        lottery_iv: Hash,
        tickets_voted: &[Hash],
        revoked_tickets: &[Hash],
        new_tickets: &[Hash],
    ) -> Result<(Node, ParentRestore), Box<InPlaceRefusal>> {
        let Node {
            height,
            live_tickets,
            missed_tickets,
            revoked_tickets: revoked,
            database_undo_update,
            database_block_tickets,
            next_winners,
            final_state,
            params,
        } = self;
        let mut connected = Node {
            height: height.wrapping_add(1),
            live_tickets,
            missed_tickets,
            revoked_tickets: revoked,
            database_undo_update: Vec::new(),
            database_block_tickets: new_tickets.to_vec(),
            next_winners: Vec::new(),
            final_state: [0u8; 6],
            params,
        };
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "the lengths of three in-memory slices, which cannot overflow usize"
        )]
        let moves =
            Vec::with_capacity(next_winners.len() + revoked_tickets.len() + new_tickets.len());
        let mut restore = ParentRestore {
            height,
            database_undo_update,
            database_block_tickets,
            next_winners,
            final_state,
            moves,
        };
        match connected.connect_tickets(
            &restore.next_winners,
            lottery_iv,
            tickets_voted,
            revoked_tickets,
            new_tickets,
            Some(&mut restore.moves),
        ) {
            Ok(()) => Ok((connected, restore)),
            Err(error) => {
                let parent = restore.undo_moves(
                    connected.live_tickets,
                    connected.missed_tickets,
                    connected.revoked_tickets,
                    connected.params,
                );
                Err(Box::new(InPlaceRefusal { error, parent }))
            }
        }
    }

    /// Make this node, which holds its parent's treaps and the block's
    /// new tickets, the parent's child: every ticket transition of dcrd
    /// `connectNode` in its order (tickets.go:548-700), each recorded in
    /// `moves` when there is a record, then the lottery.
    ///
    /// A move that takes a ticket out of one treap and is refused by the
    /// next puts the ticket back before it returns the refusal, so the
    /// treaps are always the parent's with the recorded moves made.
    fn connect_tickets(
        &mut self,
        parent_winners: &[Hash],
        lottery_iv: Hash,
        tickets_voted: &[Hash],
        revoked_tickets: &[Hash],
        new_tickets: &[Hash],
        mut moves: Option<&mut Vec<TicketMove>>,
    ) -> Result<(), RuleError> {
        // Iterate the spent and missed tickets and expire live tickets
        // once the stake enable height is reached.
        if self.height >= self.params.stake_enable_height as u32 {
            // Each voted ticket must be a winner from the parent.
            for voted in tickets_voted {
                if !hash_in_slice(voted, parent_winners) {
                    return Err(stake_rule_error(
                        ErrorKind::UnknownTicketSpent,
                        format!("unknown ticket {voted} spent in block"),
                    ));
                }
            }

            for ticket in parent_winners {
                let k = ticket.0;
                // A winner leaves the live set whether it voted or
                // not, so the lookup and the removal are one step.
                let before = take_ticket(&mut self.live_tickets, &k)?;
                let mut v = before;
                let kind = if hash_in_slice(ticket, tickets_voted) {
                    v.spent = true;
                    v.missed = false;
                    Move::Spent
                } else {
                    v.spent = false;
                    v.missed = true;
                    if let Err(refusal) = put_ticket(&mut self.missed_tickets, k, v) {
                        return Err(put_back(&mut self.live_tickets, k, before, refusal));
                    }
                    Move::Missed
                };
                record(&mut moves, kind, k, before);
                self.database_undo_update.push(undo_entry(*ticket, v));
            }

            // Expire live tickets at the expiry boundary.
            let mut to_expire_height: u32 = 0;
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "self.height > ticket_expiry_blocks is the condition"
            )]
            if self.height > self.params.ticket_expiry_blocks {
                to_expire_height = self.height - self.params.ticket_expiry_blocks;
            }
            let mut expiring: Vec<(Key, Value)> = Vec::new();
            self.live_tickets
                .for_each_by_height(to_expire_height.wrapping_add(1), |k, v| {
                    expiring.push((*k, *v));
                    true
                });
            for (k, before) in expiring {
                let mut v = before;
                v.missed = true;
                v.expired = true;
                delete_ticket(&mut self.live_tickets, &k)?;
                if let Err(refusal) = put_ticket(&mut self.missed_tickets, k, v) {
                    return Err(put_back(&mut self.live_tickets, k, before, refusal));
                }
                record(&mut moves, Move::Missed, k, before);
                self.database_undo_update.push(undo_entry(Hash(k), v));
            }

            // Process the revocations.
            for revoked in revoked_tickets {
                let k = revoked.0;
                let before = take_ticket(&mut self.missed_tickets, &k)?;
                let mut v = before;
                v.revoked = true;
                if let Err(refusal) = put_ticket(&mut self.revoked_tickets, k, v) {
                    return Err(put_back(&mut self.missed_tickets, k, before, refusal));
                }
                record(&mut moves, Move::Revoked, k, before);
                self.database_undo_update.push(undo_entry(*revoked, v));
            }
        }

        // Add the new tickets to the live set.
        for new_ticket in new_tickets {
            let k = new_ticket.0;
            let v = Value::new(self.height);
            put_ticket(&mut self.live_tickets, k, v)?;
            record(&mut moves, Move::Bought, k, v);
            self.database_undo_update.push(undo_entry(*new_ticket, v));
        }

        // Find the next set of winners and the final state once stake
        // validation is one block away.
        if self.height >= self.params.stake_validation_begin_height.wrapping_sub(1) as u32 {
            let mut prng = Hash256Prng::from_iv(lottery_iv);
            let idxs = find_ticket_idxs(
                self.live_tickets.len(),
                self.params.votes_per_block,
                &mut prng,
            )?;
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "votes_per_block is a u16, so at most (65535 + 1) * 32"
            )]
            let mut state_buffer =
                Vec::with_capacity((self.params.votes_per_block as usize + 1) * 32);
            let next_winner_keys = fetch_winners(&idxs, &self.live_tickets)?;
            for key in next_winner_keys {
                let ticket_hash = Hash(key);
                self.next_winners.push(ticket_hash);
                state_buffer.extend_from_slice(&ticket_hash.0);
            }
            let last_hash = prng.state_hash();
            state_buffer.extend_from_slice(&last_hash.0);
            self.final_state
                .copy_from_slice(&hash_b(&state_buffer)[0..6]);
        }
        Ok(())
    }

    /// Disconnect the stake node, restoring the parent's state from
    /// this node's undo data plus the parent's lottery IV, undo data,
    /// and new ticket list (dcrd `DisconnectNode`/`disconnectNode`,
    /// with the database fallback deferred to the engine wiring).
    pub fn disconnect(
        &self,
        parent_lottery_iv: Hash,
        parent_utds: &[UndoTicketData],
        parent_tickets: &[Hash],
    ) -> Result<Node, RuleError> {
        if self.height == 1 {
            return Ok(Node::genesis(self.params));
        }

        let votes_per_block = self.params.votes_per_block;
        let mut restored = Node {
            height: self.height.wrapping_sub(1),
            live_tickets: self.live_tickets.clone(),
            missed_tickets: self.missed_tickets.clone(),
            revoked_tickets: self.revoked_tickets.clone(),
            database_undo_update: parent_utds.to_vec(),
            database_block_tickets: parent_tickets.to_vec(),
            next_winners: Vec::with_capacity(votes_per_block as usize),
            final_state: [0u8; 6],
            params: self.params,
        };

        // Iterate the block undo data in reverse, reverting each
        // transition.
        let mut winners: Vec<Hash> = Vec::with_capacity(votes_per_block as usize);
        for undo in self.database_undo_update.iter().rev() {
            let k = undo.ticket_hash.0;
            let mut v = Value {
                height: undo.ticket_height,
                missed: undo.missed,
                revoked: undo.revoked,
                spent: undo.spent,
                expired: undo.expired,
            };
            if !undo.missed && !undo.revoked && !undo.spent {
                // A ticket that matured in this block: remove it.
                restored.live_tickets = safe_delete(&restored.live_tickets, &k)?;
            } else if undo.missed && undo.revoked {
                // A ticket revoked in this block: move it back to the
                // missed set.
                v.revoked = false;
                restored.revoked_tickets = safe_delete(&restored.revoked_tickets, &k)?;
                restored.missed_tickets = safe_put(&restored.missed_tickets, k, v)?;
            } else if undo.missed && !undo.revoked {
                // A ticket missed or expired in this block: move it
                // back to the live set, and remember non-expired
                // misses as parent winners.
                if !undo.expired {
                    winners.push(undo.ticket_hash);
                } else {
                    v.expired = false;
                }
                v.missed = false;
                restored.missed_tickets = safe_delete(&restored.missed_tickets, &k)?;
                restored.live_tickets = safe_put(&restored.live_tickets, k, v)?;
            } else if undo.spent {
                // A ticket that voted in this block: restore it live
                // and remember it as a parent winner.
                v.spent = false;
                winners.push(undo.ticket_hash);
                restored.live_tickets = safe_put(&restored.live_tickets, k, v)?;
            } else {
                return Err(stake_rule_error(
                    ErrorKind::MemoryCorruption,
                    "unknown ticket state in undo data",
                ));
            }
        }

        // The winners were pushed in reverse order.
        let num_winners = winners.len();
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "num_winners <= database_undo_update.len(), a Vec of 40-byte entries, so \
                      (num_winners + 1) * 32 fits in usize"
        )]
        let mut state_buffer = Vec::with_capacity((num_winners + 1) * 32);
        for winner in winners.iter().rev() {
            restored.next_winners.push(*winner);
            state_buffer.extend_from_slice(&winner.0);
        }
        if self.height >= self.params.stake_validation_begin_height as u32 {
            let mut prng = Hash256Prng::from_iv(parent_lottery_iv);
            find_ticket_idxs(
                restored.live_tickets.len(),
                self.params.votes_per_block,
                &mut prng,
            )?;
            let last_hash = prng.state_hash();
            state_buffer.extend_from_slice(&last_hash.0);
            restored
                .final_state
                .copy_from_slice(&hash_b(&state_buffer)[0..6]);
        }

        Ok(restored)
    }
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "test arithmetic over small bounded values"
)]
mod tests {
    use super::*;

    use alloc::collections::{BTreeMap, BTreeSet};
    use alloc::string::String;
    use dcroxide_testutil::SplitMix64;

    use crate::tickettreap::NodeShape;

    /// Stake enabled from the first block and the lottery never
    /// reached, so a connect runs every ticket transition and nothing
    /// after them.
    const PARAMS: StakeNodeParams = StakeNodeParams {
        votes_per_block: 5,
        stake_validation_begin_height: 1_000_000,
        stake_enable_height: 0,
        ticket_expiry_blocks: 40,
    };

    /// The height of the node the tests connect to and disconnect.
    const HEIGHT: u32 = 100;

    /// The height of a ticket that expires in the block after
    /// [`HEIGHT`].
    const EXPIRING: u32 = HEIGHT + 1 - PARAMS.ticket_expiry_blocks;

    fn ticket(n: u8) -> Hash {
        Hash([n; 32])
    }

    fn treap_of(tickets: &[(Hash, Value)]) -> Immutable {
        tickets
            .iter()
            .fold(Immutable::new(), |treap, (hash, value)| {
                treap.put(hash.0, *value)
            })
    }

    /// A node at [`HEIGHT`] holding the tickets given, whether or not
    /// a chain could have led to them.
    fn node_of(
        live: &[(Hash, Value)],
        missed: &[(Hash, Value)],
        revoked: &[(Hash, Value)],
        winners: &[Hash],
        undo: &[UndoTicketData],
    ) -> Node {
        Node {
            height: HEIGHT,
            live_tickets: treap_of(live),
            missed_tickets: treap_of(missed),
            revoked_tickets: treap_of(revoked),
            database_undo_update: undo.to_vec(),
            database_block_tickets: Vec::new(),
            next_winners: winners.to_vec(),
            final_state: [0u8; 6],
            params: PARAMS,
        }
    }

    /// dcrd `safeGet`'s error (tickets.go:470-472).
    fn not_found(ticket: Hash) -> (ErrorKind, String) {
        (
            ErrorKind::MissingTicket,
            format!(
                "ticket {ticket} was supposed to be in the passed treap, but could not be found"
            ),
        )
    }

    /// dcrd `safePut`'s error (tickets.go:492-494).
    fn duplicate(ticket: Hash) -> (ErrorKind, String) {
        (
            ErrorKind::DuplicateTicket,
            format!("attempted to insert duplicate key {ticket} into treap"),
        )
    }

    /// dcrd `safeDelete`'s error (tickets.go:505-507).
    fn not_deleted(ticket: Hash) -> (ErrorKind, String) {
        (
            ErrorKind::MissingTicket,
            format!("attempted to delete non-existing key {ticket} from treap"),
        )
    }

    fn error_of(result: Result<Node, RuleError>) -> (ErrorKind, String) {
        let err = result.expect_err("the transition is refused");
        (err.kind, err.description)
    }

    const IV: Hash = Hash([0xee; 32]);

    /// Each ticket transition of a connect that the treaps cannot make
    /// is refused with the error of the dcrd helper that finds it: the
    /// lookup's for a winner or a revocation that is not where it must
    /// be, the insert's for a ticket already where it is going.
    #[test]
    fn a_connect_the_treaps_cannot_make_is_refused_as_dcrd_refuses_it() {
        let value = Value::new(HEIGHT - 10);
        let (a, b) = (ticket(1), ticket(2));

        // A winner that is not live, voted or not: `safeGet`
        // (tickets.go:552).
        let node = node_of(&[], &[], &[], &[a], &[]);
        assert_eq!(error_of(node.connect(IV, &[a], &[], &[])), not_found(a));
        assert_eq!(error_of(node.connect(IV, &[], &[], &[])), not_found(a));

        // A winner that did not vote and is in the missed set already:
        // `safePut` (tickets.go:581).
        let node = node_of(&[(a, value)], &[(a, value)], &[], &[a], &[]);
        assert_eq!(error_of(node.connect(IV, &[], &[], &[])), duplicate(a));
        // Voting, it only leaves the live set.
        let connected = node.connect(IV, &[a], &[], &[]).expect("the vote connects");
        assert!(connected.live_tickets().is_empty());
        assert_eq!(connected.missed_tickets(), [a]);

        // A ticket that expires and is in the missed set already:
        // `safePut` (tickets.go:618).
        let expiring = Value::new(EXPIRING);
        let node = node_of(&[(a, expiring)], &[(a, expiring)], &[], &[], &[]);
        assert_eq!(error_of(node.connect(IV, &[], &[], &[])), duplicate(a));

        // A revocation of a ticket that is not missed: `safeGet`
        // (tickets.go:644).
        let node = node_of(&[(a, value)], &[(b, value)], &[(a, value)], &[], &[]);
        assert_eq!(error_of(node.connect(IV, &[], &[a], &[])), not_found(a));

        // A revocation of a ticket that is in the revoked set already:
        // `safePut` (tickets.go:657).
        let node = node_of(&[], &[(a, value)], &[(a, value)], &[], &[]);
        assert_eq!(error_of(node.connect(IV, &[], &[a], &[])), duplicate(a));

        // A new ticket that is live already: `safePut`
        // (tickets.go:686).
        let node = node_of(&[(a, value)], &[], &[], &[], &[]);
        assert_eq!(error_of(node.connect(IV, &[], &[], &[a])), duplicate(a));
    }

    /// A connect with several transitions the treaps cannot make
    /// reports the first in dcrd's order: the winners in the parent's
    /// order, then the expiring tickets, the revocations and the new
    /// tickets.
    #[test]
    fn a_connect_reports_the_first_transition_it_cannot_make() {
        let value = Value::new(HEIGHT - 10);
        let expiring = Value::new(EXPIRING);
        let (a, b, c, d, e) = (ticket(1), ticket(2), ticket(3), ticket(4), ticket(5));
        // Winner a did not vote and is missed already, winner b is not
        // live, c expires and is missed already, d is revoked without
        // being missed, e is bought while live.
        let live = [(a, value), (c, expiring), (e, value)];
        let missed = [(a, value), (c, expiring)];

        let node = node_of(&live, &missed, &[], &[a, b], &[]);
        assert_eq!(error_of(node.connect(IV, &[], &[d], &[e])), duplicate(a));
        let node = node_of(&live, &missed, &[], &[b, a], &[]);
        assert_eq!(error_of(node.connect(IV, &[], &[d], &[e])), not_found(b));
        let node = node_of(&live, &missed, &[], &[], &[]);
        assert_eq!(error_of(node.connect(IV, &[], &[d], &[e])), duplicate(c));
        let node = node_of(&live[..1], &[], &[], &[], &[]);
        assert_eq!(error_of(node.connect(IV, &[], &[d], &[a])), not_found(d));
        assert_eq!(error_of(node.connect(IV, &[], &[], &[a])), duplicate(a));
    }

    /// The tickets of a treap with the values it holds for them, in
    /// key order.
    fn held(treap: &Immutable) -> Vec<(Hash, Value)> {
        let mut tickets = Vec::new();
        treap.for_each(|k, v| {
            tickets.push((Hash(*k), *v));
            true
        });
        tickets
    }

    /// A connect moves each ticket between the sets with the flags
    /// dcrd gives it there (tickets.go:548-700), and records each move
    /// in the undo data in the order it was made; the disconnect that
    /// undoes it leaves each ticket where it was, as it was.
    #[test]
    fn a_connect_moves_each_ticket_as_dcrd_does_and_a_disconnect_moves_it_back() {
        let value = Value::new(HEIGHT - 10);
        let was_missed = Value {
            missed: true,
            ..Value::new(HEIGHT - 20)
        };
        let was_revoked = Value {
            missed: true,
            revoked: true,
            ..Value::new(HEIGHT - 30)
        };
        // Two winners, of which the first votes; a ticket that
        // expires; a missed ticket that is revoked; a ticket bought;
        // and one ticket in each set that nothing happens to.
        let (voter, absentee, expiring, revokee, bought) =
            (ticket(1), ticket(2), ticket(3), ticket(4), ticket(5));
        let (stays_live, stays_missed, stays_revoked) = (ticket(6), ticket(7), ticket(8));
        let live = [
            (voter, value),
            (absentee, value),
            (expiring, Value::new(EXPIRING)),
            (stays_live, value),
        ];
        let missed = [(revokee, was_missed), (stays_missed, was_missed)];
        let revoked = [(stays_revoked, was_revoked)];
        let parent = node_of(&live, &missed, &revoked, &[voter, absentee], &[]);

        let connected = parent
            .connect(IV, &[voter], &[revokee], &[bought])
            .expect("the block connects");
        assert_eq!(connected.height(), HEIGHT + 1);
        assert_eq!(
            held(&connected.live_tickets),
            [(bought, Value::new(HEIGHT + 1)), (stays_live, value)]
        );
        assert_eq!(
            held(&connected.missed_tickets),
            [
                (
                    absentee,
                    Value {
                        missed: true,
                        ..value
                    }
                ),
                (
                    expiring,
                    Value {
                        missed: true,
                        expired: true,
                        ..Value::new(EXPIRING)
                    }
                ),
                (stays_missed, was_missed),
            ]
        );
        assert_eq!(
            held(&connected.revoked_tickets),
            [
                (
                    revokee,
                    Value {
                        revoked: true,
                        ..was_missed
                    }
                ),
                (stays_revoked, was_revoked),
            ]
        );
        let undo = |ticket_hash, v: Value, missed, revoked, spent, expired| UndoTicketData {
            ticket_hash,
            ticket_height: v.height,
            missed,
            revoked,
            spent,
            expired,
        };
        assert_eq!(
            connected.undo_data(),
            [
                undo(voter, value, false, false, true, false),
                undo(absentee, value, true, false, false, false),
                undo(expiring, Value::new(EXPIRING), true, false, false, true),
                undo(revokee, was_missed, true, true, false, false),
                undo(bought, Value::new(HEIGHT + 1), false, false, false, false),
            ]
        );
        assert_eq!(connected.new_tickets(), [bought]);
        // The parent is as it was.
        assert_eq!(held(&parent.live_tickets), {
            let mut live = live.to_vec();
            live.sort_by_key(|(hash, _)| hash.0);
            live
        });
        assert_eq!(held(&parent.missed_tickets), missed);
        assert_eq!(held(&parent.revoked_tickets), revoked);

        let restored = connected
            .disconnect(IV, parent.undo_data(), parent.new_tickets())
            .expect("the block disconnects");
        assert_eq!(restored.height(), HEIGHT);
        assert_eq!(held(&restored.live_tickets), held(&parent.live_tickets));
        assert_eq!(held(&restored.missed_tickets), held(&parent.missed_tickets));
        assert_eq!(
            held(&restored.revoked_tickets),
            held(&parent.revoked_tickets)
        );
        assert_eq!(restored.winners(), [voter, absentee]);
    }

    fn undo_of(ticket: Hash, missed: bool, revoked: bool, spent: bool) -> UndoTicketData {
        UndoTicketData {
            ticket_hash: ticket,
            ticket_height: HEIGHT - 10,
            missed,
            revoked,
            spent,
            expired: false,
        }
    }

    /// Each transition a disconnect cannot undo is refused with the
    /// error of the dcrd helper that finds it: the removal's for a
    /// ticket that is not where the undo data says it went, the
    /// insert's for one already where it came from.
    #[test]
    fn a_disconnect_the_treaps_cannot_make_is_refused_as_dcrd_refuses_it() {
        let value = Value::new(HEIGHT - 10);
        let a = ticket(1);
        let disconnect = |node: Node| error_of(node.disconnect(IV, &[], &[]));

        // A ticket bought in the block that is not live: `safeDelete`
        // (tickets.go:820).
        let bought = [undo_of(a, false, false, false)];
        assert_eq!(
            disconnect(node_of(&[], &[], &[], &[], &bought)),
            not_deleted(a)
        );

        // A ticket revoked in the block that is not in the revoked
        // set: `safeDelete` (tickets.go:831); and one that is, and is
        // missed already: `safePut` (tickets.go:836).
        let revoked = [undo_of(a, true, true, false)];
        assert_eq!(
            disconnect(node_of(&[], &[(a, value)], &[], &[], &revoked)),
            not_deleted(a)
        );
        assert_eq!(
            disconnect(node_of(&[], &[(a, value)], &[(a, value)], &[], &revoked)),
            duplicate(a)
        );

        // A ticket missed in the block that is not in the missed set:
        // `safeDelete` (tickets.go:854); and one that is, and is live
        // already: `safePut` (tickets.go:859).
        let missed = [undo_of(a, true, false, false)];
        assert_eq!(
            disconnect(node_of(&[(a, value)], &[], &[], &[], &missed)),
            not_deleted(a)
        );
        assert_eq!(
            disconnect(node_of(&[(a, value)], &[(a, value)], &[], &[], &missed)),
            duplicate(a)
        );

        // A ticket that voted in the block and is live already:
        // `safePut` (tickets.go:871).
        let voted = [undo_of(a, false, false, true)];
        assert_eq!(
            disconnect(node_of(&[(a, value)], &[], &[], &[], &voted)),
            duplicate(a)
        );
    }

    /// `safeGet` as dcrd has it (tickets.go:464-482): a lookup.
    fn get_as_dcrd_does(t: &Immutable, k: &Key) -> Result<Value, RuleError> {
        t.value(k).ok_or_else(|| {
            stake_rule_error(
                ErrorKind::MissingTicket,
                format!(
                    "ticket {} was supposed to be in the passed treap, but could not be found",
                    Hash(*k)
                ),
            )
        })
    }

    /// `safePut` as dcrd has it (tickets.go:487-498): `Has`, then
    /// `Put`.
    fn put_as_dcrd_does(t: &Immutable, k: Key, v: Value) -> Result<Immutable, RuleError> {
        if t.has(&k) {
            return Err(stake_rule_error(
                ErrorKind::DuplicateTicket,
                format!("attempted to insert duplicate key {} into treap", Hash(k)),
            ));
        }
        Ok(t.put(k, v))
    }

    /// `safeDelete` as dcrd has it (tickets.go:503-511): `Has`, then
    /// `Delete`.
    fn delete_as_dcrd_does(t: &Immutable, k: &Key) -> Result<Immutable, RuleError> {
        if !t.has(k) {
            return Err(stake_rule_error(
                ErrorKind::MissingTicket,
                format!(
                    "attempted to delete non-existing key {} from treap",
                    Hash(*k)
                ),
            ));
        }
        Ok(t.delete(k))
    }

    /// What a helper made of a treap: the nodes of the treap it
    /// returned, each node it shares with the treap it was given under
    /// that node's address and each node it built under none, with the
    /// treap's length and size.
    fn made_of(from: &Immutable, made: &Immutable) -> (Vec<NodeShape>, usize, u64) {
        let given: BTreeSet<*const ()> = from.shape().iter().map(|n| n.address).collect();
        let mut shape = made.shape();
        for node in &mut shape {
            if !given.contains(&node.address) {
                node.address = core::ptr::null();
            }
        }
        (shape, made.len(), made.size())
    }

    /// The nodes of a treap with what each holds and where its children
    /// are, but not where it lives, with the treap's length and size.
    fn nodes_of(treap: &Immutable) -> (Vec<NodeShape>, usize, u64) {
        let mut shape = treap.shape();
        for node in &mut shape {
            node.address = core::ptr::null();
        }
        (shape, treap.len(), treap.size())
    }

    /// Each helper that descends once returns what dcrd's helpers,
    /// which look the ticket up and then descend again, return: the
    /// same treap built of the same new nodes over the same shared
    /// ones, the same value, or the same error.  Each helper that
    /// changes the treap it is given makes there the treap dcrd's
    /// return, node for node, with the same value, or refuses with the
    /// same error and leaves the treap as it was.
    #[test]
    fn the_helpers_return_what_the_lookup_and_the_operation_return() {
        let mut rng = SplitMix64::from_entropy("stake node treap helpers");
        let random_key = |rng: &mut SplitMix64| {
            let mut key = [0u8; 32];
            rng.fill(&mut key);
            key
        };
        // Results that were a treap, and results that were an error.
        let mut tally = [[0usize; 2]; 5];
        for round in 0..60 {
            // Few heights, so priorities tie and a removal cascades
            // through the ties.
            let mut keys: Vec<Key> = Vec::new();
            let mut treap = Immutable::new();
            for _ in 0..rng.below(120) {
                let key = random_key(&mut rng);
                let value = Value {
                    missed: rng.below(2) == 0,
                    expired: rng.below(2) == 0,
                    ..Value::new(rng.below(6) as u32)
                };
                keys.push(key);
                treap = treap.put(key, value);
            }
            let shape = treap.shape();
            for _ in 0..40 {
                let key = if !keys.is_empty() && rng.below(2) == 0 {
                    keys[rng.below(keys.len() as u64) as usize]
                } else {
                    random_key(&mut rng)
                };
                let value = Value {
                    revoked: true,
                    ..Value::new(rng.below(6) as u32)
                };

                let put = safe_put(&treap, key, value);
                tally[0][usize::from(put.is_err())] += 1;
                assert_eq!(
                    put.map(|made| made_of(&treap, &made)),
                    put_as_dcrd_does(&treap, key, value).map(|made| made_of(&treap, &made)),
                    "round {round}: put"
                );

                let deleted = safe_delete(&treap, &key);
                tally[1][usize::from(deleted.is_err())] += 1;
                assert_eq!(
                    deleted.map(|made| made_of(&treap, &made)),
                    delete_as_dcrd_does(&treap, &key).map(|made| made_of(&treap, &made)),
                    "round {round}: delete"
                );

                // In place, each on a clone of the treap, which shares
                // every node with it.
                let mut taken = treap.clone();
                let held = take_ticket(&mut taken, &key);
                tally[2][usize::from(held.is_err())] += 1;
                assert_eq!(
                    held.map(|held| (held, nodes_of(&taken))),
                    get_as_dcrd_does(&treap, &key).and_then(|held| {
                        delete_as_dcrd_does(&treap, &key).map(|made| (held, nodes_of(&made)))
                    }),
                    "round {round}: get and delete in place"
                );

                let mut put_in = treap.clone();
                let put = put_ticket(&mut put_in, key, value);
                tally[3][usize::from(put.is_err())] += 1;
                assert_eq!(
                    put.map(|()| nodes_of(&put_in)),
                    put_as_dcrd_does(&treap, key, value).map(|made| nodes_of(&made)),
                    "round {round}: put in place"
                );

                let mut deleted_in = treap.clone();
                let held = delete_ticket(&mut deleted_in, &key);
                tally[4][usize::from(held.is_err())] += 1;
                assert_eq!(
                    held.map(|held| (Some(held), nodes_of(&deleted_in))),
                    delete_as_dcrd_does(&treap, &key)
                        .map(|made| (treap.value(&key), nodes_of(&made))),
                    "round {round}: delete in place"
                );

                // A refusal changed no node, and nothing done in place
                // to a clone changed a node of the treap it was cloned
                // from.
                for (made, refused) in [
                    (&taken, !treap.has(&key)),
                    (&put_in, treap.has(&key)),
                    (&deleted_in, !treap.has(&key)),
                ] {
                    if refused {
                        assert_eq!(
                            made.shape(),
                            shape,
                            "round {round}: a refusal changed a node"
                        );
                    }
                }
                assert_eq!(
                    treap.shape(),
                    shape,
                    "round {round}: a clone's change reached the treap"
                );
            }
        }
        // Each helper returned a treap and an error many times.
        assert!(tally.iter().flatten().all(|&n| n >= 500), "{tally:?}");
    }

    /// The `safeGet` and `safeDelete` of the port's connect before it was
    /// made in place: the value and the treap without the ticket.
    fn get_and_delete_by_versions(t: &Immutable, k: &Key) -> Result<(Value, Immutable), RuleError> {
        t.take(k).ok_or_else(|| missing_ticket(k))
    }

    /// dcrd `connectNode` as the port made it before its connects were
    /// made in place (fdd7a83): every transition through the treap
    /// operations that return a new version, each copying the path it
    /// changes.  The reference the connects are held to, node for node.
    fn connect_by_versions(
        parent: &Node,
        lottery_iv: Hash,
        tickets_voted: &[Hash],
        revoked_tickets: &[Hash],
        new_tickets: &[Hash],
    ) -> Result<Node, RuleError> {
        let mut connected = Node {
            height: parent.height.wrapping_add(1),
            live_tickets: parent.live_tickets.clone(),
            missed_tickets: parent.missed_tickets.clone(),
            revoked_tickets: parent.revoked_tickets.clone(),
            database_undo_update: Vec::new(),
            database_block_tickets: new_tickets.to_vec(),
            next_winners: Vec::new(),
            final_state: [0u8; 6],
            params: parent.params,
        };

        // Iterate the spent and missed tickets and expire live tickets
        // once the stake enable height is reached.
        if connected.height >= connected.params.stake_enable_height as u32 {
            // Each voted ticket must be a winner from the parent.
            for voted in tickets_voted {
                if !hash_in_slice(voted, &parent.next_winners) {
                    return Err(stake_rule_error(
                        ErrorKind::UnknownTicketSpent,
                        format!("unknown ticket {voted} spent in block"),
                    ));
                }
            }

            for ticket in &parent.next_winners {
                let k = ticket.0;
                // A winner leaves the live set whether it voted or
                // not, so the lookup and the removal are one step.
                let (mut v, live_tickets) =
                    get_and_delete_by_versions(&connected.live_tickets, &k)?;
                connected.live_tickets = live_tickets;
                if hash_in_slice(ticket, tickets_voted) {
                    v.spent = true;
                    v.missed = false;
                } else {
                    v.spent = false;
                    v.missed = true;
                    connected.missed_tickets = safe_put(&connected.missed_tickets, k, v)?;
                }
                connected.database_undo_update.push(UndoTicketData {
                    ticket_hash: *ticket,
                    ticket_height: v.height,
                    missed: v.missed,
                    revoked: v.revoked,
                    spent: v.spent,
                    expired: v.expired,
                });
            }

            // Expire live tickets at the expiry boundary.
            let mut to_expire_height: u32 = 0;
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "connected.height > ticket_expiry_blocks is the condition"
            )]
            if connected.height > connected.params.ticket_expiry_blocks {
                to_expire_height = connected.height - connected.params.ticket_expiry_blocks;
            }
            let mut expiring: Vec<(Key, Value)> = Vec::new();
            connected
                .live_tickets
                .for_each_by_height(to_expire_height.wrapping_add(1), |k, v| {
                    expiring.push((*k, *v));
                    true
                });
            for (k, value) in expiring {
                let mut v = value;
                v.missed = true;
                v.expired = true;
                connected.live_tickets = safe_delete(&connected.live_tickets, &k)?;
                connected.missed_tickets = safe_put(&connected.missed_tickets, k, v)?;
                connected.database_undo_update.push(UndoTicketData {
                    ticket_hash: Hash(k),
                    ticket_height: v.height,
                    missed: v.missed,
                    revoked: v.revoked,
                    spent: v.spent,
                    expired: v.expired,
                });
            }

            // Process the revocations.
            for revoked in revoked_tickets {
                let k = revoked.0;
                let (mut v, missed_tickets) =
                    get_and_delete_by_versions(&connected.missed_tickets, &k)?;
                v.revoked = true;
                connected.missed_tickets = missed_tickets;
                connected.revoked_tickets = safe_put(&connected.revoked_tickets, k, v)?;
                connected.database_undo_update.push(UndoTicketData {
                    ticket_hash: *revoked,
                    ticket_height: v.height,
                    missed: v.missed,
                    revoked: v.revoked,
                    spent: v.spent,
                    expired: v.expired,
                });
            }
        }

        // Add the new tickets to the live set.
        for new_ticket in new_tickets {
            let k = new_ticket.0;
            let v = Value::new(connected.height);
            connected.live_tickets = safe_put(&connected.live_tickets, k, v)?;
            connected.database_undo_update.push(UndoTicketData {
                ticket_hash: *new_ticket,
                ticket_height: v.height,
                missed: v.missed,
                revoked: v.revoked,
                spent: v.spent,
                expired: v.expired,
            });
        }

        // Find the next set of winners and the final state once stake
        // validation is one block away.
        if connected.height
            >= connected
                .params
                .stake_validation_begin_height
                .wrapping_sub(1) as u32
        {
            let mut prng = Hash256Prng::from_iv(lottery_iv);
            let idxs = find_ticket_idxs(
                connected.live_tickets.len(),
                connected.params.votes_per_block,
                &mut prng,
            )?;
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "votes_per_block is a u16, so at most (65535 + 1) * 32"
            )]
            let mut state_buffer =
                Vec::with_capacity((connected.params.votes_per_block as usize + 1) * 32);
            let next_winner_keys = fetch_winners(&idxs, &connected.live_tickets)?;
            for key in next_winner_keys {
                let ticket_hash = Hash(key);
                connected.next_winners.push(ticket_hash);
                state_buffer.extend_from_slice(&ticket_hash.0);
            }
            let last_hash = prng.state_hash();
            state_buffer.extend_from_slice(&last_hash.0);
            connected
                .final_state
                .copy_from_slice(&hash_b(&state_buffer)[0..6]);
        }

        Ok(connected)
    }

    /// The parameters of a run that draws the lottery at every connect,
    /// so a pool left smaller than the votes is refused after every
    /// ticket has moved.
    const LOTTERY: StakeNodeParams = StakeNodeParams {
        votes_per_block: 3,
        stake_validation_begin_height: 1,
        ..PARAMS
    };

    /// A block for a parent node: its lottery IV and the tickets it
    /// votes, revokes and buys.
    struct Block {
        iv: Hash,
        voted: Vec<Hash>,
        revoked: Vec<Hash>,
        bought: Vec<Hash>,
    }

    /// A parent node at [`HEIGHT`] and a block for it, made from the
    /// seed, so the same seed makes the same node again, node for node:
    /// heights that tie and some that expire in the block, odd flags on
    /// a few tickets, and, now and then, a ticket where a transition
    /// refuses it -- a winner that is not live, or is missed already, an
    /// expiring ticket missed already, a revocation of a ticket that is
    /// not missed, or is revoked already, a vote for a ticket that did
    /// not win, a ticket bought twice.
    fn random_case(seed: u64) -> (Node, Block) {
        let mut rng = SplitMix64(seed);
        let rng = &mut rng;
        let key = |rng: &mut SplitMix64| {
            let mut key = [0u8; 32];
            rng.fill(&mut key);
            Hash(key)
        };
        // From two below the expiry boundary to three above it.
        let height = |rng: &mut SplitMix64| EXPIRING - 2 + rng.below(6) as u32;
        let odd = |rng: &mut SplitMix64, value: Value| {
            if rng.below(8) != 0 {
                return value;
            }
            let flags = rng.next_u64();
            Value {
                missed: flags & 1 != 0,
                revoked: flags & 2 != 0,
                spent: flags & 4 != 0,
                expired: flags & 8 != 0,
                ..value
            }
        };
        let params = if rng.below(2) == 0 { PARAMS } else { LOTTERY };

        // One pool in four is smaller than the lottery draws from.
        let pool = if rng.below(4) == 0 { 4 } else { 40 };
        let mut live: Vec<(Hash, Value)> = Vec::new();
        for _ in 0..rng.below(pool) {
            let value = Value::new(height(rng));
            live.push((key(rng), odd(rng, value)));
        }
        let mut missed: Vec<(Hash, Value)> = Vec::new();
        for _ in 0..rng.below(12) {
            let value = Value {
                missed: true,
                expired: rng.below(2) == 0,
                ..Value::new(height(rng))
            };
            missed.push((key(rng), odd(rng, value)));
        }
        let mut revoked: Vec<(Hash, Value)> = Vec::new();
        for _ in 0..rng.below(6) {
            let value = Value {
                missed: true,
                revoked: true,
                ..Value::new(height(rng))
            };
            revoked.push((key(rng), value));
        }
        // A ticket in two sets.
        if !live.is_empty() && rng.below(6) == 0 {
            let (hash, value) = live[rng.below(live.len() as u64) as usize];
            missed.push((hash, value));
        }
        if !missed.is_empty() && rng.below(6) == 0 {
            let (hash, value) = missed[rng.below(missed.len() as u64) as usize];
            revoked.push((hash, value));
        }

        // Up to three winners, distinct, from the live tickets.
        let mut winners: Vec<Hash> = Vec::new();
        for _ in 0..3 {
            if live.is_empty() {
                break;
            }
            let (hash, _) = live[rng.below(live.len() as u64) as usize];
            if !winners.contains(&hash) {
                winners.push(hash);
            }
        }
        if rng.below(10) == 0 {
            winners.push(key(rng));
        }

        let mut voted: Vec<Hash> = winners
            .iter()
            .copied()
            .filter(|_| rng.below(4) != 0)
            .collect();
        if rng.below(12) == 0 {
            voted.push(key(rng));
        }
        let mut revocations: Vec<Hash> = missed
            .iter()
            .map(|(hash, _)| *hash)
            .filter(|_| rng.below(4) == 0)
            .collect();
        if rng.below(12) == 0 {
            revocations.push(key(rng));
        }
        let mut bought: Vec<Hash> = (0..rng.below(5)).map(|_| key(rng)).collect();
        if !live.is_empty() && rng.below(12) == 0 {
            bought.push(live[rng.below(live.len() as u64) as usize].0);
        }
        if !bought.is_empty() && rng.below(12) == 0 {
            bought.push(bought[0]);
        }

        let undo: Vec<UndoTicketData> = (0..rng.below(4))
            .map(|_| undo_of(key(rng), rng.below(2) == 0, false, rng.below(2) == 0))
            .collect();
        let mut final_state = [0u8; 6];
        rng.fill(&mut final_state);
        let parent = Node {
            height: HEIGHT,
            live_tickets: treap_of(&live),
            missed_tickets: treap_of(&missed),
            revoked_tickets: treap_of(&revoked),
            database_undo_update: undo,
            database_block_tickets: (0..rng.below(3)).map(|_| key(rng)).collect(),
            next_winners: winners,
            final_state,
            params,
        };
        let block = Block {
            iv: key(rng),
            voted,
            revoked: revocations,
            bought,
        };
        (parent, block)
    }

    /// The three treaps of a node.
    fn treaps(node: &Node) -> [&Immutable; 3] {
        [
            &node.live_tickets,
            &node.missed_tickets,
            &node.revoked_tickets,
        ]
    }

    /// Every node of the three treaps of a node, where each lives
    /// included.
    fn shapes_of(node: &Node) -> [Vec<NodeShape>; 3] {
        treaps(node).map(Immutable::shape)
    }

    /// Every field but the treaps.
    fn fields_of(node: &Node) -> impl PartialEq + core::fmt::Debug {
        (
            node.height,
            node.database_undo_update.clone(),
            node.database_block_tickets.clone(),
            node.next_winners.clone(),
            node.final_state,
            (
                node.params.votes_per_block,
                node.params.stake_validation_begin_height,
                node.params.stake_enable_height,
                node.params.ticket_expiry_blocks,
            ),
        )
    }

    /// The node is the one wanted, field for field and treap node for
    /// treap node.
    fn assert_same_node(got: &Node, want: &Node, context: &str) {
        assert_eq!(fields_of(got), fields_of(want), "{context}");
        for (here, there) in treaps(got).into_iter().zip(treaps(want)) {
            assert_eq!(nodes_of(here), nodes_of(there), "{context}");
        }
    }

    /// The node answers every question as the one wanted does: the same
    /// fields, and each treap the same tickets with the same values at
    /// the same indexes, whatever the shape.
    fn assert_answers_as(got: &Node, want: &Node, context: &str) {
        assert_eq!(fields_of(got), fields_of(want), "{context}");
        for (here, there) in treaps(got).into_iter().zip(treaps(want)) {
            assert_eq!(held(here), held(there), "{context}");
            assert_eq!(here.size(), there.size(), "{context}");
            assert!(here.heap_invariant_ok(), "{context}");
            for index in 0..here.len() {
                assert_eq!(
                    here.get_by_index(index),
                    there.get_by_index(index),
                    "{context}"
                );
            }
        }
        assert_eq!(
            got.expiring_next_block(),
            want.expiring_next_block(),
            "{context}"
        );
    }

    /// Of the tickets a treap made by a connect holds that the parent's
    /// held and the connect did not move: how many there are, and how
    /// many are in the very node that held them in the parent's.
    fn kept_in_place(
        made: &[NodeShape],
        parent: &[NodeShape],
        moved: &BTreeSet<Key>,
    ) -> (usize, usize) {
        let parent: BTreeMap<Key, *const ()> = parent.iter().map(|n| (n.key, n.address)).collect();
        let stayed: Vec<&NodeShape> = made
            .iter()
            .filter(|n| parent.contains_key(&n.key) && !moved.contains(&n.key))
            .collect();
        let in_place = stayed
            .iter()
            .filter(|n| parent[&n.key] == n.address)
            .count();
        (stayed.len(), in_place)
    }

    /// What the differential run of connects did, to show it did all of
    /// it.
    #[derive(Default, Debug)]
    struct ConnectTally {
        connected: usize,
        lottery_drawn: usize,
        refused_unknown_vote: usize,
        refused_missing: usize,
        refused_duplicate: usize,
        refused_lottery: usize,
        held_alone_kept: usize,
    }

    /// Every connect, through clones of the parent's treaps or in place,
    /// makes the node the connect by versions makes, node for node, or
    /// refuses the block with its error.  The parent a connect made in
    /// place took comes back from the refusal, or from its restore, with
    /// every ticket where it was, as it was; a parent held alone is
    /// changed where it stands, every ticket that stays put kept in the
    /// node it was in; and a holder that shares the parent's treaps sees
    /// no change.
    #[test]
    fn every_connect_makes_the_node_the_connect_by_versions_makes() {
        let mut rng =
            SplitMix64::from_entropy("stake node connects against the connect by versions");
        let mut tally = ConnectTally::default();
        for round in 0..4000 {
            let seed = rng.next_u64();
            let context = format!("round {round}, case {seed:#x}");
            let (parent, block) = random_case(seed);
            let connect =
                |node: &Node| node.connect(block.iv, &block.voted, &block.revoked, &block.bought);
            let want = connect_by_versions(
                &parent,
                block.iv,
                &block.voted,
                &block.revoked,
                &block.bought,
            );
            match &want {
                Ok(child) => {
                    tally.connected += 1;
                    tally.lottery_drawn += usize::from(!child.next_winners.is_empty());
                }
                Err(err) => match err.kind {
                    ErrorKind::UnknownTicketSpent => tally.refused_unknown_vote += 1,
                    ErrorKind::MissingTicket => tally.refused_missing += 1,
                    ErrorKind::DuplicateTicket => tally.refused_duplicate += 1,
                    ErrorKind::FindTicketIdxs => tally.refused_lottery += 1,
                    kind => panic!("{context}: {kind:?}"),
                },
            }

            // Through clones of the parent's treaps: the parent stays as
            // it was, node for node.
            let parent_shapes = shapes_of(&parent);
            match (connect(&parent), &want) {
                (Ok(got), Ok(want)) => assert_same_node(&got, want, &context),
                (Err(got), Err(want)) => assert_eq!(&got, want, "{context}"),
                (got, want) => panic!(
                    "{context}: {:?} against {:?}",
                    got.err(),
                    want.as_ref().err()
                ),
            }
            assert_eq!(
                shapes_of(&parent),
                parent_shapes,
                "{context}: the parent changed"
            );

            // In place, on the same parent made again, so that it holds
            // every node alone; and on it made again with a holder of a
            // clone of it, of its missed tickets, or of its live treap.
            for holder in 0..2 {
                let (taken, _) = random_case(seed);
                let taken_shapes = shapes_of(&taken);
                let held_clone = match (holder, round % 3) {
                    (0, _) => None,
                    (_, 0) => Some(taken.clone()),
                    (_, 1) => Some(Node {
                        missed_tickets: taken.missed_ticket_set().0,
                        ..Node::genesis(PARAMS)
                    }),
                    (_, _) => Some(Node {
                        live_tickets: taken.live_tickets.clone(),
                        ..Node::genesis(PARAMS)
                    }),
                };
                let held_shapes = held_clone.as_ref().map(shapes_of);
                let made =
                    taken.connect_in_place(block.iv, &block.voted, &block.revoked, &block.bought);
                match (made, &want) {
                    (Ok((child, restore)), Ok(want)) => {
                        assert_same_node(&child, want, &context);
                        if held_clone.is_none() {
                            // Every ticket the connect did not move is
                            // in the node it was in, where it stood.
                            let moved: BTreeSet<Key> =
                                restore.moves.iter().map(|m| m.key).collect();
                            for (made, before) in shapes_of(&child).iter().zip(&taken_shapes) {
                                let stayed = kept_in_place(made, before, &moved);
                                assert_eq!(stayed.0, stayed.1, "{context}: nodes copied");
                                tally.held_alone_kept += stayed.0;
                            }
                        }
                        let child_shapes = shapes_of(&child);
                        let rebuilt = restore.rebuild(&child);
                        assert_eq!(
                            shapes_of(&child),
                            child_shapes,
                            "{context}: the rebuild changed the child"
                        );
                        assert_answers_as(&rebuilt, &parent, &context);
                    }
                    (Err(refused), Err(want)) => {
                        let InPlaceRefusal {
                            error,
                            parent: back,
                        } = *refused;
                        assert_eq!(&error, want, "{context}");
                        assert_answers_as(&back, &parent, &context);
                        assert_eq!(connect(&back).err().as_ref(), Some(want), "{context}");
                    }
                    (got, want) => panic!(
                        "{context}: {:?} against {:?}",
                        got.err(),
                        want.as_ref().err()
                    ),
                }
                if let (Some(held_clone), Some(held_shapes)) = (&held_clone, &held_shapes) {
                    assert_eq!(
                        &shapes_of(held_clone),
                        held_shapes,
                        "{context}: a holder saw a change"
                    );
                }
            }
        }
        // Every kind of outcome came many times.
        assert!(
            tally.connected >= 1_000
                && tally.lottery_drawn >= 300
                && tally.refused_unknown_vote >= 100
                && tally.refused_missing >= 100
                && tally.refused_duplicate >= 100
                && tally.refused_lottery >= 100
                && tally.held_alone_kept >= 20_000,
            "{tally:?}"
        );
    }
}
