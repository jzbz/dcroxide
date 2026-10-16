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

/// Take the ticket out of the treap: the value it held and the treap
/// without it (dcrd `safeGet` and then `safeDelete`, tickets.go:464-482
/// and :503-511).
///
/// dcrd looks the ticket up, and `safeDelete` asks whether it is there
/// before deleting it: three descents to one node, where this makes
/// one.  A ticket that is missing is refused with the lookup's error,
/// the first of the two dcrd reaches; the removal's own cannot follow a
/// lookup that found the ticket in the same treap.
fn safe_get_and_delete(t: &Immutable, k: &Key) -> Result<(Value, Immutable), RuleError> {
    t.take(k).ok_or_else(|| {
        stake_rule_error(
            ErrorKind::MissingTicket,
            format!(
                "ticket {} was supposed to be in the passed treap, but could not be found",
                Hash(*k)
            ),
        )
    })
}

/// Put a ticket the treap must not hold yet (dcrd `safePut`,
/// tickets.go:487-498), in the one descent that finds both whether the
/// ticket is there and where it goes.
fn safe_put(t: &Immutable, k: Key, v: Value) -> Result<Immutable, RuleError> {
    t.put_new(k, v).ok_or_else(|| {
        stake_rule_error(
            ErrorKind::DuplicateTicket,
            format!("attempted to insert duplicate key {} into treap", Hash(k)),
        )
    })
}

/// Delete a ticket the treap must hold (dcrd `safeDelete`,
/// tickets.go:503-511), in the one descent that finds both whether the
/// ticket is there and the path its removal rebuilds.
fn safe_delete(t: &Immutable, k: &Key) -> Result<Immutable, RuleError> {
    match t.take(k) {
        Some((_, treap)) => Ok(treap),
        None => Err(stake_rule_error(
            ErrorKind::MissingTicket,
            format!(
                "attempted to delete non-existing key {} from treap",
                Hash(*k)
            ),
        )),
    }
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
/// transitions build new treaps and leave this one as it was.  The
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

        // Iterate the spent and missed tickets and expire live tickets
        // once the stake enable height is reached.
        if connected.height >= connected.params.stake_enable_height as u32 {
            // Each voted ticket must be a winner from the parent.
            for voted in tickets_voted {
                if !hash_in_slice(voted, &self.next_winners) {
                    return Err(stake_rule_error(
                        ErrorKind::UnknownTicketSpent,
                        format!("unknown ticket {voted} spent in block"),
                    ));
                }
            }

            for ticket in &self.next_winners {
                let k = ticket.0;
                // A winner leaves the live set whether it voted or
                // not, so the lookup and the removal are one step.
                let (mut v, live_tickets) = safe_get_and_delete(&connected.live_tickets, &k)?;
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
                let (mut v, missed_tickets) = safe_get_and_delete(&connected.missed_tickets, &k)?;
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

    use alloc::collections::BTreeSet;
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

    /// Each helper that descends once returns what dcrd's helpers,
    /// which look the ticket up and then descend again, return: the
    /// same treap built of the same new nodes over the same shared
    /// ones, the same value, or the same error.
    #[test]
    fn the_helpers_return_what_the_lookup_and_the_operation_return() {
        let mut rng = SplitMix64::from_entropy("stake node treap helpers");
        let random_key = |rng: &mut SplitMix64| {
            let mut key = [0u8; 32];
            rng.fill(&mut key);
            key
        };
        // Results that were a treap, and results that were an error.
        let mut tally = [[0usize; 2]; 3];
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

                let taken = safe_get_and_delete(&treap, &key);
                tally[2][usize::from(taken.is_err())] += 1;
                assert_eq!(
                    taken.map(|(held, made)| (held, made_of(&treap, &made))),
                    get_as_dcrd_does(&treap, &key).and_then(|held| {
                        delete_as_dcrd_does(&treap, &key).map(|made| (held, made_of(&treap, &made)))
                    }),
                    "round {round}: get and delete"
                );
            }
        }
        // Each helper returned a treap and an error many times.
        assert!(tally.iter().flatten().all(|&n| n >= 500), "{tally:?}");
    }
}
