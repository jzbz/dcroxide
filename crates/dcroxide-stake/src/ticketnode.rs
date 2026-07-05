// SPDX-License-Identifier: ISC
//! The ticket pool state machine (dcrd `blockchain/stake` tickets.go):
//! the per-block stake `Node` tracking the live, missed, and revoked
//! ticket treaps, the lottery-driven next winners and final state, and
//! the connect/disconnect transitions with their undo data.
//!
//! The database-coupled entry points (`InitDatabaseState`,
//! `LoadBestNode`, `WriteConnectedBestNode`, `ResetDatabase`) arrive
//! with the chain engine persistence wiring; disconnecting therefore
//! always takes the parent undo data and ticket list directly, making
//! dcrd's `ErrMissingDatabaseTx` fallback unrepresentable here.

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

fn safe_get(t: &Immutable, k: &Key) -> Result<Value, RuleError> {
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

fn safe_put(t: &Immutable, k: Key, v: Value) -> Result<Immutable, RuleError> {
    if t.has(&k) {
        return Err(stake_rule_error(
            ErrorKind::DuplicateTicket,
            format!("attempted to insert duplicate key {} into treap", Hash(k)),
        ));
    }
    Ok(t.put(k, v))
}

fn safe_delete(t: &Immutable, k: &Key) -> Result<Immutable, RuleError> {
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

    /// Whether the ticket is missed and expired (dcrd
    /// `ExistsExpiredTicket`).
    pub fn exists_expired_ticket(&self, ticket: &Hash) -> bool {
        if let Some(v) = self.missed_tickets.value(&ticket.0) {
            if v.expired {
                return true;
            }
        }
        if let Some(v) = self.revoked_tickets.value(&ticket.0) {
            if v.expired {
                return true;
            }
        }
        false
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
        let next_block_height = self.height + 1;
        let mut to_expire_height: u32 = 0;
        if next_block_height > self.params.ticket_expiry_blocks {
            to_expire_height = next_block_height - self.params.ticket_expiry_blocks;
        }
        let winners = &self.next_winners;
        let mut expiring = Vec::new();
        self.live_tickets
            .for_each_by_height(to_expire_height + 1, |k, v| {
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
            height: self.height + 1,
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
        if i64::from(connected.height) >= connected.params.stake_enable_height {
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
                let mut v = safe_get(&connected.live_tickets, &k)?;
                if hash_in_slice(ticket, tickets_voted) {
                    v.spent = true;
                    v.missed = false;
                    connected.live_tickets = safe_delete(&connected.live_tickets, &k)?;
                } else {
                    v.spent = false;
                    v.missed = true;
                    connected.live_tickets = safe_delete(&connected.live_tickets, &k)?;
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
            if connected.height > connected.params.ticket_expiry_blocks {
                to_expire_height = connected.height - connected.params.ticket_expiry_blocks;
            }
            let mut expiring: Vec<(Key, Value)> = Vec::new();
            connected
                .live_tickets
                .for_each_by_height(to_expire_height + 1, |k, v| {
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
                let mut v = safe_get(&connected.missed_tickets, &k)?;
                v.revoked = true;
                connected.missed_tickets = safe_delete(&connected.missed_tickets, &k)?;
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
        if i64::from(connected.height) >= connected.params.stake_validation_begin_height - 1 {
            let mut prng = Hash256Prng::from_iv(lottery_iv);
            let idxs = find_ticket_idxs(
                connected.live_tickets.len(),
                connected.params.votes_per_block,
                &mut prng,
            )?;
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
            height: self.height - 1,
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
        let mut state_buffer = Vec::with_capacity((num_winners + 1) * 32);
        for winner in winners.iter().rev() {
            restored.next_winners.push(*winner);
            state_buffer.extend_from_slice(&winner.0);
        }
        if i64::from(self.height) >= self.params.stake_validation_begin_height {
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
