// SPDX-License-Identifier: ISC
//! Chain event notifications (dcrd internal/blockchain
//! `notifications.go`): the callback the chain invokes synchronously
//! as blocks are checked, accepted, connected, disconnected, and
//! reorganized.
//!
//! The callback runs on the processing thread inside the chain's
//! critical section (the daemon holds the chain mutex through the
//! whole call, where dcrd releases its chain lock around some sends),
//! so it must not call back into the chain — queue the event and
//! return, exactly how dcrd's daemon handler forwards into its
//! notification managers.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use dcroxide_chainhash::Hash;
use dcroxide_wire::MsgBlock;

use crate::validate::AgendaFlags;

/// A block accepted into the block index (dcrd
/// `BlockAcceptedNtfnsData`); the block is not necessarily on the
/// main chain.
pub struct BlockAcceptedNtfnsData<'a> {
    /// The height of the current best chain; the accepted block may
    /// sit on a side chain, so this is not necessarily its height.
    pub best_height: i64,
    /// The length of the side chain the block extended, zero when it
    /// extended the main chain.
    pub fork_len: i64,
    /// The accepted block.
    pub block: &'a MsgBlock,
}

/// A block connected to the main chain (dcrd
/// `BlockConnectedNtfnsData`).  The blocks are shared as `Arc`s so
/// the daemon's notification fan-out clones a pointer per consumer,
/// like dcrd handing the same `*dcrutil.Block` to every observer.
pub struct BlockConnectedNtfnsData {
    /// The connected block.
    pub block: Arc<MsgBlock>,
    /// The connected block's parent.
    pub parent_block: Arc<MsgBlock>,
    /// The agendas active when checking the connected block's
    /// transactions.
    pub check_tx_flags: AgendaFlags,
}

/// A block disconnected from the main chain (dcrd
/// `BlockDisconnectedNtfnsData`).  The blocks are shared as `Arc`s so
/// the daemon's notification fan-out clones a pointer per consumer,
/// like dcrd handing the same `*dcrutil.Block` to every observer.
pub struct BlockDisconnectedNtfnsData {
    /// The disconnected block.
    pub block: Arc<MsgBlock>,
    /// The disconnected block's parent, now the tip again.
    pub parent_block: Arc<MsgBlock>,
    /// The agendas that were active for the DISCONNECTED block.
    pub check_tx_flags: AgendaFlags,
}

/// The chain reorganized to a new tip (dcrd `ReorganizationNtfnsData`).
pub struct ReorganizationNtfnsData {
    /// The hash of the tip before the reorganization.
    pub old_hash: Hash,
    /// The height of the tip before the reorganization.
    pub old_height: i64,
    /// The hash of the tip after the reorganization.
    pub new_hash: Hash,
    /// The height of the tip after the reorganization.
    pub new_height: i64,
}

/// The newly maturing tickets of a connected block (dcrd
/// `TicketNotificationsData`).
pub struct TicketNotificationsData {
    /// The connected block's hash.
    pub hash: Hash,
    /// The connected block's height.
    pub height: i64,
    /// The stake difficulty for the next block.
    pub stake_difficulty: i64,
    /// The tickets maturing into the live pool.
    pub tickets_new: Vec<Hash>,
}

/// A chain event (dcrd `Notification` with its `NotificationType`).
pub enum Notification<'a> {
    /// The block passed all sanity and contextual checks and intends
    /// to directly extend the current main chain tip (dcrd
    /// `NTNewTipBlockChecked`); only sent while the chain believes it
    /// is current, before the expensive connect work, so the daemon
    /// can relay the block early.
    NewTipBlockChecked(&'a MsgBlock),
    /// A block was accepted into the block index, not necessarily
    /// onto the main chain (dcrd `NTBlockAccepted`); sent after any
    /// resulting reorganization so the data is relative to the final
    /// best chain.
    BlockAccepted(BlockAcceptedNtfnsData<'a>),
    /// A block connected to the main chain (dcrd `NTBlockConnected`).
    BlockConnected(BlockConnectedNtfnsData),
    /// A block disconnected from the main chain (dcrd
    /// `NTBlockDisconnected`).
    BlockDisconnected(BlockDisconnectedNtfnsData),
    /// A reorganization to a competing branch began (dcrd
    /// `NTChainReorgStarted`); never sent for a plain tip extension.
    ChainReorgStarted,
    /// The reorganization attempt finished, successfully or not (dcrd
    /// `NTChainReorgDone`, which dcrd defers).
    ChainReorgDone,
    /// The chain tip moved to a competing branch (dcrd
    /// `NTReorganization`).
    Reorganization(ReorganizationNtfnsData),
    /// The newly maturing tickets of a connected block at or above
    /// the stake enabled height (dcrd `NTNewTickets`).
    NewTickets(TicketNotificationsData),
}

/// The callback the chain invokes for each event (dcrd
/// `NotificationCallback`); `Send` because the chain is shared across
/// the daemon's threads.
pub type NotificationCallback = Box<dyn FnMut(&Notification<'_>) + Send>;
