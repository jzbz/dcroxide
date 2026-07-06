// SPDX-License-Identifier: ISC
//! The index update subscriber (dcrd indexers `indexsubscriber.go`
//! plus the notification processing from `common.go`): subscriptions
//! with prerequisite/dependent relationships, the expected-height
//! update state machine, catch-up to the main chain tip, and index
//! recovery.  dcrd delivers notifications through a buffered channel
//! serviced by goroutines and checks sync subscribers on a periodic
//! ticker; this port delivers synchronously with identical state
//! transitions, leaving the concurrency to the daemon phase.

use core::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use dcroxide_wire::MsgBlock;

use crate::common::{
    ChainQueryer, INTERRUPT_MSG, Indexer, Interrupt, interrupt_requested, maybe_notify_subscribers,
};
use crate::error::{ErrorKind, IdxError, indexer_error};

/// An index notification type (dcrd `IndexNtfnType`).  dcrd models
/// this as a plain integer and the update path reports unknown
/// values, so the raw value is kept accessible.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct IndexNtfnType(pub i32);

/// The notification signals a block connected to the main chain
/// (dcrd `ConnectNtfn`).
pub const CONNECT_NTFN: IndexNtfnType = IndexNtfnType(0);

/// The notification signals a block disconnected from the main chain
/// (dcrd `DisconnectNtfn`).
pub const DISCONNECT_NTFN: IndexNtfnType = IndexNtfnType(1);

/// No index prerequisites (dcrd `noPrereqs`).
pub const NO_PREREQS: &str = "none";

/// An index notification detailing a block connection or
/// disconnection (dcrd `IndexNtfn`; the `Done` channel is not needed
/// with synchronous delivery).
#[derive(Clone)]
pub struct IndexNtfn {
    /// The notification type.
    pub ntfn_type: IndexNtfnType,
    /// The block the notification is for.
    pub block: Rc<MsgBlock>,
    /// The parent of the block.
    pub parent: Rc<MsgBlock>,
    /// Whether the treasury agenda is active at the block.
    pub is_treasury_enabled: bool,
}

/// The height of a block as the indexers see it (dcrd
/// `dcrutil.Block.Height()`, which reads the header).
pub(crate) fn block_height(block: &MsgBlock) -> i64 {
    i64::from(block.header.height)
}

/// A shared, mutably borrowable indexer handle.
pub type IndexerHandle = Rc<RefCell<dyn Indexer>>;

/// A subscription chain: the first entry is the prerequisite-free
/// index, each following entry is the dependent of the one before
/// it (dcrd links these through `IndexSubscription.dependent`).
struct SubEntry {
    chain: Vec<(String, IndexerHandle)>,
}

/// Subscribes indexes for update notifications (dcrd
/// `IndexSubscriber`).
pub struct IndexSubscriber {
    interrupt: Interrupt,
    subscriptions: BTreeMap<String, SubEntry>,
    subscribers: u32,
    cancelled: bool,
}

impl IndexSubscriber {
    /// Create a new index subscriber (dcrd `NewIndexSubscriber`).
    pub fn new(interrupt: Interrupt) -> IndexSubscriber {
        IndexSubscriber {
            interrupt,
            subscriptions: BTreeMap::new(),
            subscribers: 0,
            cancelled: false,
        }
    }

    /// The shared interrupt flag.
    pub fn interrupt(&self) -> Interrupt {
        self.interrupt.clone()
    }

    /// Whether a notification error has cancelled the subscriber
    /// (dcrd cancels its context; queried by tests).
    pub fn cancelled(&self) -> bool {
        self.cancelled
    }

    /// Subscribe an index for updates (dcrd
    /// `IndexSubscriber.Subscribe`).
    pub fn subscribe(&mut self, id: &str, idx: IndexerHandle, prereq: &str) -> Result<(), String> {
        if prereq != NO_PREREQS {
            // Find the prerequisite and set the subscription as its
            // dependent.
            let entry = self
                .subscriptions
                .values_mut()
                .find(|entry| entry.chain.iter().any(|(cid, _)| cid == prereq))
                .ok_or_else(|| format!("no subscription found with id {prereq}"))?;
            let last = entry.chain.last().expect("nonempty chain");
            if last.0 != prereq {
                let pos = entry
                    .chain
                    .iter()
                    .position(|(cid, _)| cid == prereq)
                    .expect("prereq position");
                return Err(format!(
                    "{} already has a dependent set: {}",
                    prereq,
                    entry.chain[pos.saturating_add(1)].0
                ));
            }
            entry.chain.push((id.to_string(), idx));
            self.subscribers = self.subscribers.saturating_add(1);
            return Ok(());
        }

        self.subscriptions.insert(
            id.to_string(),
            SubEntry {
                chain: vec![(id.to_string(), idx)],
            },
        );
        self.subscribers = self.subscribers.saturating_add(1);
        Ok(())
    }

    /// Stop a subscription (dcrd `IndexSubscription.stop`): a
    /// dependent is unlinked from its prerequisite (dropping any
    /// deeper dependents with it), while a prerequisite-free
    /// subscription is removed entirely along with its dependents.
    pub fn stop(&mut self, id: &str) -> Result<(), String> {
        if self.subscriptions.contains_key(id) {
            self.subscriptions.remove(id);
            return Ok(());
        }
        for entry in self.subscriptions.values_mut() {
            if let Some(pos) = entry.chain.iter().position(|(cid, _)| cid == id) {
                entry.chain.truncate(pos);
                return Ok(());
            }
        }
        Err(format!("no subscription found with id {id}"))
    }

    /// Locate the subscription chain containing the provided id and
    /// return the handles from that id onward (the index itself plus
    /// its dependent tail).
    fn chain_from(&self, id: &str) -> Option<Vec<(String, IndexerHandle)>> {
        for entry in self.subscriptions.values() {
            if let Some(pos) = entry.chain.iter().position(|(cid, _)| cid == id) {
                return Some(
                    entry
                        .chain
                        .iter()
                        .skip(pos)
                        .map(|(cid, h)| (cid.clone(), h.clone()))
                        .collect(),
                );
            }
        }
        None
    }

    /// Process the notification for the provided index and relay it
    /// along the dependent chain (dcrd `updateIndex` +
    /// `notifyDependent`).
    pub fn update_index(&mut self, id: &str, ntfn: &IndexNtfn) -> Result<(), IdxError> {
        let chain = self.chain_from(id).ok_or_else(|| {
            indexer_error(
                ErrorKind::FetchSubscription,
                format!("{id}: no index update subscription found"),
            )
        })?;
        self.update_chain(&chain, ntfn)
    }

    /// The recursive body of [`update_index`](Self::update_index)
    /// over an explicit chain slice.
    fn update_chain(
        &mut self,
        chain: &[(String, IndexerHandle)],
        ntfn: &IndexNtfn,
    ) -> Result<(), IdxError> {
        let (name, idx) = &chain[0];
        let (tip, _) = idx.borrow().tip().map_err(|err| {
            indexer_error(
                ErrorKind::FetchTip,
                format!("{name}: unable to fetch index tip: {err}"),
            )
        })?;

        let expected_height = match ntfn.ntfn_type {
            CONNECT_NTFN => tip.saturating_add(1),
            DISCONNECT_NTFN => tip,
            other => {
                return Err(indexer_error(
                    ErrorKind::InvalidNotificationType,
                    format!("{name}: unknown notification type received: {}", other.0),
                ));
            }
        };

        let ntfn_height = block_height(&ntfn.block);
        if ntfn_height < expected_height {
            // Relay the notification to the dependent since it is
            // possible for a dependent to have a lower tip height
            // than its prerequisite.  dcrd discards the relay error
            // on this path.
            let _ = self.notify_dependent(chain, ntfn);
        } else if ntfn_height > expected_height {
            // Receiving a notification with a height higher than the
            // expected implies a missed index update.
            return Err(indexer_error(
                ErrorKind::MissingNotification,
                format!(
                    "{name}: missing index notification, expected notification for \
                     height {expected_height}, got {ntfn_height}"
                ),
            ));
        } else {
            let db = idx.borrow().db();
            let db_tx = db.begin(true)?;
            match idx.borrow_mut().process_notification(&db_tx, ntfn) {
                Ok(()) => db_tx.commit()?,
                Err(err) => {
                    let _ = db_tx.rollback();
                    return Err(err);
                }
            }

            self.notify_dependent(chain, ntfn)?;

            maybe_notify_subscribers(&self.interrupt, &mut *idx.borrow_mut())?;
        }

        Ok(())
    }

    /// Relay the provided notification to the dependent of the first
    /// index in the chain, if there is one (dcrd `notifyDependent`).
    fn notify_dependent(
        &mut self,
        chain: &[(String, IndexerHandle)],
        ntfn: &IndexNtfn,
    ) -> Result<(), IdxError> {
        if interrupt_requested(&self.interrupt) {
            return Err(indexer_error(ErrorKind::InterruptRequested, INTERRUPT_MSG));
        }

        if chain.len() > 1 {
            self.update_chain(&chain[1..], ntfn)?;
        }
        Ok(())
    }

    /// Relay an index notification to the subscribed indexes (dcrd
    /// `Notify` + the `handleIndexUpdates` loop body): each
    /// prerequisite-free subscription processes the notification in
    /// turn; the first error cancels the subscriber and stops
    /// processing, mirroring dcrd's handler.
    pub fn notify(&mut self, ntfn: &IndexNtfn) -> Result<(), IdxError> {
        // Only relay notifications when there are subscribed indexes
        // to be notified.
        if self.subscribers == 0 {
            return Ok(());
        }

        let ids: Vec<String> = self.subscriptions.keys().cloned().collect();
        for id in ids {
            if let Err(err) = self.update_index(&id, ntfn) {
                self.cancelled = true;
                return Err(err);
            }
        }
        Ok(())
    }

    /// Determine the lowest index tip height among the subscribed
    /// indexes and their dependents (dcrd
    /// `findLowestIndexTipHeight`).  dcrd's dependent walk re-reads
    /// the tip of the first dependent at every step of a deeper
    /// chain; with at most one dependent per index in practice the
    /// behavior is identical.
    fn find_lowest_index_tip_height(
        &self,
        queryer: &dyn ChainQueryer,
    ) -> Result<(i64, i64), IdxError> {
        let (best_height, _) = queryer.best();
        let mut lowest_height = best_height;
        for entry in self.subscriptions.values() {
            let (name, idx) = &entry.chain[0];
            let (tip_height, tip_hash) = idx.borrow().tip()?;

            // Ensure the index tip is on the main chain.
            if !queryer.main_chain_has_block(&tip_hash) {
                return Err(IdxError::Other(format!(
                    "{name}: index tip ({tip_hash}) is not on the main chain"
                )));
            }

            if tip_height < lowest_height {
                lowest_height = tip_height;
            }

            // Update the lowest tip height if a dependent has a
            // lower tip height (dcrd reads `sub.dependent.idx.Tip()`
            // at every step of the walk).
            if entry.chain.len() > 1 {
                let first_dependent = &entry.chain[1].1;
                for _ in 1..entry.chain.len() {
                    let (tip_height, _) = first_dependent.borrow().tip()?;
                    if tip_height < lowest_height {
                        lowest_height = tip_height;
                    }
                }
            }
        }

        Ok((lowest_height, best_height))
    }

    /// Sync all subscribed indexes to the main chain by connecting
    /// blocks from after the lowest index tip to the current main
    /// chain tip (dcrd `CatchUp`).
    pub fn catch_up(&mut self, queryer: &dyn ChainQueryer) -> Result<(), IdxError> {
        let (lowest_height, best_height) = self.find_lowest_index_tip_height(queryer)?;

        // Nothing to do if all indexes are synced.
        if best_height == lowest_height {
            return Ok(());
        }

        let mut cached_parent: Option<Rc<MsgBlock>> = None;
        let mut height = lowest_height.saturating_add(1);
        while height <= best_height {
            if interrupt_requested(&self.interrupt) {
                return Err(indexer_error(ErrorKind::InterruptRequested, INTERRUPT_MSG));
            }

            let hash = queryer
                .block_hash_by_height(height)
                .map_err(IdxError::Other)?;

            // Ensure the next tip hash is on the main chain.
            if !queryer.main_chain_has_block(&hash) {
                return Err(indexer_error(
                    ErrorKind::BlockNotOnMainChain,
                    format!(
                        "the next block being synced to ({hash}) at height {height} is \
                         not on the main chain"
                    ),
                ));
            }

            let parent = match &cached_parent {
                None => {
                    let parent_hash = queryer
                        .block_hash_by_height(height.saturating_sub(1))
                        .map_err(IdxError::Other)?;
                    queryer
                        .block_by_hash(&parent_hash)
                        .map_err(IdxError::Other)?
                }
                Some(parent) => parent.clone(),
            };

            let child = queryer.block_by_hash(&hash).map_err(IdxError::Other)?;

            let is_treasury_enabled = queryer
                .is_treasury_agenda_active(&parent.header.block_hash())
                .map_err(IdxError::Other)?;

            let ntfn = IndexNtfn {
                ntfn_type: CONNECT_NTFN,
                block: child.clone(),
                parent,
                is_treasury_enabled,
            };

            // Relay the index update to subscribed indexes.
            let ids: Vec<String> = self.subscriptions.keys().cloned().collect();
            for id in ids {
                if let Err(err) = self.update_index(&id, &ntfn) {
                    self.cancelled = true;
                    return Err(err);
                }
            }

            cached_parent = Some(child);
            height = height.saturating_add(1);
        }

        Ok(())
    }

    /// Revert the provided index to a block on the main chain by
    /// repeatedly disconnecting the index tip while it is not on the
    /// main chain (dcrd `recoverIndex`); relayed disconnections reach
    /// the index's dependents exactly as connect updates do.
    pub fn recover_index(&mut self, id: &str) -> Result<(), IdxError> {
        let chain = self.chain_from(id).ok_or_else(|| {
            indexer_error(
                ErrorKind::FetchSubscription,
                format!("{id}: no index update subscription found"),
            )
        })?;
        let idx = chain[0].1.clone();

        // Fetch the current tip for the index.
        let (mut height, mut hash) = idx.borrow().tip()?;

        // Nothing to do if the index does not have any entries yet.
        if height == 0 {
            return Ok(());
        }

        let queryer = idx.borrow().queryer();

        // Nothing to do if the index tip is on the main chain.
        if queryer.main_chain_has_block(&hash) {
            return Ok(());
        }

        let mut cached_block: Option<Rc<MsgBlock>> = None;
        while !queryer.main_chain_has_block(&hash) {
            if interrupt_requested(&self.interrupt) {
                return Err(indexer_error(ErrorKind::InterruptRequested, INTERRUPT_MSG));
            }

            // Get the block, unless it's already cached.
            let block = match &cached_block {
                None if height > 0 => queryer.block_by_hash(&hash).map_err(IdxError::Other)?,
                _ => cached_block.clone().expect("cached recovery block"),
            };

            let parent_hash = block.header.prev_block;
            let parent = queryer
                .block_by_hash(&parent_hash)
                .map_err(IdxError::Other)?;
            cached_block = Some(parent.clone());

            let is_treasury_enabled = queryer
                .is_treasury_agenda_active(&parent_hash)
                .map_err(IdxError::Other)?;

            let ntfn = IndexNtfn {
                ntfn_type: DISCONNECT_NTFN,
                block: block.clone(),
                parent,
                is_treasury_enabled,
            };

            self.update_chain(&chain, &ntfn)?;

            // Update the tip to the previous block.
            hash = block.header.prev_block;
            height = height.saturating_sub(1);
        }

        Ok(())
    }
}
