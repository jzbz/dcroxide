// SPDX-License-Identifier: ISC
//! The daemon's chain event handler (dcrd server.go
//! `handleBlockchainNotification`): the chain's notification callback
//! forwards connected, disconnected, reorganization, and new-ticket
//! events straight into the websocket notification manager, and runs
//! dcrd's winning-tickets announcement gate over accepted blocks.
//!
//! The callback executes inside the chain's critical section (the
//! daemon holds the chain mutex through the whole processing call
//! where dcrd releases its chain lock around some sends), so the
//! winning-tickets lottery lookup — a chain query — cannot run there.
//! The gate-passing blocks queue instead, and the sync adapter drains
//! them right after the processing call returns with the mutex free,
//! which is exactly the lock situation dcrd's handler runs under.
//!
//! The reorg-started and reorg-done events only feed dcrd's
//! background template generator, and the early new-tip event only
//! feeds its block relay; neither is wired yet, so both are ignored
//! here.  The mix-observer refusal gate is likewise skipped until the
//! mixpool arrives — without a pool there are no misbehaving mix
//! inputs to refuse.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use dcroxide_blockchain::notifications::{BlockAcceptedNtfnsData, Notification};
use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::validate::{AgendaFlags, header_approves_parent};
use dcroxide_chaincfg::Params;
use dcroxide_chainhash::Hash;
use dcroxide_rpc::websocket::RpcNtfnManager;
use dcroxide_wire::{BlockHeader, CurrencyNet};

use crate::websocket::NodeNtfnMgr;

/// The maximum depth of a reorganization a side-chain block may sit
/// past while still announcing its winning tickets (dcrd
/// `maxReorgDepthNotify`); doubles as the exhaustion-attack guard
/// against expensive lottery calculations for old orphans.
const MAX_REORG_DEPTH_NOTIFY: i64 = 6;

/// The daemon's chain event handler state (dcrd's `server` fields the
/// handler consults).  Clones share the same state.
#[derive(Clone)]
pub struct ChainNtfnHandler {
    /// The websocket notification manager, present when the RPC
    /// server runs (dcrd's nil `rpcServer` checks around the ws
    /// sends; the index and mempool maintenance run either way).
    ntfn: Option<NodeNtfnMgr>,
    params: Params,
    allow_unsynced_mining: bool,
    /// The blocks whose winning tickets were already announced (dcrd
    /// `lotteryDataBroadcast`; the reference release never prunes it).
    lottery_data_broadcast: Arc<Mutex<HashSet<Hash>>>,
    /// Gate-passing accepted blocks awaiting their lottery lookup.
    pending_winning_tickets: Arc<Mutex<Vec<(Hash, i64)>>>,
    /// Connected and disconnected blocks awaiting their mempool
    /// maintenance.
    pending_block_events: Arc<Mutex<Vec<PendingBlockEvent>>>,
    /// The shared transaction pool the maintenance drives.
    tx_pool: Arc<Mutex<crate::txmempool::NodeTxPool>>,
    /// The relay registry for the orphan-acceptance announce cascade.
    sync_peers: crate::dispatch::SyncPeers,
    /// The recently-advertised cache the cascade feeds.
    recently_advertised: Arc<Mutex<dcroxide_containers::lru::Map<Hash, dcroxide_wire::MsgTx>>>,
    /// The index subscriber the drained block events feed (dcrd's
    /// `s.indexSubscriber.Notify` at the end of each connect and
    /// disconnect case; `None` when no index is enabled).
    index_subscriber: Option<Arc<Mutex<dcroxide_indexers::IndexSubscriber>>>,
}

/// A block event awaiting its mempool maintenance (dcrd's handler
/// runs it inline with the chain lock released; the daemon's callback
/// runs under the chain mutex and the pool reaches back into the
/// chain, so the work defers to the post-processing drain).
enum PendingBlockEvent {
    /// A block connected to the main chain.
    Connected {
        block: dcroxide_wire::MsgBlock,
        parent: dcroxide_wire::MsgBlock,
        check_tx_flags: AgendaFlags,
    },
    /// A block disconnected from the main chain.
    Disconnected {
        block: dcroxide_wire::MsgBlock,
        parent: dcroxide_wire::MsgBlock,
        check_tx_flags: AgendaFlags,
    },
}

impl ChainNtfnHandler {
    /// A handler forwarding into the given notification manager and
    /// driving the pool's block maintenance through the relay sinks.
    pub fn new(
        ntfn: Option<NodeNtfnMgr>,
        params: Params,
        allow_unsynced_mining: bool,
        tx_pool: Arc<Mutex<crate::txmempool::NodeTxPool>>,
        sync_peers: crate::dispatch::SyncPeers,
        recently_advertised: Arc<Mutex<dcroxide_containers::lru::Map<Hash, dcroxide_wire::MsgTx>>>,
    ) -> ChainNtfnHandler {
        ChainNtfnHandler {
            ntfn,
            params,
            allow_unsynced_mining,
            lottery_data_broadcast: Arc::default(),
            pending_winning_tickets: Arc::default(),
            pending_block_events: Arc::default(),
            tx_pool,
            sync_peers,
            recently_advertised,
            index_subscriber: None,
        }
    }

    /// Feed the drained block events into the given index subscriber
    /// (dcrd's server holding its `indexSubscriber`).  Must be set
    /// before the handler is cloned into the chain callback.
    pub fn set_index_subscriber(
        &mut self,
        subscriber: Arc<Mutex<dcroxide_indexers::IndexSubscriber>>,
    ) {
        self.index_subscriber = Some(subscriber);
    }

    /// The chain callback body (dcrd `handleBlockchainNotification`);
    /// runs inside the chain's critical section and only queues.
    pub fn handle(&self, notification: &Notification<'_>) {
        match notification {
            // The early new-tip event only feeds dcrd's block relay,
            // which is not wired yet.
            Notification::NewTipBlockChecked(_) => {}
            Notification::BlockAccepted(data) => self.handle_block_accepted(data),
            Notification::BlockConnected(data) => {
                if let Some(ntfn) = &self.ntfn {
                    ntfn.notify_block_connected(data.block.clone());
                }
                self.pending_block_events
                    .lock()
                    .expect("pending block events")
                    .push(PendingBlockEvent::Connected {
                        block: data.block.clone(),
                        parent: data.parent_block.clone(),
                        check_tx_flags: data.check_tx_flags,
                    });
            }
            Notification::BlockDisconnected(data) => {
                if let Some(ntfn) = &self.ntfn {
                    ntfn.notify_block_disconnected(data.block.clone());
                }
                self.pending_block_events
                    .lock()
                    .expect("pending block events")
                    .push(PendingBlockEvent::Disconnected {
                        block: data.block.clone(),
                        parent: data.parent_block.clone(),
                        check_tx_flags: data.check_tx_flags,
                    });
            }
            // These only feed dcrd's background template generator,
            // which is not wired yet.
            Notification::ChainReorgStarted | Notification::ChainReorgDone => {}
            Notification::Reorganization(data) => {
                if let Some(ntfn) = &self.ntfn {
                    ntfn.notify_reorganization(
                        data.old_hash,
                        data.old_height,
                        data.new_hash,
                        data.new_height,
                    );
                }
            }
            Notification::NewTickets(data) => {
                if let Some(ntfn) = &self.ntfn {
                    ntfn.notify_new_tickets(
                        data.hash,
                        data.height,
                        data.stake_difficulty,
                        data.tickets_new.clone(),
                    );
                }
            }
        }
    }

    /// Queue the winning-tickets lookup for an accepted block that
    /// passes dcrd's announcement gate.  dcrd's first condition on
    /// the whole case is the RPC server running (`s.rpcServer !=
    /// nil`), so without one there is no lottery work and no
    /// broadcast-set growth.
    fn handle_block_accepted(&self, data: &BlockAcceptedNtfnsData<'_>) {
        if self.ntfn.is_none() {
            return;
        }
        if !should_notify_winning_tickets(
            &self.params,
            &data.block.header,
            data.best_height,
            data.fork_len,
        ) {
            return;
        }
        let block_hash = data.block.header.block_hash();
        if self
            .lottery_data_broadcast
            .lock()
            .expect("lottery broadcast set")
            .contains(&block_hash)
        {
            return;
        }
        self.pending_winning_tickets
            .lock()
            .expect("pending winning tickets")
            .push((block_hash, i64::from(data.block.header.height)));
    }

    /// Run the queued lottery lookups now that the chain mutex is
    /// free, announcing each block's winning tickets and recording it
    /// in the broadcast set (dcrd's inline `LotteryDataForBlock` +
    /// `NotifyWinningTickets` + `lotteryDataBroadcast` insert).  dcrd
    /// gates the whole accepted case on the sync being current unless
    /// unsynced mining is allowed.
    pub fn drain_pending_winning_tickets(
        &self,
        chain: &Arc<Mutex<Chain>>,
        adjusted_time_unix: i64,
    ) {
        let pending: Vec<(Hash, i64)> = core::mem::take(
            &mut *self
                .pending_winning_tickets
                .lock()
                .expect("pending winning tickets"),
        );
        if pending.is_empty() {
            return;
        }

        let mut chain = chain.lock().expect("chain mutex poisoned");
        if !self.allow_unsynced_mining && !chain.is_current_at(adjusted_time_unix) {
            return;
        }
        for (block_hash, block_height) in pending {
            {
                let broadcast = self
                    .lottery_data_broadcast
                    .lock()
                    .expect("lottery broadcast set");
                if broadcast.contains(&block_hash) {
                    continue;
                }
            }
            // A failed lookup skips the block without recording it,
            // like dcrd's logged break.
            let Ok((winners, _pool_size, _final_state)) =
                chain.lottery_data_for_block(&block_hash, &self.params)
            else {
                continue;
            };
            if let Some(ntfn) = &self.ntfn {
                let mut mgr = ntfn.clone();
                RpcNtfnManager::notify_winning_tickets(
                    &mut mgr,
                    &block_hash,
                    block_height,
                    &winners,
                );
            }
            self.lottery_data_broadcast
                .lock()
                .expect("lottery broadcast set")
                .insert(block_hash);
        }
    }
}

impl ChainNtfnHandler {
    /// Run the queued mempool maintenance for the connected and
    /// disconnected blocks, in order, now that the chain mutex is
    /// free (dcrd `handleBlockchainNotification`'s NTBlockConnected
    /// and NTBlockDisconnected mempool halves; the fee-estimator feed
    /// and the rebroadcast bookkeeping arrive with later pieces).
    pub fn drain_pending_block_events(&self) {
        let pending: Vec<PendingBlockEvent> = core::mem::take(
            &mut *self
                .pending_block_events
                .lock()
                .expect("pending block events"),
        );
        for event in pending {
            let (ntfn_type, block, parent, check_tx_flags) = match event {
                PendingBlockEvent::Connected {
                    block,
                    parent,
                    check_tx_flags,
                } => {
                    self.handle_connected_block(&block, &parent, check_tx_flags);
                    (
                        dcroxide_indexers::CONNECT_NTFN,
                        block,
                        parent,
                        check_tx_flags,
                    )
                }
                PendingBlockEvent::Disconnected {
                    block,
                    parent,
                    check_tx_flags,
                } => {
                    self.handle_disconnected_block(&block, &parent, check_tx_flags);
                    (
                        dcroxide_indexers::DISCONNECT_NTFN,
                        block,
                        parent,
                        check_tx_flags,
                    )
                }
            };
            // Notify the subscribed indexes at the end of each case
            // (dcrd's `s.indexSubscriber.Notify`).  A failed update
            // marks the subscriber cancelled and later notifications
            // skip it, like dcrd's handler goroutine logging the
            // error and cancelling its context so the quit channel
            // absorbs further sends.
            if let Some(subscriber) = &self.index_subscriber {
                let mut subscriber = subscriber.lock().expect("index subscriber mutex poisoned");
                if !subscriber.cancelled() {
                    let ntfn = dcroxide_indexers::IndexNtfn {
                        ntfn_type,
                        block: Arc::new(block),
                        parent: Arc::new(parent),
                        is_treasury_enabled: check_tx_flags.is_treasury_enabled(),
                    };
                    if let Err(e) = subscriber.notify(&ntfn) {
                        // The only operator-visible diagnostic for a
                        // halted index (dcrd logs the error right
                        // before cancelling).
                        eprintln!("index update failed, index maintenance halted: {e}");
                    }
                }
            }
        }
    }

    /// Per-transaction maintenance over a connected block's
    /// transactions (dcrd `handleConnectedBlockTxns`): drop each from
    /// the pool without touching its now-valid redeemers, unstage
    /// dependents, evict double spends and matching orphans, and
    /// process newly acceptable orphans with the announce cascade.
    fn handle_connected_block(
        &self,
        block: &dcroxide_wire::MsgBlock,
        parent: &dcroxide_wire::MsgBlock,
        check_tx_flags: AgendaFlags,
    ) {
        let is_treasury_enabled = check_tx_flags.is_treasury_enabled();
        let regular = block.transactions.get(1..).unwrap_or(&[]);
        let stake = if is_treasury_enabled {
            block.stransactions.get(1..).unwrap_or(&[])
        } else {
            &block.stransactions[..]
        };
        for tx in regular.iter().chain(stake) {
            let tx_hash = tx.tx_hash();
            let accepted = {
                let mut pool = self.tx_pool.lock().expect("tx pool mutex poisoned");
                pool.remove_transaction(tx, &tx_hash, false);
                pool.maybe_accept_dependents(tx, &tx_hash, is_treasury_enabled);
                pool.remove_double_spends(tx, &tx_hash);
                pool.remove_orphan_pub(&tx_hash);
                pool.process_orphans(tx, check_tx_flags)
            };
            self.announce_transactions(&accepted);
        }

        // A block that disapproves its parent returns the parent's
        // regular transactions to contention.
        if !header_approves_parent(&block.header) {
            let resurrect = parent.transactions.get(1..).unwrap_or(&[]);
            let _errs = self
                .tx_pool
                .lock()
                .expect("tx pool mutex poisoned")
                .maybe_accept_transactions(resurrect);
        }
    }

    /// The disconnected-block maintenance (dcrd's NTBlockDisconnected
    /// case): drop the parent's transactions when the disconnected
    /// block disapproved them, then re-admit the disconnected block's
    /// own transactions.
    fn handle_disconnected_block(
        &self,
        block: &dcroxide_wire::MsgBlock,
        parent: &dcroxide_wire::MsgBlock,
        check_tx_flags: AgendaFlags,
    ) {
        let is_treasury_enabled = check_tx_flags.is_treasury_enabled();
        if !header_approves_parent(&block.header) {
            for tx in parent.transactions.get(1..).unwrap_or(&[]) {
                let tx_hash = tx.tx_hash();
                let mut pool = self.tx_pool.lock().expect("tx pool mutex poisoned");
                pool.remove_transaction(tx, &tx_hash, false);
                pool.maybe_accept_dependents(tx, &tx_hash, is_treasury_enabled);
                pool.remove_double_spends(tx, &tx_hash);
                pool.remove_orphan_pub(&tx_hash);
                // dcrd discards the orphan acceptances on disconnect.
                let _ = pool.process_orphans(tx, check_tx_flags);
            }
        }

        let mut readmit: Vec<dcroxide_wire::MsgTx> =
            block.transactions.get(1..).unwrap_or(&[]).to_vec();
        readmit.extend_from_slice(if is_treasury_enabled {
            block.stransactions.get(1..).unwrap_or(&[])
        } else {
            &block.stransactions[..]
        });
        let _errs = self
            .tx_pool
            .lock()
            .expect("tx pool mutex poisoned")
            .maybe_accept_transactions(&readmit);
    }

    /// The announce cascade for transactions the maintenance accepted
    /// (dcrd `AnnounceNewTransactions`): websocket notifications, the
    /// recently-advertised cache, and the peer inventory relay.
    fn announce_transactions(&self, accepted: &[Hash]) {
        if accepted.is_empty() {
            return;
        }
        let mut pairs = Vec::new();
        for hash in accepted {
            let fetched = {
                let pool = self.tx_pool.lock().expect("tx pool mutex poisoned");
                pool.fetch_transaction(hash)
            };
            let Some(tx) = fetched else { continue };
            let tree = if dcroxide_stake::determine_tx_type(&tx) == dcroxide_stake::TxType::Regular
            {
                dcroxide_wire::TX_TREE_REGULAR
            } else {
                dcroxide_wire::TX_TREE_STAKE
            };
            self.recently_advertised
                .lock()
                .expect("recently advertised poisoned")
                .put(*hash, tx.clone());
            self.sync_peers
                .relay_inventory(&crate::server::RelayInvFacts {
                    inv_type: dcroxide_wire::InvType::TX,
                    inv_hash: *hash,
                    req_services: dcroxide_wire::ServiceFlag(0),
                    immediate: false,
                    data_is_block_header: false,
                    data_is_tx: true,
                });
            pairs.push((tx, tree));
        }
        if let Some(ntfn) = &self.ntfn {
            ntfn.notify_new_transactions(pairs);
        }
    }
}

/// dcrd's winning-tickets announcement gate over an accepted block
/// (server.go's NTBlockAccepted case): stake voting must be at hand,
/// the block must not sit past a deep reorganization, and old
/// pre-vote-version mainnet blocks are skipped.
pub fn should_notify_winning_tickets(
    params: &Params,
    header: &BlockHeader,
    best_height: i64,
    fork_len: i64,
) -> bool {
    let block_height = i64::from(header.height);
    let reorg_depth = best_height.saturating_sub(block_height.saturating_sub(fork_len));
    let is_old_mainnet_block =
        params.net == CurrencyNet::MAIN_NET && block_height >= 1_035_288 && header.version < 11;
    block_height >= params.stake_validation_height.saturating_sub(1)
        && reorg_depth < MAX_REORG_DEPTH_NOTIFY
        && !is_old_mainnet_block
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(height: u32, version: i32) -> BlockHeader {
        BlockHeader {
            version,
            prev_block: Hash::ZERO,
            merkle_root: Hash::ZERO,
            stake_root: Hash::ZERO,
            vote_bits: 0,
            final_state: [0u8; 6],
            voters: 0,
            fresh_stake: 0,
            revocations: 0,
            pool_size: 0,
            bits: 0,
            sbits: 0,
            height,
            size: 0,
            timestamp: 0,
            nonce: 0,
            extra_data: [0u8; 32],
            stake_version: 0,
        }
    }

    #[test]
    fn the_gate_requires_stake_validation_to_be_at_hand() {
        let params = dcroxide_chaincfg::testnet3_params();
        let svh = params.stake_validation_height;
        let at_hand = header((svh - 1) as u32, 11);
        assert!(should_notify_winning_tickets(&params, &at_hand, svh - 1, 0));
        let early = header((svh - 2) as u32, 11);
        assert!(!should_notify_winning_tickets(&params, &early, svh - 2, 0));
    }

    #[test]
    fn the_gate_refuses_deep_reorg_side_chains() {
        // dcrd's worked example shifted above simnet's stake
        // validation height: block 203' on a side chain forked after
        // 200 with best tip 206 has reorg depth 206 - (203 - 3) = 6,
        // which is refused; depth 5 passes.
        let params = dcroxide_chaincfg::simnet_params();
        let block = header(203, 11);
        assert!(!should_notify_winning_tickets(&params, &block, 206, 3));
        assert!(should_notify_winning_tickets(&params, &block, 205, 3));
    }

    #[test]
    fn the_gate_skips_old_mainnet_blocks() {
        let params = dcroxide_chaincfg::mainnet_params();
        let old = header(1_035_288, 10);
        assert!(!should_notify_winning_tickets(&params, &old, 1_035_288, 0));
        let new_version = header(1_035_288, 11);
        assert!(should_notify_winning_tickets(
            &params,
            &new_version,
            1_035_288,
            0
        ));
        // The same old version off mainnet is unaffected.
        let simnet = dcroxide_chaincfg::simnet_params();
        let off_mainnet = header(1_035_288, 10);
        assert!(should_notify_winning_tickets(
            &simnet,
            &off_mainnet,
            1_035_288,
            0
        ));
    }
}
