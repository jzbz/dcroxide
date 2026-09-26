// SPDX-License-Identifier: ISC
//! The daemon's chain event handler (dcrd server.go
//! `handleBlockchainNotification`): the chain's notification callback
//! relays the early checked-block announcement on the spot, queues the
//! connected, disconnected, reorganization, and new-ticket events for
//! the websocket notification manager in the chain's emission order,
//! and runs dcrd's winning-tickets announcement gate over accepted
//! blocks.
//!
//! The callback executes inside the chain's critical section (the
//! daemon holds the chain mutex through the whole processing call
//! where dcrd releases its chain lock around some sends), so the
//! winning-tickets lottery lookup — a chain query — cannot run there.
//! The gate-passing blocks queue instead, and the sync adapter drains
//! them right after the processing call returns with the mutex free,
//! which is exactly the lock situation dcrd's handler runs under.
//!
//! The early checked-block announcement is the exception: dcrd relays
//! it from the callback with its chain lock held, so the block spreads
//! while the expensive connect runs, and the port does the same.  The
//! relay takes only the peer registry and per-peer relay locks, which
//! are leaves — nothing holding either ever waits on the chain mutex
//! (every enqueue under them is a non-blocking `try_send`) — so taking
//! them under the chain mutex cannot close a cycle.
//!
//! The reorg-started and reorg-done events feed dcrd's background
//! template generator (present when mining addresses are configured),
//! halting and resuming template generation around the reorg; the
//! block accepted, connected, and disconnected events feed it too.
//! The mix-observer refusal gate runs when a mixpool is present, which
//! it is in the daemon; without one there are no misbehaving mix inputs
//! to refuse and the gate is skipped.
//!
//! Lock order: the mixpool mutex is never taken while the chain mutex
//! is held.  The mixpool reaches back into the chain for its tip and
//! UTXO lookups, so chain-then-mixpool would close an AB-BA cycle
//! against every peer's mix-message intake; see
//! [`ChainNtfnHandler::drain_pending_winning_tickets`], the one place
//! here that touches both.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

use dcroxide_blockchain::notifications::{
    BlockAcceptedNtfnsData, LogCallback, LogLevel as ChainLogLevel, Notification,
};

use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::validate::{AgendaFlags, header_approves_parent};
use dcroxide_chaincfg::Params;
use dcroxide_chainhash::Hash;
use dcroxide_rpc::websocket::RpcNtfnManager;
use dcroxide_wire::{BlockHeader, CurrencyNet};

/// The subsystem tag dcrd's `log.go:64` gives `internal/blockchain`.
const CHAN_LOG_SUBSYSTEM: &str = "CHAN";

/// The chain's package log sink (dcrd `log.go:85`,
/// `blockchain.UseLogger(chanLog)`): the chain formats dcrd's line and
/// this renders it under the `CHAN` tag, so `--debuglevel CHAN=`
/// governs it exactly as upstream.
pub fn chain_log_sink() -> LogCallback {
    Box::new(|level, msg| match level {
        ChainLogLevel::Trace => crate::logging::trace(CHAN_LOG_SUBSYSTEM, msg),
        ChainLogLevel::Debug => crate::logging::debug(CHAN_LOG_SUBSYSTEM, msg),
        ChainLogLevel::Info => crate::logging::info(CHAN_LOG_SUBSYSTEM, msg),
        ChainLogLevel::Warn => crate::logging::warn(CHAN_LOG_SUBSYSTEM, msg),
        ChainLogLevel::Error => crate::logging::error(CHAN_LOG_SUBSYSTEM, msg),
    })
}

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
    /// The netsync is-current gate the relay and estimator-enable
    /// paths consult (dcrd gates the NTBlockAccepted case on
    /// `s.syncManager.IsCurrent()`).
    sync_gate: crate::sync::SyncGate,
    /// The shared mixpool whose misbehavior observer the
    /// winning-tickets path consults (dcrd's
    /// `s.mixObserver.MisbehavingBlock` refusal); absent in tests that
    /// carry no pool.
    mix_pool: Option<Arc<Mutex<crate::mixnode::NodeMixPool>>>,
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
    /// Accepted-block announcements awaiting their gated relay
    /// fan-out (the send at the end of dcrd's NTBlockAccepted case).
    pending_accepted_announcements: Arc<Mutex<Vec<BlockHeader>>>,
    /// Connected and disconnected blocks awaiting their mempool
    /// maintenance, with the new-ticket and reorganization events
    /// interleaved in the chain's emission order.
    pending_block_events: Arc<Mutex<Vec<PendingBlockEvent>>>,
    /// Serializes the whole deferred-notification drain: the netsync
    /// post-process path, the generator's drain hook and the RPC
    /// `invalidateblock`/`reconsiderblock` seams all run the full
    /// [`ChainNtfnHandler::drain_pending`] sequence, and without this
    /// one could take a prefix of an in-flight reorg batch while another
    /// takes the suffix, processing the maintenance, announcements,
    /// and index notifications out of the strict order dcrd's single
    /// notification goroutine emits them in.
    drain_lock: Arc<Mutex<()>>,
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
    /// The recently-confirmed filter every confirmed transaction
    /// feeds (dcrd `TransactionConfirmed` adding to
    /// `recentlyConfirmedTxns`), shared with the netsync manager.
    recently_confirmed: Option<Arc<Mutex<dcroxide_containers::apbf::Filter>>>,
    /// The rebroadcast feeder for confirmation removals and the
    /// block-change prunes; `Some` only when the RPC server runs
    /// (dcrd gates both on `s.rpcServer != nil` since only RPC
    /// submissions are ever tracked).
    rebroadcast: Option<crate::rebroadcast::RebroadcastSink>,
    /// The background template generator feeder; `Some` only when
    /// mining addresses are configured (dcrd's chain events driving
    /// `s.bg`, present whenever the generator runs).
    generator: Option<crate::bgtemplate::GeneratorSink>,
    /// The shared fee estimator, fed the connected block's transactions
    /// and enabled at the first accepted block (dcrd's `s.feeEstimator`
    /// driven from the NTBlockConnected and NTBlockAccepted cases).
    /// Always `Some` on the daemon; `None` in tests that skip it.
    fee_estimator: Option<crate::fees::SharedFeeEstimator>,
}

/// A block event awaiting its mempool maintenance (dcrd's handler
/// runs it inline with the chain lock released; the daemon's callback
/// runs under the chain mutex and the pool reaches back into the
/// chain, so the work defers to the post-processing drain).  The
/// blocks are shared `Arc`s: the whole fan-out — generator feed,
/// mempool maintenance, websocket notify, index notify — clones
/// pointers to the one block the chain connected, like dcrd passing
/// the same `*dcrutil.Block` to every observer.
enum PendingBlockEvent {
    /// A block connected to the main chain.
    Connected {
        block: Arc<dcroxide_wire::MsgBlock>,
        parent: Arc<dcroxide_wire::MsgBlock>,
        check_tx_flags: AgendaFlags,
    },
    /// A block disconnected from the main chain.
    Disconnected {
        block: Arc<dcroxide_wire::MsgBlock>,
        parent: Arc<dcroxide_wire::MsgBlock>,
        check_tx_flags: AgendaFlags,
    },
    /// Tickets matured from the most recently connected block (dcrd
    /// NTNewTickets, which the chain sends right after that block's
    /// NTBlockConnected).  It rides the same queue as the block events
    /// so the websocket manager sees newtickets after blockconnected,
    /// as every dcrd client does.
    NewTickets {
        hash: Hash,
        height: i64,
        stake_difficulty: i64,
        tickets_new: Vec<Hash>,
    },
    /// The chain reorganized (dcrd NTReorganization, which the chain
    /// sends after every disconnect and connect of the reorg).  Queued
    /// behind those block events so a notifyblocks client sees the
    /// blockdisconnected and blockconnected frames first, as in dcrd.
    Reorganization {
        old_hash: Hash,
        old_height: i64,
        new_hash: Hash,
        new_height: i64,
    },
}

/// What dcrd's chain still holds of a run of queued disconnects while it
/// handles each of them.
///
/// dcrd handles a disconnect with the tip at the disconnected block's
/// parent (`internal/blockchain/chain.go:929, :943-949`), so when a
/// reorganization or an `invalidateblock` detaches several blocks, the
/// blocks it has yet to detach are still in the chain while it readmits
/// the newer ones' transactions: a ticket spending a split transaction
/// mined a block earlier is readmitted, and moves to the stage pool once
/// the split is readmitted too.  The drain runs with every block of the
/// run already detached, so it hands the readmission those blocks'
/// transactions as transient ones (`TxPool::with_transient`), as far as
/// dcrd's chain holds them at that point: each block's stake tree, and
/// its regular tree unless its child, still in the chain, disapproved
/// it.  (The parent of the disconnected block is the tip then, whose
/// regular tree the chain holds whatever the disconnected block voted.)
///
/// The fork block the run ends at stays in the chain, but when the
/// block connected on top of it next disapproves it, the chain the drain
/// runs against no longer holds its regular tree, which dcrd's chain
/// holds while it handles the run.  That tree is handed over too, under
/// the same rule, so the disconnected children of its transactions are
/// readmitted, as in dcrd, before that connect returns their parents to
/// the pool.
#[derive(Default)]
struct DisconnectRun {
    /// How many disconnects of the run follow the one being handled.
    remaining: usize,
    /// Whether the connect queued right after the run disapproves the
    /// fork block, so the drain's chain lacks its regular tree.
    fork_disapproved: bool,
    /// The transactions of the run's blocks older than the one being
    /// handled, and of a disapproved fork block, that dcrd's chain holds
    /// at its parent, by hash.
    txs: BTreeMap<[u8; 32], dcroxide_wire::MsgTx>,
}

impl DisconnectRun {
    /// Move on to the disconnect of `block`, whose parent is `parent`,
    /// with `later` the events queued after it: the next disconnect of
    /// the current run, or the first of a new one.
    fn advance(
        &mut self,
        block: &dcroxide_wire::MsgBlock,
        parent: &dcroxide_wire::MsgBlock,
        later: &VecDeque<PendingBlockEvent>,
    ) {
        if self.remaining == 0 {
            self.start(block, parent, later);
            return;
        }
        self.remaining = self.remaining.saturating_sub(1);

        // This block leaves dcrd's chain and its parent becomes the tip,
        // whose regular tree the chain holds even when this block
        // disapproved it.  The drain's chain holds the fork block's
        // unless the next connect disapproves it.
        for tx in block.transactions.iter().chain(&block.stransactions) {
            self.txs.remove(&tx.tx_hash().0);
        }
        if (self.remaining > 0 || self.fork_disapproved) && !header_approves_parent(&block.header) {
            hold(&mut self.txs, &parent.transactions);
        }
    }

    /// Start a run at the disconnect of `block`, whose parent is
    /// `parent`: the disconnects queued right after it that each detach
    /// the previous one's parent.
    fn start(
        &mut self,
        block: &dcroxide_wire::MsgBlock,
        parent: &dcroxide_wire::MsgBlock,
        later: &VecDeque<PendingBlockEvent>,
    ) {
        self.txs.clear();
        let mut child = block;
        let mut fork = parent;
        let mut count = 0usize;
        for event in later {
            let PendingBlockEvent::Disconnected {
                block: older,
                parent: older_parent,
                ..
            } = event
            else {
                break;
            };
            if older.header.block_hash() != child.header.prev_block {
                break;
            }
            if count == 0 || header_approves_parent(&child.header) {
                hold(&mut self.txs, &older.transactions);
            }
            hold(&mut self.txs, &older.stransactions);
            child = older;
            fork = older_parent;
            count = count.saturating_add(1);
        }
        self.remaining = count;

        // The fork block's regular tree, when the connect queued next
        // builds on it and disapproves it: dcrd's chain holds it here
        // when it is the tip or its child in the run approves it.
        self.fork_disapproved = matches!(
            later.get(count),
            Some(PendingBlockEvent::Connected { block: next, .. })
                if next.header.prev_block == child.header.prev_block
                    && !header_approves_parent(&next.header)
        );
        if self.fork_disapproved && (count == 0 || header_approves_parent(&child.header)) {
            hold(&mut self.txs, &fork.transactions);
        }
    }
}

/// Add a block tree's transactions to a [`DisconnectRun`]'s map.
fn hold(txs: &mut BTreeMap<[u8; 32], dcroxide_wire::MsgTx>, tree: &[dcroxide_wire::MsgTx]) {
    for tx in tree {
        txs.insert(tx.tx_hash().0, tx.clone());
    }
}

/// The transactions the connects queued in `later` mined.  Built only
/// when an orphan still fails once a block's maintenance processes it,
/// and once per connect, so the hashing stays off the common path.
fn mined_by_later_connects(later: &VecDeque<PendingBlockEvent>) -> HashSet<Hash> {
    later
        .iter()
        .filter_map(|event| match event {
            PendingBlockEvent::Connected { block, .. } => Some(block),
            _ => None,
        })
        .flat_map(|block| block.transactions.iter().chain(&block.stransactions))
        .map(dcroxide_wire::MsgTx::tx_hash)
        .collect()
}

impl ChainNtfnHandler {
    /// A handler forwarding into the given notification manager and
    /// driving the pool's block maintenance through the relay sinks.
    #[allow(clippy::too_many_arguments)] // Mirrors dcrd's notification surface.
    pub fn new(
        ntfn: Option<NodeNtfnMgr>,
        params: Params,
        allow_unsynced_mining: bool,
        sync_gate: crate::sync::SyncGate,
        mix_pool: Option<Arc<Mutex<crate::mixnode::NodeMixPool>>>,
        tx_pool: Arc<Mutex<crate::txmempool::NodeTxPool>>,
        sync_peers: crate::dispatch::SyncPeers,
        recently_advertised: Arc<Mutex<dcroxide_containers::lru::Map<Hash, dcroxide_wire::MsgTx>>>,
    ) -> ChainNtfnHandler {
        ChainNtfnHandler {
            ntfn,
            params,
            allow_unsynced_mining,
            sync_gate,
            mix_pool,
            lottery_data_broadcast: Arc::default(),
            pending_winning_tickets: Arc::default(),
            pending_accepted_announcements: Arc::default(),
            pending_block_events: Arc::default(),
            drain_lock: Arc::default(),
            tx_pool,
            sync_peers,
            recently_advertised,
            index_subscriber: None,
            recently_confirmed: None,
            rebroadcast: None,
            generator: None,
            fee_estimator: None,
        }
    }

    /// Record confirmed transactions in the given shared filter (dcrd
    /// `TransactionConfirmed`'s `recentlyConfirmedTxns.Add`).  Must be
    /// set before the handler is cloned into the chain callback.
    pub fn set_recently_confirmed(
        &mut self,
        filter: Arc<Mutex<dcroxide_containers::apbf::Filter>>,
    ) {
        self.recently_confirmed = Some(filter);
    }

    /// Feed confirmation removals and block-change prunes into the
    /// rebroadcast thread (dcrd's `RemoveRebroadcastInventory` and
    /// `PruneRebroadcastInventory`, both gated on the RPC server
    /// running).  Must be set before the handler is cloned into the
    /// chain callback.
    pub fn set_rebroadcast(&mut self, sink: crate::rebroadcast::RebroadcastSink) {
        self.rebroadcast = Some(sink);
    }

    /// Feed the chain's block and reorganization events into the
    /// background template generator (dcrd's chain notifications
    /// driving `s.bg`).  Must be set before the handler is cloned into
    /// the chain callback.
    pub fn set_generator(&mut self, sink: crate::bgtemplate::GeneratorSink) {
        self.generator = Some(sink);
    }

    /// Feed connected blocks into the shared fee estimator and enable
    /// it at the first accepted block (dcrd's `s.feeEstimator` driven
    /// from the chain notifications).  Must be set before the handler
    /// is cloned into the chain callback.
    pub fn set_fee_estimator(&mut self, estimator: crate::fees::SharedFeeEstimator) {
        self.fee_estimator = Some(estimator);
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
    /// runs inside the chain's critical section and, apart from the
    /// early checked-block relay, only queues.
    pub fn handle(&self, notification: &Notification<'_>) {
        match notification {
            // A block extending the current tip passed the sanity
            // and contextual checks: relay it immediately to full
            // nodes (dcrd's NTNewTipBlockChecked case calling
            // `RelayBlockAnnouncement(block, SFNodeNetwork)`; the
            // chain already gated the emission on being current).
            // Relayed here, under the chain mutex, exactly as dcrd does
            // with its chain lock held, so the announcement goes out
            // before the expensive connect rather than after it; the
            // registry and relay locks it takes are leaves (see the
            // module comment).
            Notification::NewTipBlockChecked(block) => {
                self.sync_peers.relay_block_announcement(
                    &block.header,
                    dcroxide_wire::ServiceFlag::NODE_NETWORK,
                );
            }
            Notification::BlockAccepted(data) => {
                if let Some(generator) = &self.generator {
                    generator.block_accepted(Arc::new(data.block.clone()));
                }
                self.handle_block_accepted(data);
            }
            Notification::BlockConnected(data) => {
                // The block-connected websocket notification is deferred
                // to the block-event drain: dcrd emits it only after the
                // connected block's mempool maintenance has announced any
                // newly acceptable transactions, so a websocket client
                // sees txaccepted before blockconnected.
                //
                // The generator feed stays here at callback time, where it
                // is correctly interleaved with the callback-time reorg
                // events (a reorg disconnects then connects blocks between
                // ChainReorgStarted and ChainReorgDone); moving it to the
                // drain would let ChainReorgDone reach the generator before
                // the reorg's own block events.  dcrd feeds the generator
                // only after the block's mempool maintenance and
                // NotifyBlockConnected, so the generator finishes this
                // block's drain before it handles the block (bgtemplate
                // `finish_chain_maintenance`): the votes it counts and the
                // pool it builds from are the maintained ones, and its work
                // notification follows the blockconnected frame.
                if let Some(generator) = &self.generator {
                    generator.block_connected(Arc::clone(&data.block));
                }
                self.pending_block_events
                    .lock()
                    .expect("pending block events")
                    .push(PendingBlockEvent::Connected {
                        block: Arc::clone(&data.block),
                        parent: Arc::clone(&data.parent_block),
                        check_tx_flags: data.check_tx_flags,
                    });
            }
            Notification::BlockDisconnected(data) => {
                // The block-disconnected websocket notification is also
                // deferred to the drain, matching dcrd's emission after
                // the disconnect mempool maintenance and index notify.
                if let Some(generator) = &self.generator {
                    generator.block_disconnected(Arc::clone(&data.block));
                }
                self.pending_block_events
                    .lock()
                    .expect("pending block events")
                    .push(PendingBlockEvent::Disconnected {
                        block: Arc::clone(&data.block),
                        parent: Arc::clone(&data.parent_block),
                        check_tx_flags: data.check_tx_flags,
                    });
            }
            // The reorganization events only feed dcrd's background
            // template generator, halting and resuming template
            // generation around the reorg.
            Notification::ChainReorgStarted => {
                if let Some(generator) = &self.generator {
                    generator.chain_reorg_started();
                }
            }
            Notification::ChainReorgDone => {
                if let Some(generator) = &self.generator {
                    generator.chain_reorg_done();
                }
            }
            // The reorganization and new-ticket websocket notifications
            // queue behind the deferred block events they follow in the
            // chain's emission order (dcrd sends NTReorganization after
            // the reorg's disconnects and connects, and NTNewTickets
            // right after its block's NTBlockConnected, all into the
            // one notification queue), so no client sees them ahead of
            // the blockdisconnected/blockconnected frames.  Only queued
            // when the RPC server runs (dcrd's `s.rpcServer != nil`).
            Notification::Reorganization(data) => {
                if self.ntfn.is_some() {
                    self.pending_block_events
                        .lock()
                        .expect("pending block events")
                        .push(PendingBlockEvent::Reorganization {
                            old_hash: data.old_hash,
                            old_height: data.old_height,
                            new_hash: data.new_hash,
                            new_height: data.new_height,
                        });
                }
            }
            Notification::NewTickets(data) => {
                if self.ntfn.is_some() {
                    self.pending_block_events
                        .lock()
                        .expect("pending block events")
                        .push(PendingBlockEvent::NewTickets {
                            hash: data.hash,
                            height: data.height,
                            stake_difficulty: data.stake_difficulty,
                            tickets_new: data.tickets_new.clone(),
                        });
                }
            }
        }
    }

    /// Queue the winning-tickets lookup and the block announcement
    /// for an accepted block (dcrd's NTBlockAccepted case).  The
    /// lottery work requires the RPC server (`s.rpcServer != nil` is
    /// part of dcrd's winning-tickets conditions), so without one
    /// there is no lookup and no broadcast-set growth; the relay to
    /// the peers that were not already notified via the checked
    /// announcement happens regardless.
    fn handle_block_accepted(&self, data: &BlockAcceptedNtfnsData<'_>) {
        if self.ntfn.is_some()
            && should_notify_winning_tickets(
                &self.params,
                &data.block.header,
                data.best_height,
                data.fork_len,
            )
        {
            let block_hash = data.block.header.block_hash();
            let already = self
                .lottery_data_broadcast
                .lock()
                .expect("lottery broadcast set")
                .contains(&block_hash);
            if !already {
                self.pending_winning_tickets
                    .lock()
                    .expect("pending winning tickets")
                    .push((block_hash, i64::from(data.block.header.height)));
            }
        }

        self.pending_accepted_announcements
            .lock()
            .expect("pending accepted announcements")
            .push(data.block.header);
    }

    /// Fan the accepted-block announcements out to every peer that
    /// was not already notified via the checked announcement (the
    /// send at the end of dcrd's NTBlockAccepted case).  dcrd's sync
    /// gate applies: not relayed unless the chain is current or
    /// unsynced mining is allowed.  Runs after the block-event drain
    /// so the connect maintenance's transaction announcements keep
    /// dcrd's wire order.
    pub fn drain_pending_accepted_announcements(
        &self,
        chain: &Arc<Mutex<Chain>>,
        adjusted_time_unix: i64,
    ) {
        let pending: Vec<BlockHeader> = core::mem::take(
            &mut *self
                .pending_accepted_announcements
                .lock()
                .expect("pending accepted announcements"),
        );
        if pending.is_empty() {
            return;
        }
        // dcrd's gate is the sync manager's IsCurrent, which requires
        // the best height to have reached the sync height on top of
        // the chain believing itself current.
        let is_current =
            self.allow_unsynced_mining || self.sync_gate.is_current(chain, adjusted_time_unix);
        if !is_current {
            return;
        }
        // dcrd enables the fee estimator at the height of the first
        // accepted block here — the last statement of the same
        // is-current-gated NTBlockAccepted case, right after
        // `RelayBlockAnnouncement` — so fee estimation only begins once
        // the initial sync has completed and never records mempool
        // transactions at a mid-sync height (dcrd's `if !s.feeEstimator
        // .IsEnabled() { s.feeEstimator.Enable(block.Height()) }`).
        let enable_height = pending.first().map(|header| i64::from(header.height));
        for header in pending {
            self.sync_peers
                .relay_block_announcement(&header, dcroxide_wire::ServiceFlag(0));
        }
        if let (Some(estimator), Some(height)) = (&self.fee_estimator, enable_height) {
            crate::fees::enable_at_height(estimator, height);
        }
    }

    /// Run the queued lottery lookups now that the chain mutex is
    /// free, announcing each block's winning tickets and recording it
    /// in the broadcast set (dcrd's inline `LotteryDataForBlock` +
    /// `NotifyWinningTickets` + `lotteryDataBroadcast` insert).  dcrd
    /// gates the whole accepted case on the sync being current unless
    /// unsynced mining is allowed.
    ///
    /// LOCK ORDER: the mixpool mutex must NEVER be taken while the chain
    /// mutex is held.  The pool reaches back into the chain — the peer
    /// intake path locks the pool (`NodeSyncMixPool::accept_message`) and
    /// the pool's own tip and UTXO lookups then lock the chain
    /// (`NodeMixChain::current_tip`, `NodeMixUtxoFetcher::fetch_utxo_entry`)
    /// — so mixpool-then-chain is the established order and nesting the
    /// refusal check inside the chain guard here would close an AB-BA
    /// cycle that any inbound peer's mix message could trigger.  The
    /// drain therefore runs in three phases: fetch the refusal candidates
    /// under the chain guard, drop it, ask the pool, then re-acquire the
    /// chain guard for the lottery lookups.
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

        // Phase 1 — chain guard held, mixpool untouched: apply dcrd's
        // sync gate and read the blocks the mix refusal needs.  The guard
        // is released at the end of this scope, BEFORE the pool is asked.
        let refusal_blocks: Vec<(Hash, dcroxide_wire::MsgBlock)> = {
            let mut chain = chain.lock().expect("chain mutex poisoned");
            if !self.allow_unsynced_mining
                && !self
                    .sync_gate
                    .is_current_locked(&mut chain, adjusted_time_unix)
            {
                return;
            }
            if self.mix_pool.is_none() {
                Vec::new()
            } else {
                pending
                    .iter()
                    .filter_map(|(block_hash, _)| {
                        chain
                            .block_by_hash(block_hash)
                            .map(|block| (*block_hash, block))
                    })
                    .collect()
            }
        };

        // Phase 2 — no chain guard held: refuse to notify winning tickets
        // for a block spending misbehaving mix inputs (dcrd's
        // `MisbehavingBlock` break in the same gated case), so clients are
        // not prompted to vote on it.  A block the chain could not supply
        // is simply not a refusal candidate, exactly as the missing block
        // short-circuited dcrd's check.
        let refused: HashSet<Hash> = match &self.mix_pool {
            None => HashSet::new(),
            Some(mix_pool) => {
                let mix_pool = mix_pool.lock().expect("mix pool mutex poisoned");
                refusal_blocks
                    .iter()
                    .filter(|(_, block)| mix_pool.misbehaving_block(block))
                    .map(|(block_hash, _)| *block_hash)
                    .collect()
            }
        };
        drop(refusal_blocks);

        // Phase 3 — chain guard re-acquired with the mixpool released:
        // the lottery lookups and their notifications.
        let mut chain = chain.lock().expect("chain mutex poisoned");
        for (block_hash, block_height) in pending {
            if refused.contains(&block_hash) {
                continue;
            }
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
                let mgr = ntfn.clone();
                RpcNtfnManager::notify_winning_tickets(&mgr, &block_hash, block_height, &winners);
            }
            self.lottery_data_broadcast
                .lock()
                .expect("lottery broadcast set")
                .insert(block_hash);
        }
    }
}

impl ChainNtfnHandler {
    /// Run the whole deferred-notification drain as one serialized unit:
    /// the connected/disconnected mempool maintenance with the block,
    /// new-ticket, and reorganization websocket notifications in the
    /// chain's emission order, the accepted-block announcements, then
    /// the queued winning-ticket lookups.  (The early checked-block
    /// announcement is not deferred: the callback relays it.)  This
    /// fixed order preserves the per-client orderings that dcrd's single
    /// notification queue produces — the peer relay order (a checked
    /// announcement before an accepted one) and, within the block-event
    /// drain, txaccepted before blockconnected, blockconnected before
    /// newtickets, and the reorg's block frames before reorganization.
    /// One known ordering still differs from dcrd's, and it spans two
    /// sinks: dcrd sends a block's winning-tickets websocket
    /// notification before its accepted-block peer relay inside the
    /// single NTBlockAccepted case, and no one client observes both.
    /// The background template generator is fed at callback time (see
    /// the BlockConnected arm of `handle`) but runs this drain before it
    /// handles a connected or disconnected block or the end of a
    /// reorganization, so, as in dcrd, it sees the maintained pool and
    /// its work notification follows the blockconnected frame.  The
    /// whole sequence holds the drain lock so its drivers — the netsync
    /// post-process path, the background generator's drain hook, and the
    /// RPC invalidate and reconsider seams (`rpcrun.rs`
    /// `NodeRpcChain::drain_chain_events`) — can never interleave two
    /// runs and split a reorg batch, which would process the maintenance,
    /// announcements, and index notifications out of order (an index fed
    /// out of order fails every update until the heights line up again).
    /// The block events are taken whole for the same reason (see
    /// `ChainNtfnHandler::take_block_events`).
    pub fn drain_pending(&self, chain: &Arc<Mutex<Chain>>, adjusted_time_unix: i64) {
        let _drain = self.drain_lock.lock().expect("drain lock poisoned");
        self.drain_block_events(self.take_block_events(chain));
        self.drain_pending_accepted_announcements(chain, adjusted_time_unix);
        self.drain_pending_winning_tickets(chain, adjusted_time_unix);
    }

    /// Take the queued block events once no processing call is still
    /// queueing them.  The chain callback queues every event under the
    /// chain mutex, so taking the queue under that mutex hands the drain
    /// only whole processing-call batches: a drain run while a
    /// reorganization or `invalidateblock` is still detaching blocks
    /// (the generator's drains after ChainReorgStarted, a vote or a
    /// build) would otherwise take a prefix of the reorganization.  The
    /// drain reads what dcrd's chain still holds at each block from the
    /// rest of the batch ([`DisconnectRun`], [`mined_by_later_connects`]),
    /// because dcrd's handler runs inline as each block is detached or
    /// attached; a prefix would miss the older disconnects and the
    /// connects that follow.  An empty queue is left without the chain
    /// mutex, so the generator's drain after each of its steps stays
    /// cheap.  The caller holds the drain lock, and nothing takes that
    /// lock while holding the chain mutex.
    fn take_block_events(&self, chain: &Arc<Mutex<Chain>>) -> VecDeque<PendingBlockEvent> {
        if self
            .pending_block_events
            .lock()
            .expect("pending block events")
            .is_empty()
        {
            return VecDeque::new();
        }
        let _chain = chain.lock().expect("chain mutex poisoned");
        core::mem::take(
            &mut *self
                .pending_block_events
                .lock()
                .expect("pending block events"),
        )
        .into()
    }

    /// Run the queued mempool maintenance for the connected and
    /// disconnected blocks, in order, now that the chain mutex is
    /// free (dcrd `handleBlockchainNotification`'s NTBlockConnected
    /// and NTBlockDisconnected mempool halves with the fee-estimator
    /// feed, the confirmed-transaction bookkeeping and the rebroadcast
    /// prunes), sending the queued new-ticket and reorganization
    /// notifications at their places in the same sequence (dcrd's
    /// NTNewTickets and NTReorganization cases).  Serialized by
    /// [`ChainNtfnHandler::drain_pending`], which every production
    /// caller runs the whole drain through, and which also waits out a
    /// processing call still queueing; this entry point has no chain to
    /// wait on and takes the queue as it stands.
    pub fn drain_pending_block_events(&self) {
        let pending = core::mem::take(
            &mut *self
                .pending_block_events
                .lock()
                .expect("pending block events"),
        );
        self.drain_block_events(pending.into());
    }

    /// Run the maintenance and notifications for a taken batch of block
    /// events (see [`ChainNtfnHandler::drain_pending_block_events`]).
    fn drain_block_events(&self, mut pending: VecDeque<PendingBlockEvent>) {
        // What dcrd's chain still holds of a run of disconnects while it
        // handles each of them.
        let mut run = DisconnectRun::default();
        while let Some(event) = pending.pop_front() {
            match event {
                // dcrd NTBlockConnected: the connected block's mempool
                // maintenance (which announces any newly acceptable
                // transactions) runs first, then the rebroadcast prune,
                // then the block-connected notification, then the index
                // notify — so a websocket client sees txaccepted before
                // blockconnected.
                PendingBlockEvent::Connected {
                    block,
                    parent,
                    check_tx_flags,
                } => {
                    // What the batch's later connects mined, which dcrd,
                    // with its tip at this block, has not mined yet.
                    let later_mined = std::cell::OnceCell::new();
                    let mined_later = |hash: &Hash| {
                        later_mined
                            .get_or_init(|| mined_by_later_connects(&pending))
                            .contains(hash)
                    };
                    self.handle_connected_block(&block, &parent, check_tx_flags, &mined_later);
                    if let Some(rebroadcast) = &self.rebroadcast {
                        rebroadcast.prune_rebroadcast_inventory();
                    }
                    if let Some(ntfn) = &self.ntfn {
                        ntfn.notify_block_connected(Arc::clone(&block));
                    }
                    self.notify_index_subscriber(
                        dcroxide_indexers::CONNECT_NTFN,
                        block,
                        parent,
                        check_tx_flags,
                    );
                }
                // dcrd NTBlockDisconnected: the disconnect mempool
                // maintenance, then the index notify, then the
                // rebroadcast prune and the block-disconnected
                // notification.
                PendingBlockEvent::Disconnected {
                    block,
                    parent,
                    check_tx_flags,
                } => {
                    run.advance(&block, &parent, &pending);
                    self.handle_disconnected_block(&block, &parent, check_tx_flags, &mut run.txs);
                    self.notify_index_subscriber(
                        dcroxide_indexers::DISCONNECT_NTFN,
                        Arc::clone(&block),
                        parent,
                        check_tx_flags,
                    );
                    if let Some(rebroadcast) = &self.rebroadcast {
                        rebroadcast.prune_rebroadcast_inventory();
                    }
                    if let Some(ntfn) = &self.ntfn {
                        ntfn.notify_block_disconnected(block);
                    }
                }
                // dcrd NTNewTickets: `NotifyNewTickets`, after the
                // block-connected frame of the block that matured them.
                PendingBlockEvent::NewTickets {
                    hash,
                    height,
                    stake_difficulty,
                    tickets_new,
                } => {
                    if let Some(ntfn) = &self.ntfn {
                        ntfn.notify_new_tickets(hash, height, stake_difficulty, tickets_new);
                    }
                }
                // dcrd NTReorganization: `NotifyReorganization`, after
                // every block frame of the reorg.
                PendingBlockEvent::Reorganization {
                    old_hash,
                    old_height,
                    new_hash,
                    new_height,
                } => {
                    if let Some(ntfn) = &self.ntfn {
                        ntfn.notify_reorganization(old_hash, old_height, new_hash, new_height);
                    }
                }
            }
        }
    }

    /// Notify the subscribed indexes for a drained block event (dcrd's
    /// `s.indexSubscriber.Notify` feeding `handleIndexUpdates`).  A
    /// failed update is logged and ends this notification's walk over
    /// the subscriptions, and every later notification is still
    /// processed, exactly as in dcrd: the `s.cancel()` there cancels
    /// only the context the indexes were initialized with, while the
    /// handler loop runs on the server's context and keeps consuming
    /// notifications.  An index that missed an update therefore logs
    /// dcrd's missing-notification error for each later block and
    /// resumes on its own once the heights line up again (a reorg
    /// replacing the failed block).  The subscriber's `cancelled` latch,
    /// dcrd's cancelled context, is deliberately not consulted.
    fn notify_index_subscriber(
        &self,
        ntfn_type: dcroxide_indexers::IndexNtfnType,
        block: Arc<dcroxide_wire::MsgBlock>,
        parent: Arc<dcroxide_wire::MsgBlock>,
        check_tx_flags: AgendaFlags,
    ) {
        let Some(subscriber) = &self.index_subscriber else {
            return;
        };
        let mut subscriber = subscriber.lock().expect("index subscriber mutex poisoned");
        let ntfn = dcroxide_indexers::IndexNtfn {
            ntfn_type,
            block,
            parent,
            is_treasury_enabled: check_tx_flags.is_treasury_enabled(),
        };
        if let Err(e) = subscriber.notify(&ntfn) {
            // dcrd's `log.Error(err)` under the INDX subsystem, once per
            // failed notification.
            crate::logging::error("INDX", &e.to_string());
        }
    }

    /// Per-transaction maintenance over a connected block's
    /// transactions (dcrd `handleConnectedBlockTxns`): drop each from
    /// the pool without touching its now-valid redeemers, unstage
    /// dependents, evict double spends and matching orphans, and
    /// process newly acceptable orphans with the announce cascade.
    /// `mined_later` names the transactions later connects of the same
    /// drained batch mined (`TxPool::process_orphans_accepted_in_batch`).
    fn handle_connected_block(
        &self,
        block: &dcroxide_wire::MsgBlock,
        parent: &dcroxide_wire::MsgBlock,
        check_tx_flags: AgendaFlags,
        mined_later: &dyn Fn(&Hash) -> bool,
    ) {
        // Hash every transaction in the block exactly once up front:
        // the fee-estimator feed and the per-transaction pool
        // maintenance below both key on the hashes, and dcrd pays for
        // them only once via the `dcrutil.Block` hash cache.
        let regular_hashes: Vec<Hash> = block.transactions.iter().map(|tx| tx.tx_hash()).collect();
        let stake_hashes: Vec<Hash> = block.stransactions.iter().map(|tx| tx.tx_hash()).collect();

        // Feed the connected block into the fee estimator before the
        // mempool removal.  dcrd runs `ProcessBlock` first because the
        // mempool removals below alert the estimator, and if they ran
        // first the estimator would see these transactions leave the
        // pool without ever having been mined.
        if let Some(estimator) = &self.fee_estimator {
            crate::fees::process_connected_block(
                estimator,
                i64::from(block.header.height),
                &regular_hashes,
                &stake_hashes,
            );
        }

        // dcrd's handler runs with the tip at this block, so what it
        // admits records this block's height (`TxPool::with_event_height`).
        let event_height = i64::from(block.header.height);
        let is_treasury_enabled = check_tx_flags.is_treasury_enabled();
        let regular = block.transactions.get(1..).unwrap_or(&[]);
        let regular_tail_hashes = regular_hashes.get(1..).unwrap_or(&[]);
        let (stake, stake_tail_hashes) = if is_treasury_enabled {
            (
                block.stransactions.get(1..).unwrap_or(&[]),
                stake_hashes.get(1..).unwrap_or(&[]),
            )
        } else {
            (&block.stransactions[..], &stake_hashes[..])
        };
        for (tx, tx_hash) in regular
            .iter()
            .zip(regular_tail_hashes)
            .chain(stake.iter().zip(stake_tail_hashes))
        {
            // The accepted orphans come back as values (dcrd's
            // `ProcessOrphans` returning the `*dcrutil.Tx` orphans it
            // accepted) and are announced from those, so nothing the
            // pool accepted can go unannounced and the announcement
            // carries the orphan dcrd announces rather than the pool's
            // fraud-proof-updated copy.
            let accepted = self
                .tx_pool
                .lock()
                .expect("tx pool mutex poisoned")
                .with_event_height(event_height, |pool| {
                    pool.remove_transaction(tx, tx_hash, false);
                    pool.maybe_accept_dependents(tx, tx_hash, is_treasury_enabled);
                    pool.remove_double_spends(tx, tx_hash);
                    pool.remove_orphan_pub(tx_hash);
                    pool.process_orphans_accepted_in_batch(tx, tx_hash, check_tx_flags, mined_later)
                });
            self.announce_transactions(accepted);

            // Now that this block is in the blockchain, mark the
            // transaction as no longer needing rebroadcasting and
            // keep track of it for use when avoiding requests for
            // recently confirmed transactions (dcrd
            // `TransactionConfirmed`).
            if let Some(filter) = &self.recently_confirmed {
                filter
                    .lock()
                    .expect("recently confirmed filter poisoned")
                    .add(&tx_hash.0);
            }
            if let Some(rebroadcast) = &self.rebroadcast {
                rebroadcast.remove_rebroadcast_inventory(tx_hash);
            }
        }

        // A block that disapproves its parent returns the parent's
        // regular transactions to contention.
        if !header_approves_parent(&block.header) {
            let resurrect = parent.transactions.get(1..).unwrap_or(&[]);
            let _errs = self
                .tx_pool
                .lock()
                .expect("tx pool mutex poisoned")
                .with_event_height(event_height, |pool| {
                    pool.maybe_accept_transactions(resurrect)
                });
        }
    }

    /// The disconnected-block maintenance (dcrd's NTBlockDisconnected
    /// case): drop the parent's transactions when the disconnected
    /// block disapproved them, then re-admit the disconnected block's
    /// own transactions.  `ancestors` holds the transactions of the
    /// blocks the same run of disconnects detaches next that dcrd's chain
    /// still holds at this one ([`DisconnectRun`]).
    fn handle_disconnected_block(
        &self,
        block: &dcroxide_wire::MsgBlock,
        parent: &dcroxide_wire::MsgBlock,
        check_tx_flags: AgendaFlags,
        ancestors: &mut BTreeMap<[u8; 32], dcroxide_wire::MsgTx>,
    ) {
        // dcrd's handler runs with the tip at the disconnected block's
        // parent, so what it admits records the parent's height
        // (`TxPool::with_event_height`), and the outputs of the blocks
        // still to be detached are chain outputs to it
        // (`TxPool::with_transient`).
        let event_height = i64::from(block.header.height).saturating_sub(1);
        let is_treasury_enabled = check_tx_flags.is_treasury_enabled();
        if !header_approves_parent(&block.header) {
            for tx in parent.transactions.get(1..).unwrap_or(&[]) {
                let tx_hash = tx.tx_hash();
                let mut pool = self.tx_pool.lock().expect("tx pool mutex poisoned");
                pool.with_event_height(event_height, |pool| {
                    pool.with_transient(ancestors, |pool| {
                        pool.remove_transaction(tx, &tx_hash, false);
                        pool.maybe_accept_dependents(tx, &tx_hash, is_treasury_enabled);
                        pool.remove_double_spends(tx, &tx_hash);
                        pool.remove_orphan_pub(&tx_hash);
                        // dcrd discards the orphan acceptances on
                        // disconnect.
                        let _ = pool.process_orphans(tx, &tx_hash, check_tx_flags);
                    })
                });
            }
        }

        // Two separate readmissions, the regular tree first and then the
        // stake tree, as dcrd's `handleDisconnectedBlockTxns` runs them:
        // each call walks its slice in reverse with only its own
        // transactions in the transient map, so merging the trees would
        // readmit every stake transaction (votes included, which move
        // the tip's known-disapproved tally) before any regular one.
        let regular = block.transactions.get(1..).unwrap_or(&[]);
        let _errs = self
            .tx_pool
            .lock()
            .expect("tx pool mutex poisoned")
            .with_event_height(event_height, |pool| {
                pool.with_transient(ancestors, |pool| pool.maybe_accept_transactions(regular))
            });
        let stake = if is_treasury_enabled {
            // Skip the treasurybase.
            block.stransactions.get(1..).unwrap_or(&[])
        } else {
            &block.stransactions[..]
        };
        let _errs = self
            .tx_pool
            .lock()
            .expect("tx pool mutex poisoned")
            .with_event_height(event_height, |pool| {
                pool.with_transient(ancestors, |pool| pool.maybe_accept_transactions(stake))
            });
    }

    /// The announce cascade for transactions the maintenance accepted
    /// (dcrd `AnnounceNewTransactions`): websocket notifications, the
    /// recently-advertised cache, and the peer inventory relay, all
    /// from the accepted values themselves.
    fn announce_transactions(&self, accepted: Vec<(Hash, dcroxide_wire::MsgTx)>) {
        if accepted.is_empty() {
            return;
        }
        let mut pairs = Vec::with_capacity(accepted.len());
        for (hash, tx) in accepted {
            let tree = if dcroxide_stake::determine_tx_type(&tx) == dcroxide_stake::TxType::Regular
            {
                dcroxide_wire::TX_TREE_REGULAR
            } else {
                dcroxide_wire::TX_TREE_STAKE
            };
            let advertised = self
                .sync_peers
                .relay_inventory(&crate::server::RelayInvFacts {
                    inv_type: dcroxide_wire::InvType::TX,
                    inv_hash: hash,
                    req_services: dcroxide_wire::ServiceFlag(0),
                    immediate: false,
                    data_is_block_header: false,
                    data_is_tx: true,
                });
            // Record it as recently advertised only when a peer
            // qualified, matching dcrd's per-peer cache update.
            if advertised {
                self.recently_advertised
                    .lock()
                    .expect("recently advertised poisoned")
                    .put(hash, tx.clone());
            }
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

    /// The tag the chain sink renders under must be one `--debuglevel`
    /// accepts, so `--debuglevel CHAN=off` suppresses these lines the
    /// way dcrd's `subsystemLoggers["CHAN"]` (`log.go:106`) does.
    ///
    /// Without this, a typo compiles, wires cleanly, prints under a tag
    /// nothing recognises, and silently ignores the level setting.
    #[test]
    fn chan_log_subsystem_is_a_registered_tag() {
        assert!(
            crate::logsubsys::SUBSYSTEM_IDS.contains(&CHAN_LOG_SUBSYSTEM),
            "{CHAN_LOG_SUBSYSTEM} is not a --debuglevel subsystem"
        );
        // Compile-checks the closure against `LogCallback`'s `Send +
        // 'static` bound, which would otherwise fail only at the
        // daemon's wiring line in the bin.
        let _sink: LogCallback = chain_log_sink();
    }

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

    /// The announcement drain applies dcrd's sync gate: an accepted
    /// block over a stale chain is not announced unless unsynced
    /// mining is allowed, while the early checked announcement was
    /// already gated at emission and always relays.
    #[test]
    fn the_announcement_drain_applies_dcrds_sync_gate() {
        let params = dcroxide_chaincfg::testnet3_params();
        let dir = tempfile::tempdir().expect("temp dir");
        let opts = dcroxide_database::Options::new(dir.path().join("blocks"), params.net.0);
        let db = dcroxide_database::Database::create(&opts).expect("create database");
        let chain = Arc::new(Mutex::new(
            dcroxide_blockchain::process::Chain::open(db, &params, params.assume_valid, false, 0)
                .expect("open chain"),
        ));
        let tx_pool = crate::txmempool::new_shared_tx_pool(
            Arc::clone(&chain),
            &params,
            false,
            100,
            10000,
            false,
            false,
        );
        let genesis = chain
            .lock()
            .expect("chain")
            .block_by_hash(&params.genesis_hash)
            .expect("genesis block");
        let now = 2_000_000_000i64; // far past the stale genesis tip

        let drive = |allow_unsynced: bool| -> Vec<dcroxide_wire::Message> {
            let peers = crate::dispatch::SyncPeers::new();
            let (queue, rx) = crate::peerloop::OutboundQueue::channel();
            peers.register(
                1,
                queue,
                None,
                Arc::new(Mutex::new(crate::dispatch::RelayPeerState::new(
                    crate::server::RelayPeerFacts {
                        connected: true,
                        services: dcroxide_wire::ServiceFlag::NODE_NETWORK,
                        wants_headers: false,
                        disable_relay_tx: false,
                        protocol_version: dcroxide_wire::PROTOCOL_VERSION,
                    },
                ))),
                Arc::new(Mutex::new(dcroxide_peer::Peer::new_inbound(
                    dcroxide_peer::Config::default(),
                ))),
                None,
                false,
                None,
                None,
                None,
            );
            let handler = ChainNtfnHandler::new(
                None,
                params.clone(),
                allow_unsynced,
                crate::sync::SyncGate::always_current(),
                None,
                Arc::clone(&tx_pool),
                peers,
                crate::dispatch::new_recently_advertised(),
            );
            handler.handle(&Notification::NewTipBlockChecked(&genesis));
            handler.handle(&Notification::BlockAccepted(BlockAcceptedNtfnsData {
                best_height: 0,
                fork_len: 0,
                block: &genesis,
            }));
            handler.drain_pending_accepted_announcements(&chain, now);
            let mut got = Vec::new();
            while let Ok(msg) = rx.try_recv() {
                got.push(msg);
            }
            got
        };

        // Not current and unsynced mining not allowed: only the
        // emission-gated checked announcement relays.
        let gated = drive(false);
        assert_eq!(gated.len(), 1, "checked announcement only: {gated:?}");

        // Unsynced mining allowed: the accepted announcement relays
        // too, deduped per peer by the announced-block toggle — the
        // checked pass announced the same hash, so the accepted pass
        // clears the marker and both passes produce one message.
        let allowed = drive(true);
        assert_eq!(allowed.len(), 1, "toggle dedups the second pass");
    }

    /// The combined `drain_pending` entry point drives the whole
    /// deferred sequence under one lock: with a checked announcement for
    /// a fresh hash (relayed by the callback itself) and an accepted one
    /// for another (queued), a single call leaves both relayed, so the
    /// accepted sub-drain is not skipped (P3-1).
    #[test]
    fn drain_pending_drives_the_whole_sequence() {
        let params = dcroxide_chaincfg::testnet3_params();
        let dir = tempfile::tempdir().expect("temp dir");
        let opts = dcroxide_database::Options::new(dir.path().join("blocks"), params.net.0);
        let db = dcroxide_database::Database::create(&opts).expect("create database");
        let chain = Arc::new(Mutex::new(
            dcroxide_blockchain::process::Chain::open(db, &params, params.assume_valid, false, 0)
                .expect("open chain"),
        ));
        let tx_pool = crate::txmempool::new_shared_tx_pool(
            Arc::clone(&chain),
            &params,
            false,
            100,
            10000,
            false,
            false,
        );
        let genesis = chain
            .lock()
            .expect("chain")
            .block_by_hash(&params.genesis_hash)
            .expect("genesis block");
        // A second header with a different hash so the checked and
        // accepted announcements are not deduped into one message.
        let mut other = genesis.clone();
        other.header.version = 0x5eed;
        let now = 2_000_000_000i64;

        let peers = crate::dispatch::SyncPeers::new();
        let (queue, rx) = crate::peerloop::OutboundQueue::channel();
        peers.register(
            1,
            queue,
            None,
            Arc::new(Mutex::new(crate::dispatch::RelayPeerState::new(
                crate::server::RelayPeerFacts {
                    connected: true,
                    services: dcroxide_wire::ServiceFlag::NODE_NETWORK,
                    wants_headers: false,
                    disable_relay_tx: false,
                    protocol_version: dcroxide_wire::PROTOCOL_VERSION,
                },
            ))),
            Arc::new(Mutex::new(dcroxide_peer::Peer::new_inbound(
                dcroxide_peer::Config::default(),
            ))),
            None,
            false,
            None,
            None,
            None,
        );
        // Unsynced mining allowed so the accepted announcement clears the
        // is-current gate over the stale genesis tip.
        let handler = ChainNtfnHandler::new(
            None,
            params.clone(),
            true,
            crate::sync::SyncGate::always_current(),
            None,
            Arc::clone(&tx_pool),
            peers,
            crate::dispatch::new_recently_advertised(),
        );
        handler.handle(&Notification::NewTipBlockChecked(&genesis));
        handler.handle(&Notification::BlockAccepted(BlockAcceptedNtfnsData {
            best_height: 0,
            fork_len: 0,
            block: &other,
        }));

        // A single combined drain runs the accepted sub-drain: with the
        // callback's checked relay, two distinct announced hashes relay
        // two messages.
        handler.drain_pending(&chain, now);
        let mut got = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            got.push(msg);
        }
        assert_eq!(
            got.len(),
            2,
            "drain_pending relays both the checked and accepted announcements: {got:?}"
        );
    }

    /// The fee estimator's enable rides the same sync gate: dcrd only
    /// runs `Enable(block.Height())` inside the is-current-gated
    /// NTBlockAccepted case, so an accepted block over a stale chain
    /// leaves the estimator disabled unless unsynced mining is allowed.
    #[test]
    fn the_fee_estimator_enable_honors_the_sync_gate() {
        let params = dcroxide_chaincfg::testnet3_params();
        let dir = tempfile::tempdir().expect("temp dir");
        let opts = dcroxide_database::Options::new(dir.path().join("blocks"), params.net.0);
        let db = dcroxide_database::Database::create(&opts).expect("create database");
        let chain = Arc::new(Mutex::new(
            dcroxide_blockchain::process::Chain::open(db, &params, params.assume_valid, false, 0)
                .expect("open chain"),
        ));
        let tx_pool = crate::txmempool::new_shared_tx_pool(
            Arc::clone(&chain),
            &params,
            false,
            100,
            10000,
            false,
            false,
        );
        let genesis = chain
            .lock()
            .expect("chain")
            .block_by_hash(&params.genesis_hash)
            .expect("genesis block");
        let now = 2_000_000_000i64; // far past the stale genesis tip

        let enabled_after_drain = |allow_unsynced: bool| -> bool {
            let estimator = crate::fees::new_shared_estimator(10000).expect("estimator");
            let mut handler = ChainNtfnHandler::new(
                None,
                params.clone(),
                allow_unsynced,
                crate::sync::SyncGate::unsynced(),
                None,
                Arc::clone(&tx_pool),
                crate::dispatch::SyncPeers::new(),
                crate::dispatch::new_recently_advertised(),
            );
            handler.set_fee_estimator(Arc::clone(&estimator));
            handler.handle(&Notification::BlockAccepted(BlockAcceptedNtfnsData {
                best_height: 0,
                fork_len: 0,
                block: &genesis,
            }));
            handler.drain_pending_accepted_announcements(&chain, now);
            estimator.lock().expect("estimator").is_enabled()
        };

        // Stale chain, no unsynced mining: dcrd's gate skips the enable.
        assert!(
            !enabled_after_drain(false),
            "a stale chain leaves the estimator disabled"
        );
        // Unsynced mining forces the gate open: the enable fires.
        assert!(
            enabled_after_drain(true),
            "unsynced mining enables the estimator at the accepted height"
        );
    }

    /// Register one connected full-node peer that relays transactions
    /// and prefers inventory announcements, handing back the receiving
    /// end of its outbound queue.
    fn full_node_peer(peers: &crate::dispatch::SyncPeers) -> crate::peerloop::OutboundReceiver {
        let (queue, rx) = crate::peerloop::OutboundQueue::channel();
        peers.register(
            1,
            queue,
            None,
            Arc::new(Mutex::new(crate::dispatch::RelayPeerState::new(
                crate::server::RelayPeerFacts {
                    connected: true,
                    services: dcroxide_wire::ServiceFlag::NODE_NETWORK,
                    wants_headers: false,
                    disable_relay_tx: false,
                    protocol_version: dcroxide_wire::PROTOCOL_VERSION,
                },
            ))),
            Arc::new(Mutex::new(dcroxide_peer::Peer::new_inbound(
                dcroxide_peer::Config::default(),
            ))),
            None,
            false,
            None,
            None,
            None,
        );
        rx
    }

    /// The early checked-block announcement leaves from the chain
    /// callback itself, before any drain runs, as dcrd's
    /// NTNewTipBlockChecked case relays it with the chain lock held so
    /// the block spreads while the expensive connect runs.  The
    /// accepted-block announcement still waits for the drain.
    ///
    /// Regression for the checked announcement queueing until the
    /// post-processing drain, which runs only after the whole connect
    /// and its commit.
    #[test]
    fn the_checked_announcement_relays_from_the_callback() {
        let params = dcroxide_chaincfg::testnet3_params();
        let dir = tempfile::tempdir().expect("temp dir");
        let opts = dcroxide_database::Options::new(dir.path().join("blocks"), params.net.0);
        let db = dcroxide_database::Database::create(&opts).expect("create database");
        let chain = Arc::new(Mutex::new(
            dcroxide_blockchain::process::Chain::open(db, &params, params.assume_valid, false, 0)
                .expect("open chain"),
        ));
        let tx_pool = crate::txmempool::new_shared_tx_pool(
            Arc::clone(&chain),
            &params,
            false,
            100,
            10000,
            false,
            false,
        );
        let genesis = chain
            .lock()
            .expect("chain")
            .block_by_hash(&params.genesis_hash)
            .expect("genesis block");
        let mut accepted = genesis.clone();
        accepted.header.version = 0x5eed;

        let peers = crate::dispatch::SyncPeers::new();
        let rx = full_node_peer(&peers);
        let handler = ChainNtfnHandler::new(
            None,
            params.clone(),
            true,
            crate::sync::SyncGate::always_current(),
            None,
            Arc::clone(&tx_pool),
            peers,
            crate::dispatch::new_recently_advertised(),
        );

        handler.handle(&Notification::NewTipBlockChecked(&genesis));
        match rx.try_recv() {
            Ok(dcroxide_wire::Message::Inv(inv)) => {
                assert_eq!(inv.inv_list.len(), 1);
                assert_eq!(inv.inv_list[0].hash, genesis.header.block_hash());
            }
            other => panic!("the checked announcement must relay from the callback: {other:?}"),
        }

        handler.handle(&Notification::BlockAccepted(BlockAcceptedNtfnsData {
            best_height: 0,
            fork_len: 0,
            block: &accepted,
        }));
        assert!(
            rx.try_recv().is_err(),
            "the accepted announcement waits for the drain"
        );
        handler.drain_pending(&chain, 2_000_000_000);
        match rx.try_recv() {
            Ok(dcroxide_wire::Message::Inv(inv)) => {
                assert_eq!(inv.inv_list[0].hash, accepted.header.block_hash());
            }
            other => panic!("the drain relays the accepted announcement: {other:?}"),
        }
    }

    /// A failed index update does not stop index maintenance.  dcrd's
    /// `handleIndexUpdates` logs the error and goes on to the next
    /// notification (its `s.cancel()` touches only the context the
    /// indexes were initialized with), so an update that skips a height
    /// fails with the missing-notification error and the next
    /// notification whose height lines up with the index tip is still
    /// applied.
    ///
    /// Regression for the handler skipping every notification once the
    /// subscriber had latched its cancelled flag.
    #[test]
    fn a_failed_index_update_leaves_later_updates_running() {
        use dcroxide_blockchain::notifications::BlockConnectedNtfnsData;
        use dcroxide_indexers::{ChainQueryer, ExistsAddrIndex, IndexSubscriber, Indexer};

        let params = dcroxide_chaincfg::simnet_params();
        let dir = tempfile::tempdir().expect("temp dir");
        let opts = dcroxide_database::Options::new(dir.path().join("blocks"), params.net.0);
        let db = dcroxide_database::Database::create(&opts).expect("create database");
        let chain = Arc::new(Mutex::new(
            dcroxide_blockchain::process::Chain::open(
                db.clone(),
                &params,
                params.assume_valid,
                false,
                0,
            )
            .expect("open chain"),
        ));
        let queryer = Arc::new(crate::indexes::NodeChainQueryer::new(
            Arc::clone(&chain),
            params.clone(),
        ));
        let mut subscriber = IndexSubscriber::new(dcroxide_indexers::Interrupt::default(), None);
        let index = ExistsAddrIndex::new(
            &mut subscriber,
            Arc::new(db),
            queryer as Arc<dyn ChainQueryer>,
        )
        .expect("exists address index");
        let subscriber = Arc::new(Mutex::new(subscriber));

        let tx_pool = crate::txmempool::new_shared_tx_pool(
            Arc::clone(&chain),
            &params,
            false,
            100,
            10000,
            false,
            false,
        );
        let mut handler = ChainNtfnHandler::new(
            None,
            params.clone(),
            false,
            crate::sync::SyncGate::always_current(),
            None,
            tx_pool,
            crate::dispatch::SyncPeers::new(),
            crate::dispatch::new_recently_advertised(),
        );
        handler.set_index_subscriber(Arc::clone(&subscriber));

        let genesis = Arc::new(params.genesis_block.clone());
        let at_height = |height: u32| {
            let mut block = params.genesis_block.clone();
            block.header.height = height;
            Arc::new(block)
        };
        let connect = |block: Arc<dcroxide_wire::MsgBlock>| {
            handler.handle(&Notification::BlockConnected(BlockConnectedNtfnsData {
                block,
                parent_block: Arc::clone(&genesis),
                check_tx_flags: AgendaFlags::default(),
            }));
            handler.drain_pending_block_events();
        };
        let tip = || index.lock().expect("index").tip().expect("index tip").0;
        assert_eq!(tip(), 0, "the fresh index sits at genesis");

        // Height 2 skips height 1: the update fails and the subscriber
        // latches dcrd's cancelled context.
        connect(at_height(2));
        assert_eq!(tip(), 0, "the out-of-order update is refused");
        assert!(
            subscriber.lock().expect("subscriber").cancelled(),
            "the failure cancels the subscriber's context"
        );

        // The next notification lines up with the index tip again and is
        // applied, as dcrd's handler loop applies it.
        connect(at_height(1));
        assert_eq!(
            tip(),
            1,
            "index maintenance carries on after a failed update"
        );
    }

    /// The first linear main-chain blocks of dcrd's full-block battery
    /// (fully signed regnet blocks) up to and including the first one
    /// the predicate accepts, with the battery's generation time.
    fn battery_prefix_through(
        mut stop: impl FnMut(&dcroxide_wire::MsgBlock) -> bool,
    ) -> (i64, Vec<dcroxide_wire::MsgBlock>) {
        let params = dcroxide_chaincfg::regnet_params();
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../dcroxide-blockchain/tests/data/fullblock_vectors.txt"
        );
        let data = std::fs::read_to_string(path).expect("fullblock vectors");
        let mut now: i64 = 0;
        let mut tip = params.genesis_hash;
        let mut blocks = Vec::new();
        for line in data.lines() {
            let f: Vec<&str> = line.split(' ').collect();
            match f[0] {
                "now" => now = f[1].parse().expect("generation time"),
                // accept <name> <mainchain> <orphan> <blockhex>
                "accept" => {
                    let (block, _) =
                        dcroxide_wire::MsgBlock::from_bytes(&dcroxide_testutil::unhex(f[4]))
                            .expect("block");
                    if f[2] != "true" || block.header.prev_block != tip {
                        continue;
                    }
                    tip = block.header.block_hash();
                    let done = stop(&block);
                    blocks.push(block);
                    if done {
                        return (now, blocks);
                    }
                }
                _ => {}
            }
        }
        panic!("the battery's main chain never satisfied the predicate");
    }

    /// A regnet chain with the given battery blocks processed.
    fn battery_chain(
        blocks: &[dcroxide_wire::MsgBlock],
        now: i64,
    ) -> (tempfile::TempDir, Arc<Mutex<Chain>>) {
        let params = dcroxide_chaincfg::regnet_params();
        let dir = tempfile::tempdir().expect("temp dir");
        let opts = dcroxide_database::Options::new(dir.path().join("blocks"), params.net.0);
        let db = dcroxide_database::Database::create(&opts).expect("create database");
        let mut chain =
            Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain");
        for block in blocks {
            let (_, errs) = chain.process_block(block, now, &params);
            assert!(errs.is_empty(), "battery block must accept: {errs:?}");
        }
        (dir, Arc::new(Mutex::new(chain)))
    }

    /// Driven by a real chain, the checked announcement is on the peer's
    /// queue by the time the chain emits it — inside the processing
    /// call, with the chain mutex held and the block not yet connected —
    /// exactly where dcrd's NTNewTipBlockChecked case relays it.  Relaying
    /// under the chain mutex neither deadlocks nor waits for the connect.
    #[test]
    fn the_checked_announcement_leaves_before_the_connect() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let params = dcroxide_chaincfg::regnet_params();
        let (now, blocks) = battery_prefix_through(|block| block.header.height >= 4);
        let (next, history) = blocks.split_last().expect("battery blocks");
        let (_dir, chain) = battery_chain(history, now);
        let tx_pool = crate::txmempool::new_shared_tx_pool(
            Arc::clone(&chain),
            &params,
            false,
            100,
            10000,
            false,
            false,
        );
        let peers = crate::dispatch::SyncPeers::new();
        let rx = full_node_peer(&peers);
        let handler = ChainNtfnHandler::new(
            None,
            params.clone(),
            true,
            crate::sync::SyncGate::always_current(),
            None,
            tx_pool,
            peers,
            crate::dispatch::new_recently_advertised(),
        );

        // Whether the announcement was queued when the chain emitted it,
        // and whether the block had been connected by then.
        let checked_emitted = Arc::new(AtomicBool::new(false));
        let queued_at_emission = Arc::new(AtomicBool::new(false));
        let connected_first = Arc::new(AtomicBool::new(false));
        {
            let (checked_emitted, queued_at_emission, connected_first) = (
                Arc::clone(&checked_emitted),
                Arc::clone(&queued_at_emission),
                Arc::clone(&connected_first),
            );
            let expected = next.header.block_hash();
            let callback = handler.clone();
            chain
                .lock()
                .expect("chain")
                .set_notification_callback(Box::new(move |n| {
                    callback.handle(n);
                    match n {
                        Notification::NewTipBlockChecked(_) => {
                            checked_emitted.store(true, Ordering::SeqCst);
                            let queued = matches!(
                                rx.try_recv(),
                                Ok(dcroxide_wire::Message::Inv(inv)) if inv.inv_list[0].hash == expected
                            );
                            queued_at_emission.store(queued, Ordering::SeqCst);
                        }
                        Notification::BlockConnected(_) if !checked_emitted.load(Ordering::SeqCst) => {
                            connected_first.store(true, Ordering::SeqCst);
                        }
                        _ => {}
                    }
                }));
        }
        let (_, errs) = chain
            .lock()
            .expect("chain")
            .process_block(next, now, &params);
        assert!(errs.is_empty(), "the next battery block accepts: {errs:?}");

        assert!(
            checked_emitted.load(Ordering::SeqCst),
            "the current battery chain emits the early checked event"
        );
        assert!(
            !connected_first.load(Ordering::SeqCst),
            "the chain emits the checked event before connecting the block"
        );
        assert!(
            queued_at_emission.load(Ordering::SeqCst),
            "the announcement is queued before the processing call returns"
        );
    }

    /// The battery's pay-to-script-hash output over a lone `OP_TRUE`,
    /// which anyone can spend with [`OP_TRUE_SIG_SCRIPT`].
    fn op_true_p2sh() -> Vec<u8> {
        let mut script = vec![0xa9, 0x14]; // OP_HASH160 OP_DATA_20
        script.extend_from_slice(&dcroxide_txscript::stdaddr::hash160(&[0x51]));
        script.push(0x87); // OP_EQUAL
        script
    }

    /// The signature script pushing the `OP_TRUE` redeem script.
    const OP_TRUE_SIG_SCRIPT: [u8; 2] = [0x01, 0x51];

    /// A transaction spending the given pay-to-`OP_TRUE` output back to
    /// the same script, less a fee, with the given input fraud proof.
    fn spend_op_true(
        previous_out_point: dcroxide_wire::OutPoint,
        value: i64,
        value_in: i64,
    ) -> dcroxide_wire::MsgTx {
        dcroxide_wire::MsgTx {
            tx_in: vec![dcroxide_wire::TxIn {
                previous_out_point,
                sequence: u32::MAX,
                value_in,
                block_height: 0,
                block_index: 0,
                signature_script: OP_TRUE_SIG_SCRIPT.to_vec(),
            }],
            tx_out: vec![dcroxide_wire::TxOut {
                value: value
                    .checked_sub(100_000)
                    .expect("the output covers the fee"),
                version: 0,
                pk_script: op_true_p2sh(),
            }],
            ..dcroxide_wire::MsgTx::default()
        }
    }

    /// The orphans a connected block releases are announced as the
    /// values the pool accepted — dcrd's `ProcessOrphans` hands
    /// `AnnounceNewTransactions` the orphan objects themselves — rather
    /// than looked up in the pool again: the relayed copy is the orphan
    /// as it arrived, while the pool keeps its fraud-proof-updated copy.
    ///
    /// Regression for the hash-only orphan processing whose announce
    /// cascade re-fetched each transaction from the pool.
    #[test]
    fn connected_block_orphans_announce_the_accepted_values() {
        let params = dcroxide_chaincfg::regnet_params();
        // Stop at the first battery block carrying a regular transaction
        // besides its coinbase that pays to OP_TRUE.
        let (now, blocks) = battery_prefix_through(|block| {
            block
                .transactions
                .get(1..)
                .unwrap_or(&[])
                .iter()
                .any(|tx| tx.tx_out.iter().any(|out| out.pk_script == op_true_p2sh()))
        });
        let (confirming, history) = blocks.split_last().expect("battery blocks");
        let (_dir, chain) = battery_chain(history, now);

        let parent = confirming.transactions[1..]
            .iter()
            .find(|tx| tx.tx_out.iter().any(|out| out.pk_script == op_true_p2sh()))
            .expect("parent transaction");
        let (index, parent_out) = parent
            .tx_out
            .iter()
            .enumerate()
            .find(|(_, out)| out.pk_script == op_true_p2sh())
            .expect("pay-to-OP_TRUE output");
        let orphan = spend_op_true(
            dcroxide_wire::OutPoint {
                hash: parent.tx_hash(),
                index: u32::try_from(index).expect("output index"),
                tree: dcroxide_wire::TX_TREE_REGULAR,
            },
            parent_out.value,
            0,
        );
        let orphan_hash = orphan.tx_hash();

        let tx_pool = crate::txmempool::new_shared_tx_pool(
            Arc::clone(&chain),
            &params,
            true,
            100,
            10000,
            false,
            false,
        );
        {
            let mut pool = tx_pool.lock().expect("tx pool");
            let accepted = pool
                .process_transaction(&orphan, true, true, 0)
                .expect("the orphan is admitted");
            assert!(accepted.is_empty(), "the parent is not confirmed yet");
            assert!(pool.is_orphan_in_pool(&orphan_hash));
        }

        let peers = crate::dispatch::SyncPeers::new();
        let _rx = full_node_peer(&peers);
        let recently_advertised = crate::dispatch::new_recently_advertised();
        let handler = ChainNtfnHandler::new(
            None,
            params.clone(),
            true,
            crate::sync::SyncGate::always_current(),
            None,
            Arc::clone(&tx_pool),
            peers,
            Arc::clone(&recently_advertised),
        );
        {
            let mut chain = chain.lock().expect("chain");
            let callback = handler.clone();
            chain.set_notification_callback(Box::new(move |n| callback.handle(n)));
            let (_, errs) = chain.process_block(confirming, now, &params);
            assert!(
                errs.is_empty(),
                "the confirming block must accept: {errs:?}"
            );
        }
        handler.drain_pending_block_events();

        let pooled = tx_pool
            .lock()
            .expect("tx pool")
            .fetch_transaction(&orphan_hash)
            .expect("the confirmed parent releases the orphan");
        assert_eq!(
            pooled.tx_in[0].value_in, parent_out.value,
            "the pool filled in its own copy's fraud proof"
        );
        let announced = recently_advertised
            .lock()
            .expect("recently advertised")
            .peek(&orphan_hash)
            .expect("the released orphan is announced");
        assert_eq!(
            announced.tx_in[0].value_in, 0,
            "the announcement carries the orphan as accepted, as dcrd's does"
        );
    }

    /// A mature, unspent pay-to-OP_TRUE coinbase output of the given
    /// battery chain, with its value.
    fn mature_op_true_output(
        chain: &Arc<Mutex<Chain>>,
        blocks: &[dcroxide_wire::MsgBlock],
        params: &Params,
    ) -> (dcroxide_wire::OutPoint, i64) {
        let chain = chain.lock().expect("chain");
        let next_height = chain.best_snapshot().height.saturating_add(1);
        blocks
            .iter()
            .filter(|block| {
                next_height.saturating_sub(i64::from(block.header.height))
                    >= i64::from(params.coinbase_maturity)
            })
            .flat_map(|block| {
                let coinbase = &block.transactions[0];
                let hash = coinbase.tx_hash();
                coinbase.tx_out.iter().enumerate().map(move |(index, out)| {
                    (
                        dcroxide_wire::OutPoint {
                            hash,
                            index: u32::try_from(index).expect("output index"),
                            tree: dcroxide_wire::TX_TREE_REGULAR,
                        },
                        out.clone(),
                    )
                })
            })
            .find(|(outpoint, out)| {
                out.pk_script == op_true_p2sh()
                    && chain
                        .fetch_utxo_entry(outpoint)
                        .is_some_and(|entry| !entry.is_spent())
            })
            .map(|(outpoint, out)| (outpoint, out.value))
            .expect("a mature unspent coinbase output")
    }

    /// A disconnected block's transactions are readmitted in dcrd's two
    /// passes, the regular tree first and then the stake tree, each with
    /// only its own transactions in the transient map.  A regular
    /// transaction spending a stake-tree transaction of the same block
    /// therefore finds its parent missing and is dropped, where one
    /// readmission over both trees would readmit the stake transaction
    /// first and keep the regular one.
    ///
    /// Regression for the merged readmission, which reversed dcrd's
    /// regular-then-stake order.
    #[test]
    fn disconnect_readmits_the_regular_tree_before_the_stake_tree() {
        use dcroxide_blockchain::notifications::BlockDisconnectedNtfnsData;

        let params = dcroxide_chaincfg::regnet_params();
        let (now, blocks) = battery_prefix_through(|block| block.header.height >= 24);
        let (_dir, chain) = battery_chain(&blocks, now);

        let (outpoint, value) = mature_op_true_output(&chain, &blocks, &params);
        let stake_side = spend_op_true(outpoint, value, value);
        let regular_side = spend_op_true(
            dcroxide_wire::OutPoint {
                hash: stake_side.tx_hash(),
                index: 0,
                tree: dcroxide_wire::TX_TREE_REGULAR,
            },
            stake_side.tx_out[0].value,
            stake_side.tx_out[0].value,
        );

        // The disconnected block: its header approves the parent, so only
        // the readmission runs, over the regular transaction and the
        // stake-tree transaction it spends.
        let parent = blocks.last().expect("tip").clone();
        let mut disconnected = parent.clone();
        disconnected.header.vote_bits = 1;
        disconnected.transactions = vec![parent.transactions[0].clone(), regular_side.clone()];
        disconnected.stransactions = vec![stake_side.clone()];

        let tx_pool = crate::txmempool::new_shared_tx_pool(
            Arc::clone(&chain),
            &params,
            true,
            100,
            10000,
            false,
            false,
        );
        let handler = ChainNtfnHandler::new(
            None,
            params.clone(),
            true,
            crate::sync::SyncGate::always_current(),
            None,
            Arc::clone(&tx_pool),
            crate::dispatch::SyncPeers::new(),
            crate::dispatch::new_recently_advertised(),
        );
        handler.handle(&Notification::BlockDisconnected(
            BlockDisconnectedNtfnsData {
                block: Arc::new(disconnected),
                parent_block: Arc::new(parent),
                check_tx_flags: AgendaFlags::default(),
            },
        ));
        handler.drain_pending_block_events();

        let pool = tx_pool.lock().expect("tx pool");
        assert!(
            pool.is_transaction_in_pool(&stake_side.tx_hash()),
            "the stake-tree transaction is readmitted"
        );
        assert!(
            !pool.is_transaction_in_pool(&regular_side.tx_hash()),
            "the regular tree is readmitted first, before its stake-tree parent is back"
        );
    }

    /// GAP01#2: dcrd readmits a disconnected block's transactions with
    /// the tip at that block's parent, so their descriptors record the
    /// parent's height, which `getrawmempool` reports and the stake
    /// prunes key on.  The drain runs with the tip already final and used
    /// to record that height instead.
    #[test]
    fn disconnect_readmission_records_the_parent_height() {
        use dcroxide_blockchain::notifications::BlockDisconnectedNtfnsData;

        let params = dcroxide_chaincfg::regnet_params();
        let (now, blocks) = battery_prefix_through(|block| block.header.height >= 24);
        let (_dir, chain) = battery_chain(&blocks, now);
        let tip_height = chain.lock().expect("chain").best_snapshot().height;

        let (outpoint, value) = mature_op_true_output(&chain, &blocks, &params);
        let readmitted = spend_op_true(outpoint, value, value);

        // A disconnected block at the tip's height whose header approves
        // its parent, so only the readmission runs; the chain stays at
        // the tip, as it would at the end of a one-block reorg.
        let parent = blocks.last().expect("tip").clone();
        let mut disconnected = parent.clone();
        disconnected.header.vote_bits = 1;
        disconnected.transactions = vec![parent.transactions[0].clone(), readmitted.clone()];
        disconnected.stransactions = Vec::new();
        assert_eq!(i64::from(disconnected.header.height), tip_height);

        let tx_pool = crate::txmempool::new_shared_tx_pool(
            Arc::clone(&chain),
            &params,
            true,
            100,
            10000,
            false,
            false,
        );
        let handler = ChainNtfnHandler::new(
            None,
            params.clone(),
            true,
            crate::sync::SyncGate::always_current(),
            None,
            Arc::clone(&tx_pool),
            crate::dispatch::SyncPeers::new(),
            crate::dispatch::new_recently_advertised(),
        );
        handler.handle(&Notification::BlockDisconnected(
            BlockDisconnectedNtfnsData {
                block: Arc::new(disconnected),
                parent_block: Arc::new(parent),
                check_tx_flags: AgendaFlags::default(),
            },
        ));
        handler.drain_pending_block_events();

        let pool = tx_pool.lock().expect("tx pool");
        let hash = readmitted.tx_hash();
        let desc = pool
            .tx_descs()
            .into_iter()
            .find(|desc| desc.tx_hash == hash)
            .expect("the transaction is readmitted");
        assert_eq!(
            desc.height,
            tip_height.saturating_sub(1),
            "the readmission records the disconnected block's parent height"
        );
    }

    /// How the chain tells the generator about the change whose
    /// maintenance is still queued, in
    /// [`assert_the_template_follows_the_maintenance`].
    #[derive(Clone, Copy)]
    enum TipChange {
        /// The tip is connected (the generator's BlockConnected).
        Connected,
        /// A child of the tip is disconnected (BlockDisconnected).
        Disconnected,
        /// A reorganization ends at the tip (ChainReorgStarted, then
        /// ChainReorgDone).
        ReorgDone,
    }

    /// Where the chain's side of
    /// [`assert_the_template_follows_the_maintenance`] has got to.
    enum ScriptStep {
        /// Waiting for the startup template to be installed.
        Startup {
            /// Whether a drain has run under the startup build's hold.
            built: bool,
        },
        /// ChainReorgStarted is sent; the next drain ends the reorg.
        Reorganizing,
        /// Everything is sent.
        Done,
    }

    /// GAP01#4: dcrd's handler updates the pool for a block before it
    /// hands the block to the background template generator
    /// (`s.bg.BlockConnected` and `s.bg.BlockDisconnected` follow the pool
    /// updates in `server.go`), and the chain sends ChainReorgDone only
    /// after the handler has run for every block of the reorganization,
    /// so the template built for the new tip reflects that maintenance.
    /// The generator is fed at callback time, ahead of the deferred
    /// drain, and used to build from the pool first and drain afterwards.
    ///
    /// Here a disconnect's readmission is still queued when the generator
    /// hears of `change`, with the tip below stake validation height, so
    /// it builds at once; the first template built afterwards must carry
    /// the readmitted transaction.  The chain's side is played from the
    /// generator's drain hook, at the drain right before the generator
    /// waits for its next command (the one after the startup build, and
    /// for a reorganization the one after ChainReorgStarted), so no other
    /// drain can take the readmission before the generator handles the
    /// change.
    fn assert_the_template_follows_the_maintenance(change: TipChange) {
        use crate::bgtemplate::{GeneratorSink, SharedTemplate};
        use dcroxide_blockchain::notifications::BlockDisconnectedNtfnsData;
        use dcroxide_rpc::server::RpcBlockTemplater;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        let params = dcroxide_chaincfg::regnet_params();
        let (now, blocks) = battery_prefix_through(|block| block.header.height >= 24);
        let (_dir, chain) = battery_chain(&blocks, now);
        let (outpoint, value) = mature_op_true_output(&chain, &blocks, &params);
        let readmitted = spend_op_true(outpoint, value, value);
        let tip = blocks.last().expect("tip").clone();
        assert!(
            i64::from(tip.header.height).saturating_add(1) < params.stake_validation_height,
            "the new tip builds without waiting for votes"
        );
        let disconnected = {
            let mut disconnected = tip.clone();
            disconnected.header.vote_bits = 1;
            disconnected.transactions = vec![tip.transactions[0].clone(), readmitted.clone()];
            disconnected.stransactions = Vec::new();
            disconnected
        };
        // A child of the tip, which the generator builds on the tip for.
        let child = {
            let mut child = tip.clone();
            child.header.height = tip.header.height.saturating_add(1);
            child.header.prev_block = tip.header.block_hash();
            child
        };

        // The generator's drain hook runs the handler's deferred
        // maintenance, as the daemon wires it, and then plays the chain.
        let tx_pool = crate::txmempool::new_shared_tx_pool(
            Arc::clone(&chain),
            &params,
            true,
            100,
            10000,
            false,
            false,
        );
        let handler = maintenance_handler(&params, &tx_pool);
        let drain_handler = handler.clone();
        let drain_chain = Arc::clone(&chain);
        let (setup_tx, setup_rx) = mpsc::channel::<(GeneratorSink, Arc<Mutex<SharedTemplate>>)>();
        let (go_tx, go_rx) = mpsc::channel::<()>();
        let reorg_hold_seen = Arc::new(AtomicBool::new(false));
        let hook_reorg_hold_seen = Arc::clone(&reorg_hold_seen);
        let script = Mutex::new((
            setup_rx,
            go_rx,
            None::<(GeneratorSink, Arc<Mutex<SharedTemplate>>)>,
            ScriptStep::Startup { built: false },
        ));
        let hook = move || {
            drain_handler.drain_pending(&drain_chain, now);
            let mut script = script.lock().expect("script");
            let (setup_rx, go_rx, handles, step) = &mut *script;
            let (sink, current) =
                handles.get_or_insert_with(|| setup_rx.recv().expect("generator handles"));
            let stale = current.lock().expect("shared template").is_stale();
            // The chain's callback: queue the maintenance, then (in the
            // daemon, still under the chain mutex) nothing drains it
            // before the generator hears of the change.
            let queue_readmission = || {
                drain_handler.handle(&Notification::BlockDisconnected(
                    BlockDisconnectedNtfnsData {
                        block: Arc::new(disconnected.clone()),
                        parent_block: Arc::new(tip.clone()),
                        check_tx_flags: AgendaFlags::default(),
                    },
                ));
            };
            match step {
                ScriptStep::Startup { built } => {
                    if stale {
                        *built = true;
                        return;
                    }
                    if !*built {
                        return;
                    }
                    // The startup template is installed and this is the
                    // generator's last drain before it waits.
                    go_rx.recv().expect("go");
                    match change {
                        TipChange::Connected => {
                            queue_readmission();
                            sink.block_connected(Arc::new(tip.clone()));
                            *step = ScriptStep::Done;
                        }
                        TipChange::Disconnected => {
                            queue_readmission();
                            sink.block_disconnected(Arc::new(child.clone()));
                            *step = ScriptStep::Done;
                        }
                        TipChange::ReorgDone => {
                            sink.chain_reorg_started();
                            *step = ScriptStep::Reorganizing;
                        }
                    }
                }
                ScriptStep::Reorganizing => {
                    // The drain after ChainReorgStarted, which holds
                    // template retrieval, and the last before the
                    // generator waits again.
                    hook_reorg_hold_seen.store(stale, Ordering::SeqCst);
                    queue_readmission();
                    sink.chain_reorg_done();
                    *step = ScriptStep::Done;
                }
                ScriptStep::Done => {}
            }
        };

        let policy = dcroxide_mining::MiningPolicy {
            block_max_size: params.maximum_block_sizes[0] as u32,
            tx_min_free_fee: 10000,
            aggressive_mining: true,
        };
        let mining_addr = dcroxide_txscript::stdaddr::decode_address(
            "RsKrWb7Vny1jnzL1sDLgKTAteh9RZcRr5g6",
            &params,
        )
        .expect("mining address");
        let generator = crate::bgtemplate::start_generator(
            Arc::clone(&chain),
            Arc::clone(&tx_pool),
            params.clone(),
            vec![mining_addr],
            policy.clone(),
            0,
            true,
            crate::sync::SyncGate::always_current(),
            None,
            Some(Box::new(hook)),
        );
        setup_tx
            .send((generator.sink(), generator.current_handle()))
            .expect("the drain hook waits for the generator handles");
        let templater = crate::bgtemplate::NodeRpcBlockTemplater::new(
            generator.current_handle(),
            generator.subscribers_handle(),
            generator.sink(),
            Arc::clone(&chain),
            Arc::clone(&tx_pool),
            params.clone(),
            policy,
            0,
        );
        let template_other_than = |skip: Option<Hash>| {
            let started = Instant::now();
            loop {
                if let Ok(Some(block)) = templater.current_template()
                    && Some(block.header.block_hash()) != skip
                {
                    return block;
                }
                assert!(
                    started.elapsed() < Duration::from_secs(20),
                    "no new template"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        };
        // The hook holds the generator at its last startup drain until
        // the startup template is read.
        let startup = template_other_than(None).header.block_hash();
        go_tx
            .send(())
            .expect("the drain hook waits to play the chain");

        let built = template_other_than(Some(startup));
        assert!(
            tx_pool
                .lock()
                .expect("tx pool")
                .is_transaction_in_pool(&readmitted.tx_hash()),
            "the queued maintenance readmitted the transaction"
        );
        if matches!(change, TipChange::ReorgDone) {
            assert!(
                reorg_hold_seen.load(Ordering::SeqCst),
                "the reorganization's end was sent from the drain after its start"
            );
        }
        assert!(
            built
                .transactions
                .iter()
                .any(|tx| tx.tx_hash() == readmitted.tx_hash()),
            "the template for the new tip is built from the maintained pool"
        );
        generator.shutdown();
    }

    /// GAP01#4, for a connected tip (see
    /// [`assert_the_template_follows_the_maintenance`]).
    #[test]
    fn the_generator_builds_on_a_connected_block_after_its_maintenance() {
        assert_the_template_follows_the_maintenance(TipChange::Connected);
    }

    /// GAP01#4, for a disconnected block (see
    /// [`assert_the_template_follows_the_maintenance`]).
    #[test]
    fn the_generator_builds_on_a_disconnected_block_after_its_maintenance() {
        assert_the_template_follows_the_maintenance(TipChange::Disconnected);
    }

    /// GAP01#4, for the end of a reorganization whose blocks' maintenance
    /// is still queued: the trigger the review confirmed, where a sync or
    /// RPC reorganization ends at a tip that needs no more votes (see
    /// [`assert_the_template_follows_the_maintenance`]).
    #[test]
    fn the_generator_builds_after_a_reorganizations_maintenance() {
        assert_the_template_follows_the_maintenance(TipChange::ReorgDone);
    }

    /// A handler over the given pool with no relay or notification
    /// sinks, for driving the block-event drain by hand.
    fn maintenance_handler(
        params: &Params,
        tx_pool: &Arc<Mutex<crate::txmempool::NodeTxPool>>,
    ) -> ChainNtfnHandler {
        ChainNtfnHandler::new(
            None,
            params.clone(),
            true,
            crate::sync::SyncGate::always_current(),
            None,
            Arc::clone(tx_pool),
            crate::dispatch::SyncPeers::new(),
            crate::dispatch::new_recently_advertised(),
        )
    }

    /// A block with the given header fields and transactions, for the
    /// run bookkeeping, which reads nothing else.
    fn run_block(
        height: u32,
        vote_bits: u16,
        prev_block: Hash,
        tag: u32,
    ) -> dcroxide_wire::MsgBlock {
        let tx = |n: u32| dcroxide_wire::MsgTx {
            lock_time: tag.saturating_mul(10).saturating_add(n),
            ..dcroxide_wire::MsgTx::default()
        };
        let mut block = dcroxide_wire::MsgBlock {
            header: header(height, 1),
            transactions: vec![tx(0), tx(1)],
            stransactions: vec![tx(2)],
        };
        block.header.vote_bits = vote_bits;
        block.header.prev_block = prev_block;
        block
    }

    /// GAP01#1: while dcrd handles each disconnect of a run, its chain
    /// still holds the blocks the run detaches next: all of the
    /// disconnected block's parent, which is the tip, and of each older
    /// block the stake tree and, unless its child disapproved it, the
    /// regular tree.  The run hands exactly those to the readmission.
    #[test]
    fn a_disconnect_run_holds_what_dcrds_chain_still_holds() {
        let hashes = |block: &dcroxide_wire::MsgBlock, regular: bool| -> Vec<[u8; 32]> {
            let tree = if regular {
                &block.transactions
            } else {
                &block.stransactions
            };
            tree.iter().map(|tx| tx.tx_hash().0).collect()
        };
        let held = |run: &DisconnectRun| -> std::collections::BTreeSet<[u8; 32]> {
            run.txs.keys().copied().collect()
        };
        let expect = |parts: &[(&dcroxide_wire::MsgBlock, bool)]| {
            parts
                .iter()
                .flat_map(|(block, regular)| hashes(block, *regular))
                .collect::<std::collections::BTreeSet<_>>()
        };

        // Oldest first: d1 disapproves d2, every other block approves its
        // parent.
        let fork = run_block(10, 1, Hash([9; 32]), 9);
        let d3 = run_block(11, 1, fork.header.block_hash(), 3);
        let d2 = run_block(12, 1, d3.header.block_hash(), 2);
        let d1 = run_block(13, 0, d2.header.block_hash(), 1);
        let d0 = run_block(14, 1, d1.header.block_hash(), 0);
        let disconnect = |block: &dcroxide_wire::MsgBlock, parent: &dcroxide_wire::MsgBlock| {
            PendingBlockEvent::Disconnected {
                block: Arc::new(block.clone()),
                parent: Arc::new(parent.clone()),
                check_tx_flags: AgendaFlags::default(),
            }
        };
        let mut queue: VecDeque<PendingBlockEvent> = VecDeque::from(vec![
            disconnect(&d0, &d1),
            disconnect(&d1, &d2),
            disconnect(&d2, &d3),
            disconnect(&d3, &fork),
            // A lone disconnect that does not continue the run.
            disconnect(&d0, &d1),
            PendingBlockEvent::Connected {
                block: Arc::new(d0.clone()),
                parent: Arc::new(d1.clone()),
                check_tx_flags: AgendaFlags::default(),
            },
        ]);
        let mut run = DisconnectRun::default();
        let mut step = |run: &mut DisconnectRun| {
            let Some(PendingBlockEvent::Disconnected { block, parent, .. }) = queue.pop_front()
            else {
                panic!("a disconnect");
            };
            run.advance(&block, &parent, &queue);
        };

        // At d0 the tip is d1: all of d1, d2's stake tree only (d1
        // disapproved its regular tree), all of d3.
        step(&mut run);
        assert_eq!(
            held(&run),
            expect(&[
                (&d1, true),
                (&d1, false),
                (&d2, false),
                (&d3, true),
                (&d3, false)
            ])
        );
        // At d1 the tip is d2, whose regular tree is live again.
        step(&mut run);
        assert_eq!(
            held(&run),
            expect(&[(&d2, true), (&d2, false), (&d3, true), (&d3, false)])
        );
        // At d2 the tip is d3.
        step(&mut run);
        assert_eq!(held(&run), expect(&[(&d3, true), (&d3, false)]));
        // At d3 the tip is the fork block, which the chain still holds.
        step(&mut run);
        assert!(held(&run).is_empty());
        // A disconnect followed by a connect starts a run of one.
        step(&mut run);
        assert!(held(&run).is_empty());
    }

    /// GAP01#1: when the connect queued right after a run builds on the
    /// fork block and disapproves it, the drain's chain lacks the fork
    /// block's regular tree, which dcrd's chain holds while it handles
    /// the run: at the last disconnect, where the fork block is the tip,
    /// and at earlier ones when its child in the run approves it.
    #[test]
    fn a_disconnect_run_holds_a_fork_block_the_next_connect_disapproves() {
        let fork = run_block(10, 1, Hash([9; 32]), 9);
        let regular = |block: &dcroxide_wire::MsgBlock| -> std::collections::BTreeSet<[u8; 32]> {
            block.transactions.iter().map(|tx| tx.tx_hash().0).collect()
        };
        let all = |block: &dcroxide_wire::MsgBlock| -> std::collections::BTreeSet<[u8; 32]> {
            block
                .transactions
                .iter()
                .chain(&block.stransactions)
                .map(|tx| tx.tx_hash().0)
                .collect()
        };
        let union = |a: std::collections::BTreeSet<[u8; 32]>,
                     b: std::collections::BTreeSet<[u8; 32]>| {
            a.union(&b)
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
        };
        let disconnect = |block: &dcroxide_wire::MsgBlock, parent: &dcroxide_wire::MsgBlock| {
            PendingBlockEvent::Disconnected {
                block: Arc::new(block.clone()),
                parent: Arc::new(parent.clone()),
                check_tx_flags: AgendaFlags::default(),
            }
        };
        let connect = |vote_bits: u16, prev_block: Hash| PendingBlockEvent::Connected {
            block: Arc::new(run_block(11, vote_bits, prev_block, 5)),
            parent: Arc::new(fork.clone()),
            check_tx_flags: AgendaFlags::default(),
        };
        // Drive the queue's disconnects, returning what the run holds at
        // each.
        let drive = |events: Vec<PendingBlockEvent>| {
            let mut queue = VecDeque::from(events);
            let mut run = DisconnectRun::default();
            let mut steps = Vec::new();
            while let Some(PendingBlockEvent::Disconnected { block, parent, .. }) =
                queue.pop_front()
            {
                run.advance(&block, &parent, &queue);
                steps.push(
                    run.txs
                        .keys()
                        .copied()
                        .collect::<std::collections::BTreeSet<_>>(),
                );
            }
            steps
        };
        let fork_hash = fork.header.block_hash();

        // A run of one: the fork block is the tip, so its regular tree is
        // held when the connect disapproves it, and not otherwise.
        let b1 = run_block(11, 1, fork_hash, 1);
        assert_eq!(
            drive(vec![disconnect(&b1, &fork), connect(0, fork_hash)]),
            vec![regular(&fork)]
        );
        assert_eq!(
            drive(vec![disconnect(&b1, &fork), connect(1, fork_hash)]),
            vec![Default::default()]
        );
        // A connect that disapproves another block is not the fork's.
        assert_eq!(
            drive(vec![disconnect(&b1, &fork), connect(0, Hash([3; 32]))]),
            vec![Default::default()]
        );

        // A run of two whose older block approves the fork block: held at
        // both disconnects.
        let b2 = run_block(12, 1, b1.header.block_hash(), 2);
        assert_eq!(
            drive(vec![
                disconnect(&b2, &b1),
                disconnect(&b1, &fork),
                connect(0, fork_hash)
            ]),
            vec![union(all(&b1), regular(&fork)), regular(&fork)]
        );

        // One whose older block disapproves it: held only once the fork
        // block is the tip.
        let b1_disapproving = run_block(11, 0, fork_hash, 1);
        let b2 = run_block(12, 1, b1_disapproving.header.block_hash(), 2);
        assert_eq!(
            drive(vec![
                disconnect(&b2, &b1_disapproving),
                disconnect(&b1_disapproving, &fork),
                connect(0, fork_hash)
            ]),
            vec![all(&b1_disapproving), regular(&fork)]
        );
    }

    /// GAP01#1: a reorganization or `invalidateblock` that detaches two
    /// blocks readmits the newer block's transactions while dcrd's chain
    /// still holds the older one, so a transaction spending one mined a
    /// block earlier is readmitted with it.  The drain runs with both
    /// blocks already detached and used to drop that child: its parent
    /// was in neither the chain nor the pool yet.
    #[test]
    fn a_multi_block_disconnect_readmits_children_of_older_blocks() {
        use dcroxide_blockchain::notifications::BlockDisconnectedNtfnsData;

        let params = dcroxide_chaincfg::regnet_params();
        let (now, blocks) = battery_prefix_through(|block| block.header.height >= 24);
        let (_dir, chain) = battery_chain(&blocks, now);

        let (outpoint, value) = mature_op_true_output(&chain, &blocks, &params);
        let parent_tx = spend_op_true(outpoint, value, value);
        let child_tx = spend_op_true(
            dcroxide_wire::OutPoint {
                hash: parent_tx.tx_hash(),
                index: 0,
                tree: dcroxide_wire::TX_TREE_REGULAR,
            },
            parent_tx.tx_out[0].value,
            parent_tx.tx_out[0].value,
        );

        // The two detached blocks, newest first: the child in the newer
        // one, its parent in the older one.  Both approve their parents,
        // so only the readmissions run.
        let [.., grandparent, older_src, newer_src] = &blocks[..] else {
            panic!("three battery blocks");
        };
        let mut older = older_src.clone();
        older.header.vote_bits = 1;
        older.transactions = vec![older_src.transactions[0].clone(), parent_tx.clone()];
        older.stransactions = Vec::new();
        let mut newer = newer_src.clone();
        newer.header.vote_bits = 1;
        newer.header.prev_block = older.header.block_hash();
        newer.transactions = vec![newer_src.transactions[0].clone(), child_tx.clone()];
        newer.stransactions = Vec::new();

        let tx_pool = crate::txmempool::new_shared_tx_pool(
            Arc::clone(&chain),
            &params,
            true,
            100,
            10000,
            false,
            false,
        );
        let handler = maintenance_handler(&params, &tx_pool);
        for (block, parent) in [(&newer, &older), (&older, grandparent)] {
            handler.handle(&Notification::BlockDisconnected(
                BlockDisconnectedNtfnsData {
                    block: Arc::new(block.clone()),
                    parent_block: Arc::new(parent.clone()),
                    check_tx_flags: AgendaFlags::default(),
                },
            ));
        }
        handler.drain_pending_block_events();

        let pool = tx_pool.lock().expect("tx pool");
        let height_of = |hash: Hash| {
            pool.tx_descs()
                .into_iter()
                .find(|desc| desc.tx_hash == hash)
                .map(|desc| desc.height)
        };
        assert_eq!(
            height_of(child_tx.tx_hash()),
            Some(i64::from(older.header.height)),
            "the child is readmitted at the newer block's parent"
        );
        assert_eq!(
            height_of(parent_tx.tx_hash()),
            Some(i64::from(grandparent.header.height)),
            "the parent is readmitted at the older block's parent"
        );
        assert!(pool.orphan_hashes().is_empty(), "nothing is left an orphan");
    }

    /// A drain that runs while a processing call is still queueing its
    /// batch (the generator drains after ChainReorgStarted, a vote or a
    /// build without first waiting on the chain) takes the batch whole:
    /// the callback queues under the chain mutex, and the drain takes the
    /// queue under it.  Taking the prefix a reorganization had queued so
    /// far handed the newer block's readmission no older disconnect, so
    /// the child of a transaction the older block mined was dropped (the
    /// pair `a_multi_block_disconnect_readmits_children_of_older_blocks`
    /// drains in one piece).
    #[test]
    fn a_drain_takes_a_batch_still_being_queued_whole() {
        use dcroxide_blockchain::notifications::BlockDisconnectedNtfnsData;
        use std::time::{Duration, Instant};

        // How long the processing call waits for the drain to take what
        // it has queued so far.  The drain must not while the call holds
        // the chain mutex; overshooting only costs wall time, and a
        // machine too loaded to schedule the drain within it lets the
        // test pass without checking anything rather than fail.
        const HANDOFF: Duration = Duration::from_millis(300);

        let params = dcroxide_chaincfg::regnet_params();
        let (now, blocks) = battery_prefix_through(|block| block.header.height >= 24);
        let (_dir, chain) = battery_chain(&blocks, now);

        let (outpoint, value) = mature_op_true_output(&chain, &blocks, &params);
        let parent_tx = spend_op_true(outpoint, value, value);
        let child_tx = spend_op_true(
            dcroxide_wire::OutPoint {
                hash: parent_tx.tx_hash(),
                index: 0,
                tree: dcroxide_wire::TX_TREE_REGULAR,
            },
            parent_tx.tx_out[0].value,
            parent_tx.tx_out[0].value,
        );
        let [.., grandparent, older_src, newer_src] = &blocks[..] else {
            panic!("three battery blocks");
        };
        let mut older = older_src.clone();
        older.header.vote_bits = 1;
        older.transactions = vec![older_src.transactions[0].clone(), parent_tx.clone()];
        older.stransactions = Vec::new();
        let mut newer = newer_src.clone();
        newer.header.vote_bits = 1;
        newer.header.prev_block = older.header.block_hash();
        newer.transactions = vec![newer_src.transactions[0].clone(), child_tx.clone()];
        newer.stransactions = Vec::new();

        let tx_pool = crate::txmempool::new_shared_tx_pool(
            Arc::clone(&chain),
            &params,
            true,
            100,
            10000,
            false,
            false,
        );
        let handler = maintenance_handler(&params, &tx_pool);
        let queue = |block: &dcroxide_wire::MsgBlock, parent: &dcroxide_wire::MsgBlock| {
            handler.handle(&Notification::BlockDisconnected(
                BlockDisconnectedNtfnsData {
                    block: Arc::new(block.clone()),
                    parent_block: Arc::new(parent.clone()),
                    check_tx_flags: AgendaFlags::default(),
                },
            ));
        };

        // The processing call holds the chain mutex while it detaches
        // the newer block and then the older one.
        let processing = chain.lock().expect("chain");
        queue(&newer, &older);
        let drain = {
            let handler = handler.clone();
            let chain = Arc::clone(&chain);
            std::thread::spawn(move || handler.drain_pending(&chain, now))
        };
        let started = Instant::now();
        while handler.drain_lock.try_lock().is_ok() {
            assert!(
                started.elapsed() < Duration::from_secs(20),
                "the drain never started"
            );
            std::thread::yield_now();
        }
        let handoff = Instant::now();
        while handoff.elapsed() < HANDOFF
            && !handler
                .pending_block_events
                .lock()
                .expect("pending block events")
                .is_empty()
        {
            std::thread::yield_now();
        }
        queue(&older, grandparent);
        drop(processing);
        drain.join().expect("the drain thread");
        // The processing call's own post-process drain.
        handler.drain_pending(&chain, now);

        let pool = tx_pool.lock().expect("tx pool");
        assert!(
            pool.is_transaction_in_pool(&child_tx.tx_hash()),
            "the child is readmitted while the older block is still held"
        );
        assert!(
            pool.is_transaction_in_pool(&parent_tx.tx_hash()),
            "the parent is readmitted"
        );
    }

    /// GAP01#1: a reorganization whose first new block disapproves the
    /// fork block readmits the detached block's transactions while
    /// dcrd's tip is still the fork block, whose regular tree its chain
    /// then holds, so a child of one of its transactions is readmitted;
    /// the new block then returns the parent to the pool.  The drain runs
    /// against a chain without that tree and used to drop the child.
    #[test]
    fn a_reorg_disapproving_the_fork_block_readmits_its_childrens_spends() {
        use dcroxide_blockchain::notifications::{
            BlockConnectedNtfnsData, BlockDisconnectedNtfnsData,
        };

        let params = dcroxide_chaincfg::regnet_params();
        let (now, blocks) = battery_prefix_through(|block| block.header.height >= 24);
        let (_dir, chain) = battery_chain(&blocks, now);

        let (outpoint, value) = mature_op_true_output(&chain, &blocks, &params);
        let parent_tx = spend_op_true(outpoint, value, value);
        let child_tx = spend_op_true(
            dcroxide_wire::OutPoint {
                hash: parent_tx.tx_hash(),
                index: 0,
                tree: dcroxide_wire::TX_TREE_REGULAR,
            },
            parent_tx.tx_out[0].value,
            parent_tx.tx_out[0].value,
        );

        // The fork block mines the parent, which the chain the drain runs
        // against does not hold, as a disapproved regular tree.  The
        // detached block, which approves it, mines the child, and the new
        // block disapproves it.
        let [.., fork_src, detached_src] = &blocks[..] else {
            panic!("two battery blocks");
        };
        let mut fork = fork_src.clone();
        fork.transactions = vec![fork_src.transactions[0].clone(), parent_tx.clone()];
        fork.stransactions = Vec::new();
        let mut detached = detached_src.clone();
        detached.header.vote_bits = 1;
        detached.header.prev_block = fork.header.block_hash();
        detached.transactions = vec![detached_src.transactions[0].clone(), child_tx.clone()];
        detached.stransactions = Vec::new();
        let mut connected = detached.clone();
        connected.header.vote_bits = 0;
        connected.header.nonce = connected.header.nonce.wrapping_add(1);
        connected.transactions = vec![detached_src.transactions[0].clone()];

        let tx_pool = crate::txmempool::new_shared_tx_pool(
            Arc::clone(&chain),
            &params,
            true,
            100,
            10000,
            false,
            false,
        );
        let handler = maintenance_handler(&params, &tx_pool);
        handler.handle(&Notification::BlockDisconnected(
            BlockDisconnectedNtfnsData {
                block: Arc::new(detached),
                parent_block: Arc::new(fork.clone()),
                check_tx_flags: AgendaFlags::default(),
            },
        ));
        handler.handle(&Notification::BlockConnected(BlockConnectedNtfnsData {
            block: Arc::new(connected),
            parent_block: Arc::new(fork),
            check_tx_flags: AgendaFlags::default(),
        }));
        handler.drain_pending_block_events();

        let pool = tx_pool.lock().expect("tx pool");
        assert!(
            pool.is_transaction_in_pool(&child_tx.tx_hash()),
            "the child is readmitted at the fork block"
        );
        assert!(
            pool.is_transaction_in_pool(&parent_tx.tx_hash()),
            "the new block returns the parent to the pool"
        );
    }

    /// GAP01#3: the drain treats as mined later exactly what a connect
    /// queued after the one being handled mined, in either tree, and
    /// nothing a queued disconnect carries.
    #[test]
    fn mined_later_names_what_a_later_connect_mined() {
        let tip = run_block(20, 1, Hash([7; 32]), 1);
        let next = run_block(21, 1, tip.header.block_hash(), 2);
        let detached = run_block(22, 1, next.header.block_hash(), 3);
        let later: VecDeque<PendingBlockEvent> = VecDeque::from(vec![
            PendingBlockEvent::Disconnected {
                block: Arc::new(detached.clone()),
                parent: Arc::new(next.clone()),
                check_tx_flags: AgendaFlags::default(),
            },
            PendingBlockEvent::Connected {
                block: Arc::new(next.clone()),
                parent: Arc::new(tip.clone()),
                check_tx_flags: AgendaFlags::default(),
            },
        ]);
        let mined = mined_by_later_connects(&later);
        let expected: HashSet<Hash> = next
            .transactions
            .iter()
            .chain(&next.stransactions)
            .map(dcroxide_wire::MsgTx::tx_hash)
            .collect();
        assert_eq!(mined, expected, "exactly the later connect's transactions");
        for tx in detached
            .transactions
            .iter()
            .chain(&detached.stransactions)
            .chain(&tip.transactions)
        {
            assert!(!mined.contains(&tx.tx_hash()));
        }
        assert!(mined_by_later_connects(&VecDeque::new()).is_empty());
    }
}
