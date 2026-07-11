// SPDX-License-Identifier: ISC
//! The sync manager (dcrd internal/netsync `manager.go`).

// Counter and height arithmetic mirrors Go.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::{BTreeMap, HashMap, VecDeque};

use dcroxide_chainhash::Hash;
use dcroxide_containers::{apbf, lru};
use dcroxide_peer::{MAX_KNOWN_INVENTORY, MAX_KNOWN_INVENTORY_TTL};
use dcroxide_uint256::Uint256;
use dcroxide_wire::{
    BlockHeader, BlockLocator, CurrencyNet, INIT_STATE_HEAD_BLOCK_VOTES, INIT_STATE_HEAD_BLOCKS,
    INIT_STATE_TSPENDS, INIT_STATE_VERSION, InvType, InvVect, MAX_BLOCK_HEADERS_PER_MSG,
    MAX_INV_PER_MSG, Message, MsgBlock, MsgGetData, MsgGetHeaders, MsgGetInitState, MsgHeaders,
    MsgInv, MsgNotFound, MsgTx, ServiceFlag,
};

/// The minimum number of blocks that should be in the request queue
/// before requesting more (dcrd `minInFlightBlocks`).
pub const MIN_IN_FLIGHT_BLOCKS: usize = 10;

/// The maximum number of blocks to allow in the sync peer request
/// queue (dcrd `maxInFlightBlocks`).
pub const MAX_IN_FLIGHT_BLOCKS: usize = 16;

/// The maximum number of recently rejected transactions to track
/// (dcrd `maxRejectedTxns`).
pub const MAX_REJECTED_TXNS: u32 = 62500;

/// The false positive rate for the rejected transactions APBF (dcrd
/// `rejectedTxnsFPRate`).
pub const REJECTED_TXNS_FP_RATE: f64 = 0.0000001;

/// The maximum number of recently rejected mixing messages to track
/// (dcrd `maxRejectedMixMsgs`).
pub const MAX_REJECTED_MIX_MSGS: u32 = MAX_REJECTED_TXNS;

/// The false positive rate for the rejected mixing messages APBF
/// (dcrd `rejectedMixMsgsFPRate`).
pub const REJECTED_MIX_MSGS_FP_RATE: f64 = REJECTED_TXNS_FP_RATE;

/// The maximum number of requested block hashes to store in memory
/// (dcrd `maxRequestedBlocks`).
pub const MAX_REQUESTED_BLOCKS: usize = MAX_INV_PER_MSG as usize;

/// The maximum number of requested transaction hashes to store in
/// memory (dcrd `maxRequestedTxns`).
pub const MAX_REQUESTED_TXNS: usize = MAX_INV_PER_MSG as usize;

/// The maximum number of hashes of in-flight mixing messages (dcrd
/// `maxRequestedMixMsgs`).
pub const MAX_REQUESTED_MIX_MSGS: usize = MAX_INV_PER_MSG as usize;

/// The maximum number of headers in a single message that is expected
/// when determining when the message appears to be announcing new
/// blocks (dcrd `maxExpectedHeaderAnnouncementsPerMsg`).
pub const MAX_EXPECTED_HEADER_ANNOUNCEMENTS_PER_MSG: usize = 12;

/// The maximum number of consecutive header messages that contain
/// headers which do not connect a peer can send before it is deemed
/// to have diverged so far it is no longer useful (dcrd
/// `maxConsecutiveOrphanHeaders`).
pub const MAX_CONSECUTIVE_ORPHAN_HEADERS: i64 = 10;

/// The number of seconds to wait for progress during the header sync
/// process before stalling the sync and disconnecting the peer (dcrd
/// `headerSyncStallTimeoutSecs`).
pub const HEADER_SYNC_STALL_TIMEOUT_SECS: u64 = (3 + MAX_BLOCK_HEADERS_PER_MSG / 1000) * 2;

/// The size of the lookahead buffer for the next needed blocks (the
/// length of dcrd's `nextBlocksBuf` backing array).
pub const NEXT_BLOCKS_BUF_SIZE: usize = 512;

/// The number of blocks from the sync height within which the final
/// header of a headers message causes the initial header sync to be
/// considered complete (dcrd `syncHeightFetchOffset`).
const SYNC_HEIGHT_FETCH_OFFSET: i64 = 6;

/// An external effect decided by the manager: a message for the
/// daemon to queue to a peer, a peer to disconnect, or a change to
/// the header sync progress stall timer (dcrd queues messages and
/// disconnects peers directly and owns a `time.Timer`).
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)] // Message mirrors dcrd's queued values.
pub enum Action {
    /// Queue the message to the peer (dcrd `peer.QueueMessage`).
    QueueMessage {
        /// The unique id of the peer to send to.
        peer: i32,
        /// The message to send.
        message: Message,
    },
    /// Disconnect the peer (dcrd `peer.Disconnect`).
    Disconnect {
        /// The unique id of the peer to disconnect.
        peer: i32,
    },
    /// (Re)arm the header sync progress stall timer for
    /// [`HEADER_SYNC_STALL_TIMEOUT_SECS`] (dcrd
    /// `headerSyncState.ResetStallTimeout`).
    ResetHeaderSyncStallTimeout,
    /// Prevent the header sync progress stall timer from firing (dcrd
    /// `headerSyncState.StopStallTimeout`).
    StopHeaderSyncStallTimeout,
}

/// The best chain snapshot fields the manager consumes (a subset of
/// dcrd's `blockchain.BestState`).
#[derive(Debug, Clone)]
pub struct BestSnapshot {
    /// The hash of the best block.
    pub hash: Hash,
    /// The height of the best block.
    pub height: i64,
    /// The next stake difficulty.
    pub next_stake_diff: i64,
}

/// A block processing failure (the error from dcrd
/// `blockchain.ProcessBlock` with the classification the manager
/// needs).
#[derive(Debug, Clone)]
pub struct ProcessBlockFailure {
    /// Whether the failure is dcrd `blockchain.ErrDuplicateBlock`.
    pub is_duplicate_block: bool,
    /// The error text (log only).
    pub message: String,
}

/// The chain operations the manager performs (the used surface of
/// dcrd's `*blockchain.BlockChain` config field).
pub trait SyncChain {
    /// The hash and height of the current best known header (dcrd
    /// `BestHeader`).
    fn best_header(&mut self) -> (Hash, i64);
    /// The header with the given hash regardless of chain (dcrd
    /// `HeaderByHash`; `None` stands for the error return).
    fn header_by_hash(&mut self, hash: &Hash) -> Option<BlockHeader>;
    /// A block locator for the block with the given hash (dcrd
    /// `BlockLocatorFromHash`).
    fn block_locator_from_hash(&mut self, hash: &Hash) -> Vec<Hash>;
    /// Up to `max_results` hashes of the next blocks needed to make
    /// progress towards the best known header (dcrd
    /// `PutNextNeededBlocks`).
    fn put_next_needed_blocks(&mut self, max_results: usize) -> Vec<Hash>;
    /// The best chain snapshot (dcrd `BestSnapshot`).
    fn best_snapshot(&mut self) -> BestSnapshot;
    /// Whether the chain believes it is current (dcrd `IsCurrent`).
    fn is_current(&mut self) -> bool;
    /// Potentially flip the chain's is-current latch (dcrd
    /// `MaybeUpdateIsCurrent`).
    fn maybe_update_is_current(&mut self);
    /// The cumulative work of the block with the given hash (dcrd
    /// `ChainWork`; `None` stands for the error return).
    fn chain_work(&mut self, hash: &Hash) -> Option<Uint256>;
    /// Whether the header is known to the chain (dcrd `HaveHeader`).
    fn have_header(&mut self, hash: &Hash) -> bool;
    /// Whether the block data is available (dcrd `HaveBlock`).
    fn have_block(&mut self, hash: &Hash) -> bool;
    /// Process the header (dcrd `ProcessBlockHeader`; the error text
    /// only feeds logs).
    fn process_block_header(&mut self, header: &BlockHeader) -> Result<(), String>;
    /// Process the block, returning the fork length on success (dcrd
    /// `ProcessBlock`).
    fn process_block(&mut self, block: &MsgBlock) -> Result<i64, ProcessBlockFailure>;
}

/// The transaction pool operations the manager performs (the used
/// surface of dcrd's `*mempool.TxPool` config field).
pub trait SyncTxPool {
    /// Validate and potentially accept the transaction along with any
    /// orphans it redeems, returning the accepted transaction hashes
    /// (dcrd `ProcessTransaction`; the error text only feeds logs and
    /// the rejected filter decision).
    fn process_transaction(
        &mut self,
        tx: &MsgTx,
        allow_orphan: bool,
        allow_high_fees: bool,
        tag: u64,
    ) -> Result<Vec<Hash>, String>;
    /// Whether the pool already has the transaction, main or orphan
    /// (dcrd `HaveTransaction`).
    fn have_transaction(&mut self, hash: &Hash) -> bool;
    /// Prune stake transactions below the difficulty or height gates
    /// (dcrd `PruneStakeTx`).
    fn prune_stake_tx(&mut self, required_stake_difficulty: i64, height: i64);
    /// Prune expired transactions (dcrd `PruneExpiredTx`).
    fn prune_expired_tx(&mut self, height: i64);
}

/// The mixing pool operations the manager performs (the used surface
/// of dcrd's `*mixpool.Pool` config field).
pub trait SyncMixPool {
    /// The mixing message type.
    type Msg;
    /// The mixing message hash (dcrd `mixing.Message.Hash`).
    fn mix_hash(&mut self, msg: &Self::Msg) -> Hash;
    /// Validate and potentially accept the message along with any
    /// orphans it satisfies (dcrd `AcceptMessage`; the error text only
    /// feeds logs and is returned to the caller).
    fn accept_message(&mut self, msg: &Self::Msg, source: u64) -> Result<Vec<Self::Msg>, String>;
    /// Whether the message is currently or was recently in the pool
    /// (dcrd `RecentMessage` presence).
    fn recent_message(&mut self, hash: &Hash) -> bool;
    /// Remove pair requests spent by the given transactions (dcrd
    /// `RemoveSpentPRs`).
    fn remove_spent_prs(&mut self, txs: &[MsgTx]);
    /// Expire messages by height (dcrd `ExpireMessagesInBackground`).
    fn expire_messages_in_background(&mut self, height: u32);
}

/// A peer as the manager tracks it: the netsync-specific state from
/// dcrd's `netsync.Peer` plus the facts and small state machines the
/// manager reads from the embedded `peer.Peer` (id, direction,
/// services, protocol version, last known block, the known inventory
/// cache, and the getheaders duplicate filter).  The daemon keeps
/// these in step with its real peers.
pub struct Peer {
    id: i32,
    inbound: bool,
    protocol_version: u32,
    connected: bool,
    last_block: i64,
    /// Whether the peer is capable of serving data (dcrd
    /// `servesData`); set at creation from the services.
    serves_data: bool,
    request_initial_state_done: bool,
    num_consecutive_orphan_headers: i64,
    announced_orphan_block: Option<Hash>,
    best_announced_block: Option<Hash>,
    best_announced_work: Option<Uint256>,
    known_inventory: lru::Set<InvVect>,
    prev_get_hdrs_begin: Option<Hash>,
    prev_get_hdrs_stop: Option<Hash>,
}

impl Peer {
    /// A new peer wrapping the provided facts (dcrd `NewPeer`).
    pub fn new(
        id: i32,
        inbound: bool,
        services: ServiceFlag,
        protocol_version: u32,
        last_block: i64,
    ) -> Peer {
        let serves_data = services.0 & ServiceFlag::NODE_NETWORK.0 == ServiceFlag::NODE_NETWORK.0;
        Peer {
            id,
            inbound,
            protocol_version,
            connected: true,
            last_block,
            serves_data,
            request_initial_state_done: false,
            num_consecutive_orphan_headers: 0,
            announced_orphan_block: None,
            best_announced_block: None,
            best_announced_work: None,
            known_inventory: lru::Set::new_with_default_ttl(
                MAX_KNOWN_INVENTORY,
                MAX_KNOWN_INVENTORY_TTL,
            ),
            prev_get_hdrs_begin: None,
            prev_get_hdrs_stop: None,
        }
    }

    /// The peer's unique id.
    pub fn id(&self) -> i32 {
        self.id
    }

    /// Whether the manager still considers the peer connected (dcrd
    /// `peer.Connected`; flips false once the manager decides to
    /// disconnect it).
    pub fn connected(&self) -> bool {
        self.connected
    }

    /// The latest block height the peer is known to have.
    pub fn last_block(&self) -> i64 {
        self.last_block
    }

    /// The hash of the most recently announced block that did not
    /// connect to any known headers at announcement time.
    pub fn announced_orphan_block(&self) -> Option<&Hash> {
        self.announced_orphan_block.as_ref()
    }

    /// The hash of the block with the most cumulative proof of work
    /// the peer has announced that is known to the local chain.
    pub fn best_announced_block(&self) -> Option<&Hash> {
        self.best_announced_block.as_ref()
    }

    /// The consecutive count of header messages that did not connect.
    pub fn num_consecutive_orphan_headers(&self) -> i64 {
        self.num_consecutive_orphan_headers
    }

    /// Mark the peer's known inventory (dcrd
    /// `peer.AddKnownInventory`).
    pub fn add_known_inventory(&mut self, inv_vect: InvVect) {
        self.known_inventory.put(inv_vect);
    }

    /// Whether the inventory is known to the peer (dcrd
    /// `peer.IsKnownInventory`).
    pub fn is_known_inventory(&mut self, inv_vect: &InvVect) -> bool {
        self.known_inventory.contains(inv_vect)
    }

    /// Update the last known block height when it is greater (dcrd
    /// `peer.UpdateLastBlockHeight`).
    pub fn update_last_block_height(&mut self, new_height: i64) {
        if new_height <= self.last_block {
            return;
        }
        self.last_block = new_height;
    }

    /// The getheaders push with dcrd `peer.PushGetHeadersMsg`'s
    /// duplicate-request filter: the message is suppressed when both
    /// the begin and stop hashes match the previous request.
    fn push_get_headers_msg(&mut self, locator: Vec<Hash>, stop_hash: &Hash) -> Option<Message> {
        let begin_hash = locator.first().copied();

        // Filter duplicate getheaders requests.
        if let (Some(prev_stop), Some(prev_begin), Some(begin)) = (
            &self.prev_get_hdrs_stop,
            &self.prev_get_hdrs_begin,
            &begin_hash,
        ) && stop_hash == prev_stop
            && begin == prev_begin
        {
            return None;
        }

        // Construct the getheaders request.  Note that dcrd's
        // NewMsgGetHeaders leaves the locator protocol version zero.
        let msg = Message::GetHeaders(MsgGetHeaders(BlockLocator {
            protocol_version: 0,
            block_locator_hashes: locator,
            hash_stop: *stop_hash,
        }));

        // Update the previous getheaders request information for
        // filtering duplicates.
        self.prev_get_hdrs_begin = begin_hash;
        self.prev_get_hdrs_stop = Some(*stop_hash);
        Some(msg)
    }

    /// The initial state request message, at most once per peer and
    /// only while connected (dcrd `maybeRequestInitialState`).
    fn maybe_request_initial_state(&mut self, include_mining_state: bool) -> Option<Message> {
        // Don't request the initial state more than once or when the
        // peer is in the process of being removed.
        if !self.connected {
            return None;
        }
        if self.request_initial_state_done {
            return None;
        }
        self.request_initial_state_done = true;

        // Choose which initial state sync p2p messages to use based on
        // the protocol version.
        //
        // Protocol versions prior to the init state version use
        // getminingstate and miningstate while those after use
        // getinitstate and initstate.
        if self.protocol_version < INIT_STATE_VERSION {
            if include_mining_state {
                return Some(Message::GetMiningState);
            }
            return None;
        }

        // Always request treasury spends for newer protocol versions.
        let mut types = Vec::with_capacity(3);
        types.push(INIT_STATE_TSPENDS.to_string());
        if include_mining_state {
            types.push(INIT_STATE_HEAD_BLOCKS.to_string());
            types.push(INIT_STATE_HEAD_BLOCK_VOTES.to_string());
        }
        Some(Message::GetInitState(MsgGetInitState { types }))
    }
}

/// The configuration options for the sync manager (dcrd `Config`;
/// the chain parameter fields the manager consumes are copied out so
/// the traits stay decoupled).  dcrd's `MaxPeers` hint is not used by
/// any manager logic and has no equivalent here.
pub struct Config<C, T, M> {
    /// The chain instance to use for processing blocks and headers.
    pub chain: C,
    /// The mempool to use for processing transactions.
    pub tx_mem_pool: T,
    /// The mixing pool to use for transient mixing messages.
    pub mix_pool: M,
    /// The network's minimum known chain work (dcrd
    /// `chaincfg.Params.MinKnownChainWork`).
    pub min_known_chain_work: Option<Uint256>,
    /// The network identifier (dcrd `chaincfg.Params.Net`).
    pub net: CurrencyNet,
    /// The network's target time per block in seconds (dcrd
    /// `chaincfg.Params.TargetTimePerBlock`).
    pub target_time_per_block_secs: i64,
    /// Whether the initial mining state synchronization is disabled
    /// (dcrd `NoMiningStateSync`).
    pub no_mining_state_sync: bool,
    /// The maximum number of outbound peers the server is expected to
    /// be connected with (dcrd `MaxOutboundPeers`).
    pub max_outbound_peers: u64,
    /// The maximum number of orphan transactions the pool supports
    /// (dcrd `MaxOrphanTxs`).
    pub max_orphan_txs: usize,
    /// A size limited set tracking the most recently confirmed
    /// transactions (dcrd `RecentlyConfirmedTxns`).  Shared with the
    /// daemon exactly as dcrd shares the server's filter with the
    /// netsync config: the chain handler records confirmations while
    /// the manager consults it.
    pub recently_confirmed_txns: std::sync::Arc<std::sync::Mutex<apbf::Filter>>,
}

/// The concurrency-free core of dcrd's `SyncManager`.
pub struct SyncManager<C, T, M: SyncMixPool> {
    cfg: Config<C, T, M>,
    min_known_work: Option<Uint256>,

    rejected_txns: apbf::Filter,
    rejected_mix_msgs: apbf::Filter,

    /// Pending requests for data from all peers, keyed by hash with
    /// the id of the peer the data was requested from.
    requested_txns: HashMap<Hash, i32>,
    requested_blocks: HashMap<Hash, i32>,
    requested_mix_msgs: HashMap<Hash, i32>,

    sync_peer: Option<i32>,
    warn_on_no_sync: bool,

    /// The peers available to the sync manager by id.  dcrd keys the
    /// set by pointer with random iteration order; iteration here is
    /// by ascending id (the decisions that depend on the order are
    /// documented at their sites).
    peers: BTreeMap<i32, Peer>,

    headers_synced: bool,
    is_initial_chain_sync_done: bool,

    sync_height: i64,
    is_current: bool,

    next_blocks_header: Hash,
    next_needed_blocks: VecDeque<Hash>,

    shutdown: bool,
}

impl<C: SyncChain, T: SyncTxPool, M: SyncMixPool> SyncManager<C, T, M> {
    /// A new sync manager (dcrd `New`).
    pub fn new(mut cfg: Config<C, T, M>) -> SyncManager<C, T, M> {
        let min_known_work = cfg.min_known_chain_work;
        let sync_height = cfg.chain.best_snapshot().height;
        let is_current = cfg.chain.is_current();
        SyncManager {
            cfg,
            min_known_work,
            rejected_txns: apbf::new_filter(MAX_REJECTED_TXNS, REJECTED_TXNS_FP_RATE),
            rejected_mix_msgs: apbf::new_filter(MAX_REJECTED_MIX_MSGS, REJECTED_MIX_MSGS_FP_RATE),
            requested_txns: HashMap::new(),
            requested_blocks: HashMap::new(),
            requested_mix_msgs: HashMap::new(),
            sync_peer: None,
            warn_on_no_sync: true,
            peers: BTreeMap::new(),
            headers_synced: false,
            is_initial_chain_sync_done: false,
            sync_height,
            is_current,
            next_blocks_header: Hash([0u8; 32]),
            next_needed_blocks: VecDeque::new(),
            shutdown: false,
        }
    }

    /// Mark the manager shut down; every handler becomes a no-op
    /// (dcrd closes `quit` when its run context is cancelled).
    pub fn request_shutdown(&mut self) {
        self.shutdown = true;
    }

    /// The peer with the given id, when tracked.
    pub fn peer(&self, id: i32) -> Option<&Peer> {
        self.peers.get(&id)
    }

    /// The chain instance (for daemon queries).
    pub fn chain_mut(&mut self) -> &mut C {
        &mut self.cfg.chain
    }

    /// The recently confirmed transactions filter (shared with the
    /// daemon, which records confirmations).
    pub fn recently_confirmed_txns(&self) -> std::sync::Arc<std::sync::Mutex<apbf::Filter>> {
        std::sync::Arc::clone(&self.cfg.recently_confirmed_txns)
    }

    /// The hashes and requesting peers of the in-flight requests, for
    /// inspection (sorted by hash).
    pub fn requested_snapshot(&self) -> [Vec<(Hash, i32)>; 3] {
        let sorted = |m: &HashMap<Hash, i32>| {
            let mut v: Vec<(Hash, i32)> = m.iter().map(|(h, p)| (*h, *p)).collect();
            v.sort_unstable_by_key(|e| e.0.0);
            v
        };
        [
            sorted(&self.requested_txns),
            sorted(&self.requested_blocks),
            sorted(&self.requested_mix_msgs),
        ]
    }

    /// Whether the transaction is in the recently rejected filter
    /// (for daemon queries and parity probes).
    pub fn rejected_txns_contains(&self, hash: &Hash) -> bool {
        self.rejected_txns.contains(&hash.0)
    }

    /// Whether the mixing message is in the recently rejected filter
    /// (for daemon queries and parity probes).
    pub fn rejected_mix_msgs_contains(&self, hash: &Hash) -> bool {
        self.rejected_mix_msgs.contains(&hash.0)
    }

    /// The latest known block height being synced to (dcrd
    /// `SyncHeight`).
    pub fn sync_height(&self) -> i64 {
        self.sync_height
    }

    /// Whether the initial header sync process is complete (dcrd
    /// `headerSyncState.InitialHeaderSyncDone`).
    pub fn initial_header_sync_done(&self) -> bool {
        self.headers_synced
    }

    /// Whether the initial chain sync process is complete.
    pub fn initial_chain_sync_done(&self) -> bool {
        self.is_initial_chain_sync_done
    }

    /// Atomically raise the sync height to the provided value (dcrd
    /// `maybeUpdateSyncHeight`).
    fn maybe_update_sync_height(&mut self, new_height: i64) {
        if new_height > self.sync_height {
            self.sync_height = new_height;
        }
    }

    /// Potentially update the list of the next blocks to download in
    /// the branch leading up to the best known header (dcrd
    /// `maybeUpdateNextNeededBlocks`).
    fn maybe_update_next_needed_blocks(&mut self) {
        // Update the list if the best known header changed since the
        // last time it was updated or it is not empty, is getting
        // short, and does not already end at the best known header.
        let (best_header, _) = self.cfg.chain.best_header();
        let num_needed = self.next_needed_blocks.len();
        let needs_update = self.next_blocks_header != best_header
            || (num_needed > 0
                && num_needed < MIN_IN_FLIGHT_BLOCKS
                && self.next_needed_blocks[num_needed - 1] != best_header);
        if needs_update {
            self.next_needed_blocks = self
                .cfg
                .chain
                .put_next_needed_blocks(NEXT_BLOCKS_BUF_SIZE)
                .into();
            self.next_blocks_header = best_header;
        }
    }

    /// Create and record a request to the provided peer for the next
    /// blocks to be downloaded based on the current headers (dcrd
    /// `fetchNextBlocks`).
    fn fetch_next_blocks(&mut self, peer_id: i32, actions: &mut Vec<Action>) {
        // Nothing to do if the target maximum number of blocks to
        // request from the peer at the same time are already in flight.
        let num_in_flight = self
            .requested_blocks
            .values()
            .filter(|&&from| from == peer_id)
            .count();
        if num_in_flight >= MAX_IN_FLIGHT_BLOCKS {
            return;
        }

        // Potentially update the list of the next blocks to download in
        // the branch leading up to the best known header.
        self.maybe_update_next_needed_blocks();

        // Build and send a getdata request for the needed blocks.
        let num_needed = self.next_needed_blocks.len();
        if num_needed == 0 {
            return;
        }
        let max_needed = MAX_IN_FLIGHT_BLOCKS - num_in_flight;
        let num_needed = num_needed.min(max_needed);
        let mut inv_list = Vec::with_capacity(num_needed);
        for _ in 0..num_needed {
            if inv_list.len() >= MAX_INV_PER_MSG as usize {
                break;
            }
            // The block is either going to be skipped because it has
            // already been requested or it will be requested, but in
            // either case, the block is no longer needed for future
            // iterations.
            let Some(hash) = self.next_needed_blocks.pop_front() else {
                break;
            };

            // Skip blocks that have already been requested.  The needed
            // blocks might have been updated above thereby potentially
            // repopulating some blocks that are still in flight.
            if self.requested_blocks.contains_key(&hash) {
                continue;
            }

            self.requested_blocks.insert(hash, peer_id);
            inv_list.push(InvVect {
                inv_type: InvType::BLOCK,
                hash,
            });
        }
        if !inv_list.is_empty() {
            actions.push(Action::QueueMessage {
                peer: peer_id,
                message: Message::GetData(MsgGetData { inv_list }),
            });
        }
    }

    /// Request headers from the provided peer starting from the parent
    /// of the best known header for the local chain (dcrd
    /// `fetchNextHeaders`).
    fn fetch_next_headers(&mut self, peer_id: i32, actions: &mut Vec<Action>) {
        let (mut parent_hash, _) = self.cfg.chain.best_header();
        if let Some(header) = self.cfg.chain.header_by_hash(&parent_hash) {
            parent_hash = header.prev_block;
        }
        let locator = self.cfg.chain.block_locator_from_hash(&parent_hash);
        let Some(peer) = self.peers.get_mut(&peer_id) else {
            return;
        };
        if let Some(msg) = peer.push_get_headers_msg(locator, &Hash([0u8; 32])) {
            actions.push(Action::QueueMessage {
                peer: peer_id,
                message: msg,
            });
        }
    }

    /// Update the sync peer to be the candidate with the highest known
    /// block height, and the is-current belief when there are no
    /// candidates (dcrd `updateSyncPeerState`).
    fn update_sync_peer_state(&mut self) {
        let (_, best_header_height) = self.cfg.chain.best_header();

        // Determine the best sync peer and number of outbound peers.
        // dcrd iterates its peer set in random map order, so a tie in
        // the last block height between candidates is broken
        // arbitrarily there; iteration here is by ascending peer id.
        let mut best_peer: Option<(i32, i64)> = None;
        let mut num_outbound: u64 = 0;
        for (id, peer) in &self.peers {
            if !peer.inbound {
                num_outbound += 1;
            }

            // Skip peers that are not sync candidates: the peer must
            // serve data and its latest known block height must be at
            // least as high as the best known header height (dcrd
            // `isSyncPeerCandidate`).
            if !(peer.serves_data && peer.last_block >= best_header_height) {
                continue;
            }

            // The best sync candidate is the most updated peer.
            match best_peer {
                Some((_, best_last)) if best_last >= peer.last_block => {}
                _ => best_peer = Some((*id, peer.last_block)),
            }
        }

        if best_peer.is_none() {
            self.is_current = self.cfg.chain.is_current();

            // A sync peer already being assigned prior to calling
            // implies it was disconnected or otherwise is no longer a
            // suitable candidate; no sync peer assigned implies there
            // were no suitable candidates at all, which is only worth a
            // warning at the max expected outbound connections.
            let had_sync_peer = self.sync_peer.is_some();
            let has_max_outbound = num_outbound >= self.cfg.max_outbound_peers;
            if self.warn_on_no_sync && (had_sync_peer || has_max_outbound) {
                self.warn_on_no_sync = false;
            }
        } else {
            // Ensure future warnings are eligible to be shown when no
            // sync peer candidates are available.
            self.warn_on_no_sync = true;
        }

        self.sync_peer = best_peer.map(|(id, _)| id);
    }

    /// Find the best header sync candidate and start or continue the
    /// initial header sync process with it (dcrd
    /// `startInitialHeaderSync`).
    fn start_initial_header_sync(&mut self, actions: &mut Vec<Action>) {
        self.update_sync_peer_state();
        let Some(sync_peer) = self.sync_peer else {
            return;
        };

        let sync_height = self.peers[&sync_peer].last_block;

        // The chain is not synced whenever the current best chain
        // height is not within a couple of blocks of the height to sync
        // to.
        let best_height = self.cfg.chain.best_snapshot().height;
        if best_height + 2 < sync_height {
            self.is_current = false;
        }

        // Request headers starting from the parent of the best known
        // header for the local chain from the sync peer.
        self.fetch_next_headers(sync_peer, actions);

        // Update the sync height when it is higher than the currently
        // best known value.
        self.maybe_update_sync_height(sync_height);

        // Start the header sync progress stall timeout.
        actions.push(Action::ResetHeaderSyncStallTimeout);
    }

    /// Find a peer to sync the chain from and start or continue the
    /// blockchain sync process with it (dcrd `startChainSync`).
    fn start_chain_sync(&mut self, actions: &mut Vec<Action>) {
        self.update_sync_peer_state();
        let Some(sync_peer) = self.sync_peer else {
            return;
        };

        // Download any blocks needed to catch the local chain up to the
        // best known header (if any).
        self.fetch_next_blocks(sync_peer, actions);
    }

    /// The initial chain sync completion transition (dcrd
    /// `onInitialChainSyncDone`).
    fn on_initial_chain_sync_done(&mut self, actions: &mut Vec<Action>) {
        // Prevent multiple invocations.
        if self.is_initial_chain_sync_done {
            return;
        }
        self.is_initial_chain_sync_done = true;

        // Request initial state from all peers that still need it now
        // that the initial chain sync is done.
        let include_mining_state = !self.cfg.no_mining_state_sync;
        for (id, peer) in self.peers.iter_mut() {
            if let Some(msg) = peer.maybe_request_initial_state(include_mining_state) {
                actions.push(Action::QueueMessage {
                    peer: *id,
                    message: msg,
                });
            }
        }
    }

    /// Track a peer that has gone through version negotiation and is
    /// suitable for participating in syncing (dcrd `OnPeerConnected`).
    pub fn on_peer_connected(&mut self, peer: Peer) -> Vec<Action> {
        let mut actions = Vec::new();
        if self.shutdown {
            return actions;
        }

        let peer_id = peer.id;
        self.peers.insert(peer_id, peer);

        // Attempt to find a peer to sync headers from when there isn't
        // already one and the initial headers sync process is still in
        // progress.
        if !self.headers_synced {
            if self.sync_peer.is_none() {
                self.start_initial_header_sync(&mut actions);
            }
            return actions;
        }

        // The initial headers sync process is done at this point.

        // Request headers starting from the parent of the best known
        // header for the local chain immediately when the initial
        // headers sync process is complete and the peer potentially
        // serves useful data.
        if self.peers[&peer_id].serves_data {
            self.fetch_next_headers(peer_id, &mut actions);
        }

        // Attempt to find a sync peer and start syncing the chain from
        // it when there isn't already one.
        if self.sync_peer.is_none() {
            self.start_chain_sync(&mut actions);
        }

        // Potentially request the initial state from this peer now when
        // the manager believes the chain is fully synced.  Otherwise,
        // it will be requested when the initial chain sync process is
        // complete.
        if self.is_current() {
            let include_mining_state = !self.cfg.no_mining_state_sync;
            if let Some(peer) = self.peers.get_mut(&peer_id)
                && let Some(msg) = peer.maybe_request_initial_state(include_mining_state)
            {
                actions.push(Action::QueueMessage {
                    peer: peer_id,
                    message: msg,
                });
            }
        }

        actions
    }

    /// Remove a disconnected peer as a sync candidate, re-request its
    /// in-flight data from other announcing peers, and potentially
    /// select a new sync peer (dcrd `OnPeerDisconnected`).
    pub fn on_peer_disconnected(&mut self, peer_id: i32) -> Vec<Action> {
        let mut actions = Vec::new();
        if self.shutdown {
            return actions;
        }

        // Remove the peer from the list of candidate peers.
        self.peers.remove(&peer_id);

        // Attempt to find a new peer to sync headers from when the
        // quitting peer is the sync peer and the initial headers sync
        // process is still in progress.  Also, skip the rest of the
        // logic below before the headers are synced since no requests
        // for the data being checked are made prior to that point nor
        // can the chain sync be started.
        if !self.headers_synced {
            if self.sync_peer == Some(peer_id) {
                self.start_initial_header_sync(&mut actions);
            }
            return actions;
        }

        // The initial headers sync process is done at this point.

        // Re-request in-flight blocks and transactions that were not
        // received by the disconnected peer if the data was announced
        // by another peer.  Remove the data from the request maps if no
        // other peers have announced the data.
        //
        // dcrd walks each request map and its peer set in random map
        // order, so when several other peers announced the same data
        // the replacement choice is arbitrary there, as is the entry
        // order within each rebuilt getdata message; here both walks
        // are in deterministic order (arbitrary hash-map order for the
        // requests, ascending id for the peers).
        let mut request_queues: BTreeMap<i32, Vec<InvVect>> = BTreeMap::new();
        let mut requeue = |requested: &mut HashMap<Hash, i32>,
                           peers: &mut BTreeMap<i32, Peer>,
                           inv_type: InvType| {
            let hashes: Vec<Hash> = requested
                .iter()
                .filter(|&(_, from)| *from == peer_id)
                .map(|(h, _)| *h)
                .collect();
            'hashes: for hash in hashes {
                let inv = InvVect { inv_type, hash };
                for (id, pp) in peers.iter_mut() {
                    if !pp.is_known_inventory(&inv) {
                        continue;
                    }
                    request_queues.entry(*id).or_default().push(inv);
                    requested.insert(hash, *id);
                    continue 'hashes;
                }
                // No peers found that have announced this data.
                requested.remove(&hash);
            }
        };
        requeue(&mut self.requested_txns, &mut self.peers, InvType::TX);
        requeue(&mut self.requested_blocks, &mut self.peers, InvType::BLOCK);
        requeue(&mut self.requested_mix_msgs, &mut self.peers, InvType::MIX);
        for (pp, request_queue) in request_queues {
            let mut inv_list = Vec::new();
            for inv in request_queue {
                inv_list.push(inv);
                if inv_list.len() == MAX_INV_PER_MSG as usize {
                    actions.push(Action::QueueMessage {
                        peer: pp,
                        message: Message::GetData(MsgGetData {
                            inv_list: std::mem::take(&mut inv_list),
                        }),
                    });
                }
            }
            if !inv_list.is_empty() {
                actions.push(Action::QueueMessage {
                    peer: pp,
                    message: Message::GetData(MsgGetData { inv_list }),
                });
            }
        }

        // Attempt to find a new peer to sync the chain from when the
        // quitting peer is the sync peer.
        if self.sync_peer == Some(peer_id) {
            self.start_chain_sync(&mut actions);
        }

        actions
    }

    /// Process a transaction received from a remote peer, returning
    /// the hashes of the transactions accepted to the mempool (dcrd
    /// `OnTx`).
    pub fn on_tx(&mut self, peer_id: i32, tx: &MsgTx) -> Vec<Hash> {
        if self.shutdown {
            return Vec::new();
        }

        // There is deliberately no check to disconnect peers for
        // sending unsolicited transactions (legacy interoperability).
        let tx_hash = tx.tx_hash();

        // Ignore transactions that have already been rejected.  The
        // transaction was unsolicited if it was already previously
        // rejected.
        if self.rejected_txns.contains(&tx_hash.0) {
            return Vec::new();
        }

        // Process the transaction to include validation, insertion in
        // the memory pool, orphan handling, etc.
        let allow_orphans = self.cfg.max_orphan_txs > 0;
        let result =
            self.cfg
                .tx_mem_pool
                .process_transaction(tx, allow_orphans, true, peer_id as u64);

        // Remove transaction from request maps.  Either the
        // mempool/chain already knows about it and as such we
        // shouldn't have any more instances of trying to fetch it, or
        // we failed to insert and thus we'll retry next time we get an
        // inv.
        self.requested_txns.remove(&tx_hash);

        match result {
            Ok(accepted_txns) => accepted_txns,
            Err(_) => {
                // Do not request this transaction again until a new
                // block has been processed.
                self.rejected_txns.add(&tx_hash.0);
                Vec::new()
            }
        }
    }

    /// Process a mixing message received from a remote peer, returning
    /// the messages accepted to the mixpool or the acceptance error
    /// (dcrd `OnMixMsg`).
    pub fn on_mix_msg(&mut self, peer_id: i32, msg: &M::Msg) -> Result<Vec<M::Msg>, String> {
        if self.shutdown {
            return Ok(Vec::new());
        }

        // Ignore mix messages that have already been rejected.  The
        // message was unsolicited if it was already previously
        // rejected.
        let mix_hash = self.cfg.mix_pool.mix_hash(msg);
        if self.rejected_mix_msgs.contains(&mix_hash.0) {
            return Ok(Vec::new());
        }

        let result = self.cfg.mix_pool.accept_message(msg, peer_id as u64);

        // Remove message from request maps.  Either the mixpool
        // already knows about it and as such we shouldn't have any
        // more instances of trying to fetch it, or we failed to insert
        // and thus we'll retry next time we get an inv.
        self.requested_mix_msgs.remove(&mix_hash);

        match result {
            Ok(accepted) => Ok(accepted),
            Err(err) => {
                // Do not request this message again until a new block
                // has been processed.
                self.rejected_mix_msgs.add(&mix_hash.0);
                Err(err)
            }
        }
    }

    /// Potentially update the manager to signal it believes the chain
    /// is considered synced (dcrd `maybeUpdateIsCurrent`).
    fn maybe_update_is_current(&mut self) {
        // Nothing to do when already considered synced.
        if self.is_current {
            return;
        }

        // The chain is considered synced once both the blockchain
        // believes it is current and the sync height is reached or
        // exceeded.
        let best_height = self.cfg.chain.best_snapshot().height;
        if best_height >= self.sync_height && self.cfg.chain.is_current() {
            self.is_current = true;
        }
    }

    /// Potentially update the block with the most cumulative proof of
    /// work announced by the peer (dcrd
    /// `maybeUpdateBestAnnouncedBlock`).
    fn maybe_update_best_announced_block(
        &mut self,
        peer_id: i32,
        hash: &Hash,
        header: &BlockHeader,
    ) {
        let Some(work_sum) = self.cfg.chain.chain_work(hash) else {
            return;
        };
        let Some(peer) = self.peers.get_mut(&peer_id) else {
            return;
        };

        // Update the best block and associated values when the
        // cumulative work for the given block exceeds that of the
        // current best known block for the peer.
        let exceeds = match &peer.best_announced_work {
            None => true,
            Some(best) => work_sum > *best,
        };
        if exceeds {
            peer.best_announced_block = Some(*hash);
            peer.best_announced_work = Some(work_sum);
            peer.update_last_block_height(header.height as i64);
        }
    }

    /// Potentially resolve the most recently announced block by the
    /// peer that did not connect to any known headers at announcement
    /// time (dcrd `maybeResolveOrphanBlock`).
    fn maybe_resolve_orphan_block(&mut self, peer_id: i32) {
        // Nothing to do if there isn't a pending orphan block
        // announcement that has not yet been resolved or the block
        // still isn't known.
        let Some(block_hash) = self
            .peers
            .get(&peer_id)
            .and_then(|p| p.announced_orphan_block)
        else {
            return;
        };
        if !self.cfg.chain.have_header(&block_hash) {
            return;
        }

        // The block has now been resolved, so potentially make it the
        // block with the most cumulative proof of work announced by
        // the peer.
        let Some(header) = self.cfg.chain.header_by_hash(&block_hash) else {
            return;
        };
        self.maybe_update_best_announced_block(peer_id, &block_hash, &header);
    }

    /// Process the provided block using the internal chain instance
    /// (dcrd unexported `processBlock`).
    fn process_block_internal(&mut self, block: &MsgBlock) -> Result<i64, ProcessBlockFailure> {
        // Process the block to include validation, best chain
        // selection, etc.
        let fork_len = self.cfg.chain.process_block(block)?;

        // Update the sync height when the block is higher than the
        // currently best known value and it extends the main chain.
        let on_main_chain = fork_len == 0;
        if on_main_chain {
            self.maybe_update_sync_height(block.header.height as i64);
        }

        self.maybe_update_is_current();

        Ok(fork_len)
    }

    /// Process a block received from a remote peer (dcrd `OnBlock`).
    pub fn on_block(&mut self, peer_id: i32, block: &MsgBlock) -> Vec<Action> {
        let mut actions = Vec::new();
        if self.shutdown {
            return actions;
        }

        // The remote peer is misbehaving when the block was not
        // requested.
        let block_hash = block.header.block_hash();
        let requested = self.requested_blocks.get(&block_hash) == Some(&peer_id);
        if !requested {
            if let Some(peer) = self.peers.get_mut(&peer_id) {
                peer.connected = false;
            }
            actions.push(Action::Disconnect { peer: peer_id });
            return actions;
        }

        // Save the current best header prior to processing the block
        // for use below.
        let (cur_best_header_hash, _) = self.cfg.chain.best_header();

        // Process the block to include validation, best chain
        // selection, etc.  Also, remove the block from the request maps
        // once it has been processed.  This ensures chain is aware of
        // the block before it is removed from the maps in order to
        // help prevent duplicate requests.
        let result = self.process_block_internal(block);
        self.requested_blocks.remove(&block_hash);
        let fork_len = match result {
            Ok(fork_len) => fork_len,
            Err(failure) => {
                // Ideally there should never be any requests for
                // duplicate blocks, but ignore any that manage to make
                // it through.
                if failure.is_duplicate_block {
                    return actions;
                }

                // Request headers from all peers that serve data to
                // discover any new blocks that are not already known
                // starting from the parent of the new best known
                // header for the local chain when the header that was
                // previously believed to be the best candidate is
                // rejected.  Also, reset the sync height to whatever
                // the chain reports as the new best header height
                // since it is now very likely less than the tip that
                // was just rejected.
                let is_block_for_best_header = cur_best_header_hash == block_hash;
                if is_block_for_best_header {
                    let (_, new_best_header_height) = self.cfg.chain.best_header();
                    self.sync_height = new_best_header_height;

                    self.maybe_update_is_current();

                    let peer_ids: Vec<i32> = self
                        .peers
                        .iter()
                        .filter(|(_, p)| p.serves_data)
                        .map(|(id, _)| *id)
                        .collect();
                    for id in peer_ids {
                        self.fetch_next_headers(id, &mut actions);
                    }
                }

                return actions;
            }
        };

        // dcrd logs information about the block here, via the periodic
        // progress logger before the initial chain sync is done and
        // individually after; only the state transition is mirrored.
        let header = &block.header;
        if !self.is_initial_chain_sync_done {
            let is_chain_current = self.cfg.chain.is_current();
            if is_chain_current {
                self.on_initial_chain_sync_done(&mut actions);
            }
        }

        // Perform some additional processing when the block extended
        // the main chain.
        let on_main_chain = fork_len == 0;
        if on_main_chain {
            // Prune invalidated transactions.
            let best = self.cfg.chain.best_snapshot();
            self.cfg
                .tx_mem_pool
                .prune_stake_tx(best.next_stake_diff, best.height);
            self.cfg.tx_mem_pool.prune_expired_tx(best.height);

            // Clear the rejected transactions.
            self.rejected_txns.reset();

            // Remove expired pair requests and completed mixes from
            // the mixpool.
            self.cfg.mix_pool.remove_spent_prs(&block.transactions);
            self.cfg.mix_pool.remove_spent_prs(&block.stransactions);
            self.cfg
                .mix_pool
                .expire_messages_in_background(header.height);
        }

        // Request more blocks using the headers when the request queue
        // is getting short.
        if self.sync_peer == Some(peer_id) && self.requested_blocks.len() < MIN_IN_FLIGHT_BLOCKS {
            self.fetch_next_blocks(peer_id, &mut actions);
        }

        actions
    }

    /// A guess of the header sync progress percentage based on the
    /// expected total number of headers given the target time per
    /// block (dcrd `guessHeaderSyncProgress`); only suitable for the
    /// main and test networks.
    pub fn guess_header_sync_progress(
        &self,
        header: &BlockHeader,
        cur_adjusted_time_unix: i64,
    ) -> f64 {
        // Calculate the expected total number of blocks to reach the
        // current time by considering the number there already are
        // plus the expected number of remaining ones there should be
        // in the time interval since the provided best known header
        // and the current time given the target block time.
        let target_secs_per_block = self.cfg.target_time_per_block_secs;
        let remaining = (cur_adjusted_time_unix - header.timestamp as i64) / target_secs_per_block;
        let expected_total = header.height as i64 + remaining;

        // Finally the progress guess is simply the ratio of the
        // current number of known headers to the total expected number
        // of headers.
        (header.height as f64 / expected_total as f64).min(1.0) * 100.0
    }

    /// A guess of the progress of the header sync process (dcrd
    /// `headerSyncProgress`; the adjusted time stands in for dcrd's
    /// median time source).
    pub fn header_sync_progress(&mut self, cur_adjusted_time_unix: i64) -> f64 {
        let (hash, _) = self.cfg.chain.best_header();
        let Some(header) = self.cfg.chain.header_by_hash(&hash) else {
            return 0.0;
        };

        // Use an algorithm that considers the total number of expected
        // headers based on the target time per block of the network
        // for the main and test networks; it assumes consistent
        // mining, which is not the case on all networks.
        let net = self.cfg.net;
        if net == CurrencyNet::MAIN_NET || net == CurrencyNet::TEST_NET3 {
            return self.guess_header_sync_progress(&header, cur_adjusted_time_unix);
        }

        // Fall back to using the sync height reported by the remote
        // peer otherwise.
        let sync_height = self.sync_height;
        if sync_height == 0 {
            return 0.0;
        }
        (header.height as f64 / sync_height as f64).min(1.0) * 100.0
    }

    /// The initial header sync completion transition (dcrd
    /// `onInitialHeaderSyncDone`).
    fn on_initial_header_sync_done(&mut self, actions: &mut Vec<Action>) {
        actions.push(Action::StopHeaderSyncStallTimeout);

        // Prevent multiple invocations.
        if self.headers_synced {
            return;
        }
        self.headers_synced = true;

        // Request headers starting from the parent of the best known
        // header for the local chain from any peers that potentially
        // serve useful data and have not yet had their best known
        // block discovered now that the initial headers sync process
        // is complete.
        let peer_ids: Vec<i32> = self.peers.keys().copied().collect();
        for id in peer_ids {
            self.maybe_resolve_orphan_block(id);
            let Some(peer) = self.peers.get(&id) else {
                continue;
            };
            let needs_best_header = peer.serves_data && peer.best_announced_block.is_none();
            if !needs_best_header {
                continue;
            }
            self.fetch_next_headers(id, actions);
        }

        // Potentially update whether the chain believes it is current
        // now that the headers are synced.
        self.cfg.chain.maybe_update_is_current();
        if self.cfg.chain.is_current() {
            self.on_initial_chain_sync_done(actions);
        }
    }

    /// Process a headers message received from a remote peer (dcrd
    /// `OnHeaders`).
    pub fn on_headers(&mut self, peer_id: i32, headers_msg: &MsgHeaders) -> Vec<Action> {
        let mut actions = Vec::new();
        if self.shutdown {
            return actions;
        }

        // Nothing to do for an empty headers message as it means the
        // sending peer does not have any additional headers for the
        // requested block locator.
        let headers = &headers_msg.headers;
        let num_headers = headers.len();
        if num_headers == 0 {
            return actions;
        }

        // Handle the case where the first header does not connect to
        // any known headers specially.
        let first_header = &headers[0];
        let first_header_hash = first_header.block_hash();
        let first_header_connects = self.cfg.chain.have_header(&first_header.prev_block);
        let mut headers_synced = self.headers_synced;
        if !first_header_connects {
            // Attempt to detect block announcements which do not
            // connect to any known headers and request any headers
            // starting from the best header the local chain knows in
            // order to (hopefully) discover the missing headers unless
            // the initial headers sync process is still in progress.
            //
            // Meanwhile, also keep track of how many times the peer
            // has consecutively sent a headers message that looks like
            // an announcement that does not connect and disconnect it
            // once the max allowed threshold has been reached.
            if num_headers < MAX_EXPECTED_HEADER_ANNOUNCEMENTS_PER_MSG {
                let num_consecutive = {
                    let Some(peer) = self.peers.get_mut(&peer_id) else {
                        return actions;
                    };
                    peer.num_consecutive_orphan_headers += 1;
                    peer.num_consecutive_orphan_headers
                };
                if num_consecutive >= MAX_CONSECUTIVE_ORPHAN_HEADERS {
                    if let Some(peer) = self.peers.get_mut(&peer_id) {
                        peer.connected = false;
                    }
                    actions.push(Action::Disconnect { peer: peer_id });
                    return actions;
                }

                if headers_synced {
                    let (best_header_hash, _) = self.cfg.chain.best_header();
                    let locator = self.cfg.chain.block_locator_from_hash(&best_header_hash);
                    if let Some(peer) = self.peers.get_mut(&peer_id)
                        && let Some(msg) = peer.push_get_headers_msg(locator, &Hash([0u8; 32]))
                    {
                        actions.push(Action::QueueMessage {
                            peer: peer_id,
                            message: msg,
                        });
                    }
                }

                // Track the final announced header as the most recently
                // announced block by the peer that does not connect to
                // any headers known to the local chain since there is a
                // good chance it will eventually become known either
                // from this peer or others.
                let final_header = &headers[headers.len() - 1];
                let final_header_hash = final_header.block_hash();
                self.maybe_resolve_orphan_block(peer_id);
                if let Some(peer) = self.peers.get_mut(&peer_id) {
                    peer.announced_orphan_block = Some(final_header_hash);

                    // Update the latest block height for the peer to
                    // avoid stale heights when looking for future
                    // potential header sync node candidacy when the
                    // initial headers sync process is still in
                    // progress.
                    if !headers_synced {
                        peer.update_last_block_height(final_header.height as i64);
                    }
                }
                return actions;
            }

            // Disconnect the peer when the initial headers sync
            // process is done and this does not appear to be a block
            // announcement.
            if headers_synced {
                if let Some(peer) = self.peers.get_mut(&peer_id) {
                    peer.connected = false;
                }
                actions.push(Action::Disconnect { peer: peer_id });
                return actions;
            }

            // Ignore headers that do not connect to any known headers
            // when the initial headers sync is taking place.  It is
            // expected that headers will be announced that are not yet
            // known.
            return actions;
        }

        // Ensure all of the received headers connect the previous one
        // before attempting to perform any further processing on any
        // of them.
        let mut header_hashes = Vec::with_capacity(headers.len());
        header_hashes.push(first_header_hash);
        for (prev_idx, header) in headers[1..].iter().enumerate() {
            let prev_hash = &header_hashes[prev_idx];
            let prev_height = headers[prev_idx].height;
            if header.prev_block != *prev_hash || header.height != prev_height + 1 {
                if let Some(peer) = self.peers.get_mut(&peer_id) {
                    peer.connected = false;
                }
                actions.push(Action::Disconnect { peer: peer_id });
                return actions;
            }
            header_hashes.push(header.block_hash());
        }

        let is_sync_peer = self.sync_peer == Some(peer_id);

        // Save the current best known header height prior to
        // processing the headers so the code later is able to
        // determine if any new useful headers were provided.
        let (_, prev_best_header_height) = self.cfg.chain.best_header();

        // Process all of the received headers.
        for header in headers {
            if self.cfg.chain.process_block_header(header).is_err() {
                // Update the sync height when the sync peer fails to
                // process any headers since that chain is invalid from
                // the local point of view and thus whatever the best
                // known good header is becomes the new sync height
                // unless a better one is discovered from the new sync
                // peer.
                if !headers_synced && is_sync_peer {
                    let (_, new_best_header_height) = self.cfg.chain.best_header();
                    self.sync_height = new_best_header_height;
                }

                if let Some(peer) = self.peers.get_mut(&peer_id) {
                    peer.connected = false;
                }
                actions.push(Action::Disconnect { peer: peer_id });
                return actions;
            }
        }

        // All of the headers were either accepted or already known
        // valid at this point.

        // Reset the header sync progress stall timeout when the
        // headers are not already synced and progress was made.
        let (new_best_header_hash, new_best_header_height) = self.cfg.chain.best_header();
        let _ = new_best_header_hash;
        if !headers_synced && is_sync_peer && new_best_header_height > prev_best_header_height {
            actions.push(Action::ResetHeaderSyncStallTimeout);
        }

        // Reset the count of consecutive headers messages that
        // contained headers which do not connect.  Note that this is
        // intentionally only done when all of the provided headers are
        // successfully processed above.
        if let Some(peer) = self.peers.get_mut(&peer_id) {
            peer.num_consecutive_orphan_headers = 0;
        }

        // Potentially resolve a previously unknown announced block and
        // then update the block with the most cumulative proof of work
        // the peer has announced to the final announced header if
        // needed.
        let final_header = &headers[headers.len() - 1];
        let final_received_hash = header_hashes[header_hashes.len() - 1];
        self.maybe_resolve_orphan_block(peer_id);
        self.maybe_update_best_announced_block(peer_id, &final_received_hash, final_header);

        // Update the sync height if the new best known header height
        // exceeds it.
        self.maybe_update_sync_height(new_best_header_height);

        // Disconnect outbound peers that have less cumulative work
        // than the minimum value already known to have been achieved
        // on the network a priori while the initial sync is still
        // underway.  This is determined by noting that a peer only
        // sends fewer than the maximum number of headers per message
        // when it has reached its best known header.
        let mut is_chain_current = self.cfg.chain.is_current();
        let received_max_headers = headers.len() == MAX_BLOCK_HEADERS_PER_MSG as usize;
        let peer_inbound = self.peers.get(&peer_id).is_some_and(|p| p.inbound);
        if !is_chain_current
            && !peer_inbound
            && !received_max_headers
            && let Some(min_known_work) = &self.min_known_work
            && let Some(work_sum) = self.cfg.chain.chain_work(&final_received_hash)
            && work_sum < *min_known_work
        {
            if let Some(peer) = self.peers.get_mut(&peer_id) {
                peer.connected = false;
            }
            actions.push(Action::Disconnect { peer: peer_id });
            return actions;
        }

        // Request more headers when the peer announced the maximum
        // number of headers that can be sent in a single message since
        // it probably has more.
        if received_max_headers {
            let locator = self.cfg.chain.block_locator_from_hash(&final_received_hash);
            if let Some(peer) = self.peers.get_mut(&peer_id)
                && let Some(msg) = peer.push_get_headers_msg(locator, &Hash([0u8; 32]))
            {
                actions.push(Action::QueueMessage {
                    peer: peer_id,
                    message: msg,
                });
            }
        }

        // Consider the headers synced once the sync peer sends a
        // message with a final header that is within a few blocks of
        // the sync height.
        if !headers_synced
            && is_sync_peer
            && final_header.height as i64 + SYNC_HEIGHT_FETCH_OFFSET > self.sync_height
        {
            {
                headers_synced = true;

                // dcrd logs the header progress here.
                self.on_initial_header_sync_done(&mut actions);

                // Update the local var that tracks whether the chain
                // believes it is current since it might have been
                // updated now that the headers are synced.
                is_chain_current = self.cfg.chain.is_current();
            }
        }

        // Immediately download blocks associated with the announced
        // headers once the chain is current.  This allows downloading
        // from whichever peer announces it first and also ensures any
        // side chain blocks are downloaded for vote consideration.
        if is_chain_current {
            let mut inv_list = Vec::with_capacity(headers.len());
            for hash in &header_hashes {
                // Skip the block when it has already been requested or
                // is otherwise already known.
                if self.requested_blocks.contains_key(hash) || self.cfg.chain.have_block(hash) {
                    continue;
                }

                // Stop requesting when the request would exceed the max
                // size of the map used to track requests.
                if self.requested_blocks.len() + 1 > MAX_REQUESTED_BLOCKS {
                    break;
                }

                self.requested_blocks.insert(*hash, peer_id);
                inv_list.push(InvVect {
                    inv_type: InvType::BLOCK,
                    hash: *hash,
                });
            }
            if !inv_list.is_empty() {
                actions.push(Action::QueueMessage {
                    peer: peer_id,
                    message: Message::GetData(MsgGetData { inv_list }),
                });
            }
        }

        // Download any blocks needed to catch the local chain up to
        // the best known header (if any) once the initial headers sync
        // is done.
        if headers_synced && let Some(sync_peer) = self.sync_peer {
            self.fetch_next_blocks(sync_peer, &mut actions);
        }

        actions
    }

    /// Remove reported items from the request maps so they can
    /// eventually be requested from elsewhere (dcrd `OnNotFound`).
    // The per-type arms mirror dcrd's switch.
    #[allow(clippy::collapsible_match)]
    pub fn on_not_found(&mut self, peer_id: i32, not_found: &MsgNotFound) {
        if self.shutdown {
            return;
        }

        for inv in &not_found.inv_list {
            // Verify the hash was actually announced by the peer
            // before deleting from the request maps.
            match inv.inv_type {
                InvType::BLOCK => {
                    if self.requested_blocks.get(&inv.hash) == Some(&peer_id) {
                        self.requested_blocks.remove(&inv.hash);
                    }
                }
                InvType::TX => {
                    if self.requested_txns.get(&inv.hash) == Some(&peer_id) {
                        self.requested_txns.remove(&inv.hash);
                    }
                }
                InvType::MIX => {
                    if self.requested_mix_msgs.get(&inv.hash) == Some(&peer_id) {
                        self.requested_mix_msgs.remove(&inv.hash);
                    }
                }
                _ => {}
            }
        }
    }

    /// Whether the transaction needs to be downloaded (dcrd `needTx`).
    fn need_tx(&mut self, hash: &Hash) -> bool {
        // No need for transactions that have already been rejected.
        if self.rejected_txns.contains(&hash.0) {
            return false;
        }

        // No need for transactions that are already available in the
        // transaction memory pool (main pool or orphan).
        if self.cfg.tx_mem_pool.have_transaction(hash) {
            return false;
        }

        // No need for transactions that were recently confirmed.
        if self
            .cfg
            .recently_confirmed_txns
            .lock()
            .expect("recently confirmed filter poisoned")
            .contains(&hash.0)
        {
            return false;
        }

        true
    }

    /// Whether the mixing message needs to be downloaded (dcrd
    /// `needMixMsg`).
    fn need_mix_msg(&mut self, hash: &Hash) -> bool {
        if self.rejected_mix_msgs.contains(&hash.0) {
            return false;
        }

        // No need for mix messages that are already available in the
        // mixing pool or were recently removed.
        if self.cfg.mix_pool.recent_message(hash) {
            return false;
        }

        true
    }

    /// Learn about the inventory advertised by the remote peer and
    /// decide what associated data to request from it (dcrd `OnInv`).
    pub fn on_inv(&mut self, peer_id: i32, inv: &MsgInv) -> Vec<Action> {
        let mut actions = Vec::new();
        if self.shutdown {
            return actions;
        }

        let is_current = self.is_current();

        // Update state information regarding per-peer known inventory
        // and determine what inventory to request based on factors
        // such as the current sync state and whether or not the data
        // is already available.  Also, keep track of the final
        // announced block (when there is one) so the peer can be
        // updated with that information accordingly.
        let mut last_block: Option<InvVect> = None;
        let mut request_queue: Vec<InvVect> = Vec::new();
        for iv in &inv.inv_list {
            match iv.inv_type {
                InvType::BLOCK => {
                    // All block announcements are made via headers, so
                    // there is no need to request anything here; the
                    // known inventory state is still updated.
                    if let Some(peer) = self.peers.get_mut(&peer_id) {
                        peer.add_known_inventory(*iv);
                    }

                    // Update the last block in the announced inventory.
                    last_block = Some(*iv);
                }
                InvType::TX => {
                    // Add the tx to the cache of known inventory for
                    // the peer.
                    if let Some(peer) = self.peers.get_mut(&peer_id) {
                        peer.add_known_inventory(*iv);
                    }

                    // Ignore transaction announcements before the chain
                    // is current or are otherwise not needed.
                    if !is_current || !self.need_tx(&iv.hash) {
                        continue;
                    }

                    // Request the transaction if there is not one
                    // already pending.
                    if !self.requested_txns.contains_key(&iv.hash) {
                        limit_add(
                            &mut self.requested_txns,
                            iv.hash,
                            peer_id,
                            MAX_REQUESTED_TXNS,
                        );
                        request_queue.push(*iv);
                    }
                }
                InvType::MIX => {
                    // Add the mix message to the cache of known
                    // inventory for the peer.
                    if let Some(peer) = self.peers.get_mut(&peer_id) {
                        peer.add_known_inventory(*iv);
                    }

                    // Ignore mixing messages before the chain is
                    // current or if the messages are not needed.
                    if !is_current || !self.need_mix_msg(&iv.hash) {
                        continue;
                    }

                    // Request the mixing message if it is not already
                    // pending.
                    if !self.requested_mix_msgs.contains_key(&iv.hash) {
                        limit_add(
                            &mut self.requested_mix_msgs,
                            iv.hash,
                            peer_id,
                            MAX_REQUESTED_MIX_MSGS,
                        );
                        request_queue.push(*iv);
                    }
                }
                _ => {}
            }
        }

        if let Some(last_block) = last_block {
            // Determine if the final announced block is already known
            // to the local chain and then either track it as the most
            // recently announced block by the peer that does not
            // connect to any headers known to the local chain or
            // potentially make it the block with the most cumulative
            // proof of work announced by the peer when it is already
            // known.
            if !self.cfg.chain.have_header(&last_block.hash) {
                self.maybe_resolve_orphan_block(peer_id);
                if let Some(peer) = self.peers.get_mut(&peer_id) {
                    peer.announced_orphan_block = Some(last_block.hash);
                }
            } else if let Some(header) = self.cfg.chain.header_by_hash(&last_block.hash) {
                self.maybe_resolve_orphan_block(peer_id);
                self.maybe_update_best_announced_block(peer_id, &last_block.hash, &header);
            }
        }

        // Request as much as possible at once.
        let mut inv_list = Vec::new();
        for iv in request_queue {
            inv_list.push(iv);
            if inv_list.len() == MAX_INV_PER_MSG as usize {
                // Send full getdata message and reset.
                actions.push(Action::QueueMessage {
                    peer: peer_id,
                    message: Message::GetData(MsgGetData {
                        inv_list: std::mem::take(&mut inv_list),
                    }),
                });
            }
        }
        if !inv_list.is_empty() {
            actions.push(Action::QueueMessage {
                peer: peer_id,
                message: Message::GetData(MsgGetData { inv_list }),
            });
        }

        actions
    }

    /// The header sync stall timeout firing: disconnect the sync peer
    /// to ensure clean recovery from stalls (the body of dcrd's
    /// `stallHandler` timer case; the daemon invokes this when the
    /// timer armed by [`Action::ResetHeaderSyncStallTimeout`] fires).
    pub fn on_header_sync_stall_timeout(&mut self) -> Vec<Action> {
        let mut actions = Vec::new();
        if let Some(sync_peer) = self.sync_peer {
            if let Some(peer) = self.peers.get_mut(&sync_peer) {
                peer.connected = false;
            }
            actions.push(Action::Disconnect { peer: sync_peer });
        }
        actions
    }

    /// The id of the current sync peer, or 0 if there is none (dcrd
    /// `SyncPeerID`).
    pub fn sync_peer_id(&self) -> i32 {
        if self.shutdown {
            return 0;
        }
        self.sync_peer.unwrap_or(0)
    }

    /// Request any combination of blocks, votes, and treasury spends
    /// from the given peer, tracking the requests so the peer is not
    /// banned for sending unrequested data when it responds (dcrd
    /// `RequestFromPeer`).
    pub fn request_from_peer(
        &mut self,
        peer_id: i32,
        blocks: &[Hash],
        vote_hashes: &[Hash],
        tspend_hashes: &[Hash],
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        if self.shutdown {
            return actions;
        }

        // Request as many needed blocks as possible at once.
        let mut inv_list = Vec::new();
        for block_hash in blocks {
            // Skip the block when it has already been requested or is
            // already known.
            if self.requested_blocks.contains_key(block_hash)
                || self.cfg.chain.have_block(block_hash)
            {
                continue;
            }

            inv_list.push(InvVect {
                inv_type: InvType::BLOCK,
                hash: *block_hash,
            });
            self.requested_blocks.insert(*block_hash, peer_id);
            if inv_list.len() == MAX_INV_PER_MSG as usize {
                // Send full getdata message and reset.
                actions.push(Action::QueueMessage {
                    peer: peer_id,
                    message: Message::GetData(MsgGetData {
                        inv_list: std::mem::take(&mut inv_list),
                    }),
                });
            }
        }

        // Request as many needed votes and treasury spend transactions
        // as possible at once.
        for hashes in [vote_hashes, tspend_hashes] {
            for tx_hash in hashes {
                // Skip the transaction when it has already been
                // requested or is otherwise not needed.
                if self.requested_txns.contains_key(tx_hash) || !self.need_tx(tx_hash) {
                    continue;
                }

                inv_list.push(InvVect {
                    inv_type: InvType::TX,
                    hash: *tx_hash,
                });
                self.requested_txns.insert(*tx_hash, peer_id);
                if inv_list.len() == MAX_INV_PER_MSG as usize {
                    // Send full getdata message and reset.
                    actions.push(Action::QueueMessage {
                        peer: peer_id,
                        message: Message::GetData(MsgGetData {
                            inv_list: std::mem::take(&mut inv_list),
                        }),
                    });
                }
            }
        }

        if !inv_list.is_empty() {
            actions.push(Action::QueueMessage {
                peer: peer_id,
                message: Message::GetData(MsgGetData { inv_list }),
            });
        }

        actions
    }

    /// Request the specified mix message from the given peer, tracking
    /// the request so the peer is not banned for sending unrequested
    /// data when it responds (dcrd `RequestMixMsgFromPeer`).
    pub fn request_mix_msg_from_peer(&mut self, peer_id: i32, mix_hash: &Hash) -> Vec<Action> {
        let mut actions = Vec::new();
        if self.shutdown {
            return actions;
        }

        // Skip mix messages that have already been requested or are
        // otherwise not needed.
        if self.requested_mix_msgs.contains_key(mix_hash) || !self.need_mix_msg(mix_hash) {
            return actions;
        }

        let inv_list = vec![InvVect {
            inv_type: InvType::MIX,
            hash: *mix_hash,
        }];
        self.requested_mix_msgs.insert(*mix_hash, peer_id);
        actions.push(Action::QueueMessage {
            peer: peer_id,
            message: Message::GetData(MsgGetData { inv_list }),
        });
        actions
    }

    /// Process a block from a local source such as the RPC server or
    /// the CPU miner through the same code paths as blocks received
    /// from the network (dcrd `ProcessBlock`).
    pub fn process_block(&mut self, block: &MsgBlock) -> Result<(), ProcessBlockFailure> {
        if self.shutdown {
            return Ok(());
        }

        let fork_len = self.process_block_internal(block)?;

        let on_main_chain = fork_len == 0;
        if on_main_chain {
            // Prune invalidated transactions.
            let best = self.cfg.chain.best_snapshot();
            self.cfg
                .tx_mem_pool
                .prune_stake_tx(best.next_stake_diff, best.height);
            self.cfg.tx_mem_pool.prune_expired_tx(best.height);
        }

        Ok(())
    }

    /// Whether the manager believes it is synced with the connected
    /// peers (dcrd `IsCurrent`).
    pub fn is_current(&mut self) -> bool {
        self.maybe_update_is_current();
        self.is_current
    }
}

/// Add to a request map bounded by a maximum limit, evicting an
/// arbitrary entry when adding the new value would overflow it (dcrd
/// `limitAdd`, which evicts a random entry via Go's map iteration
/// order).
fn limit_add(m: &mut HashMap<Hash, i32>, hash: Hash, peer: i32, limit: usize) {
    // Replace existing entries.
    if let Some(entry) = m.get_mut(&hash) {
        *entry = peer;
        return;
    }
    if m.len() + 1 > limit
        && let Some(victim) = m.keys().next().copied()
    {
        m.remove(&victim);
    }
    m.insert(hash, peer);
}
