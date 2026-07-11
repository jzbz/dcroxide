// SPDX-License-Identifier: ISC
//! The server-handler dispatch for served peers — the daemon wiring of
//! dcrd `server.go`'s `serverPeer` message callbacks (`OnGetHeaders`,
//! `OnGetBlocks`, `OnGetData`) over the ported decision cores and the
//! shared chain.
//!
//! Each served connection gets a [`ServerPeerHandler`] holding the
//! per-peer server state dcrd keeps on `serverPeer` (the decaying ban
//! score, the getblocks continuation hash), sharing the daemon-wide
//! [`ServerContext`].  The handler runs on the peer's input thread and
//! queues responses through the peer's [`OutboundQueue`], so all writes
//! stay serialized on the output loop exactly like dcrd's `QueueMessage`.
//!
//! dcrd serves getdata batches asynchronously behind a semaphore and
//! pending-request counters; this synchronous translation serves each
//! batch inline on the input thread, so batches never overlap by
//! construction and the intake gates see zero prior pending requests.
//! The address/relay handlers (`OnAddr`, `OnGetAddr`, inventory relay),
//! the sync-manager forwards (`OnInv`, `OnHeaders`, block/tx intake),
//! and the mempool/mixpool-backed fetches arrive with later pieces;
//! messages without a handler are ignored, matching a dcrd node whose
//! subsystems simply have nothing to do.

use std::collections::HashMap;
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dcroxide_addrmgr::AddrManager;
use dcroxide_blockchain::process::Chain;
use dcroxide_chainhash::Hash;
use dcroxide_netsync::manager::Action;
use dcroxide_peer::{Peer, PeerEnv};
use dcroxide_uint256::Uint256;
use dcroxide_wire::{
    INIT_STATE_HEAD_BLOCK_VOTES, INIT_STATE_HEAD_BLOCKS, INIT_STATE_TSPENDS, InvType, InvVect,
    Message, MsgCFilterV2, MsgHeaders, MsgInitState, MsgInv, MsgNotFound,
};

use crate::peerconn::NodePeerEnv;
use crate::peerloop::{OutboundQueue, ServeSignal};
use crate::server::{
    GetAddrFacts, GetDataResolution, GetHeadersResponse, InitStateWants, MAX_BLOCKS_PER_MSG,
    OnAddrFacts, OnAddrOutcome, OnGetDataOutcome, OnGetInitStateOutcome, OnInvOutcome,
    PushAddrOutcome, ServeGetDataAction, ServerPeerAddrState, build_get_blocks_response,
    build_get_headers_response, natf_supported, on_addr, on_get_addr, on_get_data,
    on_get_init_state, on_inv_classify, serve_get_data,
};
use crate::sync::NodeSyncManager;

/// The daemon-wide state the server handlers consult, shared across
/// every served peer (the relevant slice of dcrd's `server`).
pub struct ServerContext {
    /// The chain instance answering block locator and fetch queries.
    pub chain: Arc<Mutex<Chain>>,
    /// The minimum known chain work from the network parameters; a
    /// best tip with less cumulative work answers getheaders with an
    /// empty message (dcrd `server.minKnownWork`, zero when the
    /// network defines none).
    pub min_known_work: Option<Uint256>,
    /// Whether banning misbehaving peers is disabled (`--nobanning`).
    pub disable_banning: bool,
    /// The ban score threshold (`--banthreshold`).
    pub ban_threshold: u32,
    /// The parsed whitelisted networks (`--whitelist`); peers matching
    /// one are exempt from banning.
    pub whitelists: Vec<crate::config::IpNet>,
    /// The address manager the addr exchange consults and feeds.
    pub addr_manager: Arc<Mutex<AddrManager>>,
    /// The network's stake validation height; a best tip below it
    /// answers getinitstate with an empty message.
    pub stake_validation_height: i64,
    /// Whether transaction and mix relay is disabled (`--blocksonly`);
    /// peers announcing either are disconnected.
    pub blocks_only: bool,
    /// Whether the simulation or regression test network is active;
    /// both suppress the address exchange entirely.
    pub sim_or_reg_net: bool,
    /// The sync manager tracking the header and block download state.
    pub sync_manager: Arc<Mutex<NodeSyncManager>>,
    /// The live peers' outbound queues and socket handles, keyed by
    /// the sync-manager peer id, so the manager's actions can reach
    /// any peer (dcrd resolves the same through its peer references).
    pub sync_peers: SyncPeers,
    /// The next sync-manager peer id (dcrd's peer package draws ids
    /// from a package-global atomic counter).
    pub next_peer_id: AtomicI32,
    /// The number of outbound peers connected per address group (dcrd
    /// `peerState.outboundGroups`), consulted by the automatic dialer
    /// so it spreads connections across network segments.
    pub outbound_groups: OutboundGroups,
    /// Whether the daemon accepts incoming connections (`--nolisten`);
    /// gates the local-address advertisement to outbound peers.
    pub disable_listen: bool,
    /// The server-wide wire byte totals every peer transport feeds
    /// (dcrd's `bytesReceived`/`bytesSent` pair; getnettotals serves
    /// them).
    pub net_totals: Arc<crate::transport::NetByteTotals>,
    /// The shared transaction memory pool the getdata and mempool
    /// handlers serve from.
    pub tx_pool: Arc<Mutex<crate::txmempool::NodeTxPool>>,
    /// The websocket notification manager fed on transaction
    /// acceptance; absent when the RPC server is disabled (dcrd's nil
    /// rpcServer checks).
    pub ntfn: Option<crate::websocket::NodeNtfnMgr>,
    /// Recently advertised transactions, kept servable briefly after
    /// leaving the pool (dcrd `recentlyAdvertisedTxns`).
    pub recently_advertised: Arc<Mutex<dcroxide_containers::lru::Map<Hash, dcroxide_wire::MsgTx>>>,
}

/// The maximum number of recently advertised transactions to track
/// (dcrd `maxRecentlyAdvertisedTxns`).
pub const MAX_RECENTLY_ADVERTISED_TXNS: u32 = 4500;

/// How long advertised transactions stay servable, in nanoseconds
/// (dcrd `recentlyAdvertisedTxnsTTL`).
pub const RECENTLY_ADVERTISED_TXNS_TTL_NANOS: i64 = 45 * 1_000_000_000;

/// A fresh recently-advertised transaction cache.
pub fn new_recently_advertised()
-> Arc<Mutex<dcroxide_containers::lru::Map<Hash, dcroxide_wire::MsgTx>>> {
    Arc::new(Mutex::new(
        dcroxide_containers::lru::Map::new_with_default_ttl(
            MAX_RECENTLY_ADVERTISED_TXNS,
            RECENTLY_ADVERTISED_TXNS_TTL_NANOS,
        ),
    ))
}

/// The per-group count of outbound connections (dcrd
/// `peerState.outboundGroups` behind the peer-state lock).
#[derive(Clone, Default)]
pub struct OutboundGroups {
    inner: Arc<Mutex<HashMap<String, i64>>>,
}

impl OutboundGroups {
    /// An empty tracker.
    pub fn new() -> OutboundGroups {
        OutboundGroups::default()
    }

    /// Record an outbound connection to the group (dcrd
    /// `handleAddPeer`'s increment).
    pub fn increment(&self, key: &str) {
        let mut groups = self.inner.lock().expect("outbound groups poisoned");
        let count = groups.entry(key.to_string()).or_insert(0);
        *count = count.saturating_add(1);
    }

    /// Record an outbound disconnection from the group (dcrd
    /// `handleDonePeer`'s decrement).
    pub fn decrement(&self, key: &str) {
        let mut groups = self.inner.lock().expect("outbound groups poisoned");
        if let Some(count) = groups.get_mut(key) {
            *count = count.saturating_sub(1);
            if *count <= 0 {
                groups.remove(key);
            }
        }
    }

    /// The number of outbound connections to the group (dcrd
    /// `OutboundGroupCount`).
    pub fn count(&self, key: &str) -> i64 {
        *self
            .inner
            .lock()
            .expect("outbound groups poisoned")
            .get(key)
            .unwrap_or(&0)
    }
}

/// The registry resolving sync-manager peer ids to the handles the
/// manager's actions need: the outbound queue for sends and the socket
/// for disconnects.
/// A registered peer's handles: the outbound queue for sends, the
/// socket for disconnects, the relay state the inventory fan-out
/// consults, the shared peer for live stat snapshots (`getpeerinfo`),
/// and the local connection address.
struct SyncPeerHandles {
    outbound: OutboundQueue,
    socket: Option<TcpStream>,
    relay: Arc<Mutex<RelayPeerState>>,
    peer: Arc<Mutex<Peer>>,
    local_addr: Option<String>,
}

/// The per-peer relay state (dcrd's `serverPeer` fields the relay
/// reads): the handshake facts, the last announced block, and the
/// known-inventory set that both dedups our announcements and
/// prevents echoing inventory the peer itself announced.
pub struct RelayPeerState {
    facts: crate::server::RelayPeerFacts,
    announced_block: Option<Hash>,
    known_inventory: dcroxide_containers::lru::Set<InvVect>,
}

impl RelayPeerState {
    /// Whether the peer disabled transaction relay in its version
    /// message (dcrd's `serverPeer.disableRelayTx`, reported inverted as
    /// `relaytxes` by `getpeerinfo`).
    pub(crate) fn tx_relay_disabled(&self) -> bool {
        self.facts.disable_relay_tx
    }

    /// The relay state for a freshly handshaken peer.
    pub(crate) fn new(facts: crate::server::RelayPeerFacts) -> RelayPeerState {
        RelayPeerState {
            facts,
            announced_block: None,
            known_inventory: dcroxide_containers::lru::Set::new_with_default_ttl(
                dcroxide_peer::MAX_KNOWN_INVENTORY,
                dcroxide_peer::MAX_KNOWN_INVENTORY_TTL,
            ),
        }
    }
}

/// The registry resolving sync-manager peer ids to their handles so
/// the manager's actions can reach any live peer.
#[derive(Clone, Default)]
pub struct SyncPeers {
    inner: Arc<Mutex<HashMap<i32, SyncPeerHandles>>>,
    /// The command channel of the header-sync stall timer, once it is
    /// started ([`start_stall_timer`] wires it back here).
    stall: Arc<Mutex<Option<mpsc::Sender<StallCommand>>>>,
}

impl SyncPeers {
    /// An empty registry.
    pub fn new() -> SyncPeers {
        SyncPeers::default()
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn register(
        &self,
        id: i32,
        outbound: OutboundQueue,
        socket: Option<TcpStream>,
        relay: Arc<Mutex<RelayPeerState>>,
        peer: Arc<Mutex<Peer>>,
        local_addr: Option<String>,
    ) {
        self.inner
            .lock()
            .expect("sync peers mutex poisoned")
            .insert(
                id,
                SyncPeerHandles {
                    outbound,
                    socket,
                    relay,
                    peer,
                    local_addr,
                },
            );
    }

    /// Snapshot every registered peer as an RPC peer-info record (dcrd's
    /// `rpcConnManager.ConnectedPeers` over the server's `peerState`).
    /// The registry lock is released before any peer or relay lock is
    /// taken — the entries are cloned out under the map lock, then each
    /// `Peer` and `RelayPeerState` is locked one at a time — so this
    /// never nests the map lock inside a peer lock and cannot invert the
    /// input thread's `Peer -> map -> relay` lock order; each per-peer
    /// lock is held only for the lock-free stat snapshot.
    pub(crate) fn connected_peer_infos(&self) -> Vec<dcroxide_rpc::server::RpcPeerInfo> {
        #[allow(clippy::type_complexity)]
        let entries: Vec<(
            i32,
            Arc<Mutex<Peer>>,
            Arc<Mutex<RelayPeerState>>,
            Option<String>,
        )> = {
            let registry = self.inner.lock().expect("sync peers mutex poisoned");
            registry
                .iter()
                .map(|(id, handles)| {
                    (
                        *id,
                        Arc::clone(&handles.peer),
                        Arc::clone(&handles.relay),
                        handles.local_addr.clone(),
                    )
                })
                .collect()
        };

        entries
            .into_iter()
            .filter_map(|(id, peer, relay, local_addr)| {
                // Skip a peer whose mutex is poisoned — its input thread
                // panicked, so it is effectively dead — rather than
                // propagating the poison and making every `getpeerinfo`
                // call panic (caught as an internal error) forever.
                let peer = peer.lock().ok()?;
                let snap = peer.stats_snapshot();
                // dcrd's `getpeerinfo` reports the version the peer
                // advertised, not the negotiated (capped) one.
                let advertised_version = peer.advertised_proto_ver();
                drop(peer);
                let tx_relay_disabled = relay
                    .lock()
                    .map(|relay| relay.tx_relay_disabled())
                    .unwrap_or(false);
                Some(dcroxide_rpc::server::RpcPeerInfo {
                    // The id is the registry key (the sync manager's peer
                    // id, the space `sync_peer_id` returns), not the
                    // snapshot's id which the peer never assigns.
                    id,
                    addr: snap.addr,
                    local_addr,
                    services: snap.services.0,
                    tx_relay_disabled,
                    // The peer tracks these as unix nanoseconds; the RPC
                    // result reports unix seconds.  They (and the byte
                    // counters) read zero until per-peer send/receive
                    // accounting is wired through the transport — a
                    // documented divergence from dcrd, which updates the
                    // peer's counters on every read and write.
                    last_send_unix: snap.last_send_nanos / 1_000_000_000,
                    last_recv_unix: snap.last_recv_nanos / 1_000_000_000,
                    bytes_sent: snap.bytes_sent,
                    bytes_recv: snap.bytes_recv,
                    conn_time_unix: snap.connected_nanos / 1_000_000_000,
                    time_offset: snap.time_offset,
                    version: advertised_version,
                    // `StatsSnap.version` is the user-agent string (dcrd's
                    // `subver`).
                    user_agent: snap.version,
                    inbound: snap.inbound,
                    starting_height: snap.starting_height,
                    last_block: snap.last_block,
                    // The live decaying ban score is not shared to the RPC
                    // seam yet; a well-behaved peer scores zero (a
                    // documented divergence from dcrd's `banScore.Int()`).
                    ban_score: 0,
                    last_ping_nonce: snap.last_ping_nonce,
                    // The handler feeds this straight to `clock.since_nanos`,
                    // so it stays in nanoseconds.
                    last_ping_time_unix_nanos: snap.last_ping_time_nanos,
                    last_ping_micros: snap.last_ping_micros,
                    connected: true,
                })
            })
            .collect()
    }

    /// Flip the peer's preference for header announcements (dcrd's
    /// `sendHeadersPreferred`, consulted as `WantsHeaders` by the
    /// relay).
    pub(crate) fn set_wants_headers(&self, id: i32) {
        let registry = self.inner.lock().expect("sync peers mutex poisoned");
        if let Some(handles) = registry.get(&id) {
            let mut relay = handles.relay.lock().expect("relay state poisoned");
            relay.facts.wants_headers = true;
        }
    }

    /// Mark inventory as known to the peer so the relay never echoes
    /// it back (dcrd `AddKnownInventory` on intake).
    pub(crate) fn mark_known_inventory(&self, id: i32, inv: InvVect) {
        let registry = self.inner.lock().expect("sync peers mutex poisoned");
        if let Some(handles) = registry.get(&id) {
            handles
                .relay
                .lock()
                .expect("relay state poisoned")
                .known_inventory
                .put(inv);
        }
    }

    /// Relay inventory to every registered peer that should receive it
    /// (dcrd `RelayInventory` driving `handleRelayPeerInvMsg`); the
    /// known-inventory set dedups repeated announcements.  dcrd's
    /// trickle queue batches non-immediate inventory over a short
    /// random window; the plain per-peer queue sends each announcement
    /// as its own message.
    pub fn relay_inventory(&self, msg: &crate::server::RelayInvFacts) {
        self.relay_to_peers(msg, None);
    }

    /// Announce a block to every registered peer with the required
    /// services (dcrd `RelayBlockAnnouncement` driving
    /// `handleRelayPeerInvMsg` with the header as the message data):
    /// peers that asked for headers get the header itself, the rest
    /// get the immediate inventory.
    pub fn relay_block_announcement(
        &self,
        header: &dcroxide_wire::BlockHeader,
        req_services: dcroxide_wire::ServiceFlag,
    ) {
        let msg = crate::server::RelayInvFacts {
            inv_type: InvType::BLOCK,
            inv_hash: header.block_hash(),
            req_services,
            immediate: true,
            data_is_block_header: true,
            data_is_tx: false,
        };
        self.relay_to_peers(&msg, Some(header));
    }

    fn relay_to_peers(
        &self,
        msg: &crate::server::RelayInvFacts,
        header: Option<&dcroxide_wire::BlockHeader>,
    ) {
        let registry = self.inner.lock().expect("sync peers mutex poisoned");
        for handles in registry.values() {
            let mut relay = handles.relay.lock().expect("relay state poisoned");
            let RelayPeerState {
                facts,
                announced_block,
                known_inventory,
            } = &mut *relay;
            let outcome = crate::server::handle_relay_peer_inv(announced_block, facts, msg);
            match outcome.action {
                crate::server::RelayPeerAction::Ignore => {}
                crate::server::RelayPeerAction::QueueHeaders => {
                    // The decision core only asks for headers when the
                    // announcement carries the header data (dcrd sends
                    // the headers message directly, bypassing the
                    // inventory queue and its known-inventory set).
                    if let Some(header) = header {
                        let _ = handles.outbound.queue_message(Message::Headers(
                            dcroxide_wire::MsgHeaders {
                                headers: vec![*header],
                            },
                        ));
                    }
                }
                crate::server::RelayPeerAction::QueueInventory
                | crate::server::RelayPeerAction::QueueInventoryImmediate => {
                    let inv = InvVect {
                        inv_type: msg.inv_type,
                        hash: msg.inv_hash,
                    };
                    if known_inventory.contains(&inv) {
                        continue;
                    }
                    known_inventory.put(inv);
                    let _ = handles.outbound.queue_message(Message::Inv(MsgInv {
                        inv_list: vec![inv],
                    }));
                }
            }
        }
    }

    fn deregister(&self, id: i32) {
        self.inner
            .lock()
            .expect("sync peers mutex poisoned")
            .remove(&id);
    }

    /// Forward a timer command to the stall timer when one is running
    /// (a closed or absent timer means shutdown is in progress).
    fn send_stall(&self, command: StallCommand) {
        if let Some(sender) = self.stall.lock().expect("stall sender poisoned").as_ref() {
            let _ = sender.send(command);
        }
    }

    /// Execute the sync manager's actions: queue messages on the
    /// targeted peers' outbound queues and interrupt disconnected
    /// peers' reads by shutting their sockets down.  The stall-timer
    /// actions are handled by the header-sync timer piece.
    fn execute(&self, actions: Vec<Action>) {
        let registry = self.inner.lock().expect("sync peers mutex poisoned");
        for action in actions {
            match action {
                Action::QueueMessage { peer, message } => {
                    if let Some(handles) = registry.get(&peer) {
                        let _ = handles.outbound.queue_message(message);
                    }
                }
                Action::Disconnect { peer } => {
                    if let Some(SyncPeerHandles {
                        socket: Some(socket),
                        ..
                    }) = registry.get(&peer)
                    {
                        let _ = socket.shutdown(Shutdown::Both);
                    }
                }
                Action::ResetHeaderSyncStallTimeout => self.send_stall(StallCommand::Reset),
                Action::StopHeaderSyncStallTimeout => self.send_stall(StallCommand::Stop),
            }
        }
    }
}

/// A command for the header-sync stall timer.
enum StallCommand {
    /// (Re)arm the timer (dcrd `headerSyncState.ResetStallTimeout`).
    Reset,
    /// Disarm the timer (dcrd `headerSyncState.StopStallTimeout`).
    Stop,
}

/// The running header-sync stall timer; dropping it (or calling
/// [`StallTimer::shutdown`]) stops the thread.
pub struct StallTimer {
    sender: mpsc::Sender<StallCommand>,
    /// The registry's sender slot, cleared on shutdown so every sender
    /// is gone and the thread's receive fails promptly.
    stall: Arc<Mutex<Option<mpsc::Sender<StallCommand>>>>,
    thread: Option<JoinHandle<()>>,
}

impl StallTimer {
    /// Stop the timer thread and wait for it to finish.
    pub fn shutdown(mut self) {
        self.stop_thread();
    }

    fn stop_thread(&mut self) {
        // Dropping every sender — the registry's clone and this
        // handle's own — makes the thread's receive fail, ending its
        // loop even while parked.
        *self.stall.lock().expect("stall sender poisoned") = None;
        let (closed, _) = mpsc::channel();
        self.sender = closed;
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for StallTimer {
    fn drop(&mut self) {
        self.stop_thread();
    }
}

/// Start the header-sync stall timer: a thread that, once armed by the
/// manager's reset action, fires the manager's stall handler after
/// `timeout` unless rearmed or stopped first, executing the disconnect
/// it decides (dcrd arms the same timeout around its `stallHandler`).
/// The timeout is injected so tests can shorten it; the daemon passes
/// [`dcroxide_netsync::manager::HEADER_SYNC_STALL_TIMEOUT_SECS`].
pub fn start_stall_timer(
    manager: Arc<Mutex<NodeSyncManager>>,
    peers: SyncPeers,
    timeout: Duration,
) -> StallTimer {
    let (sender, receiver) = mpsc::channel();
    let peers_stall = Arc::clone(&peers.stall);
    *peers_stall.lock().expect("stall sender poisoned") = Some(sender.clone());
    let thread = thread::spawn(move || {
        // Parked until a command arrives; armed while a deadline is set.
        let mut deadline: Option<Instant> = None;
        loop {
            let wait = match deadline {
                Some(deadline) => deadline.saturating_duration_since(Instant::now()),
                None => Duration::from_secs(3600),
            };
            match receiver.recv_timeout(wait) {
                Ok(StallCommand::Reset) => deadline = Instant::now().checked_add(timeout),
                Ok(StallCommand::Stop) => deadline = None,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // Fire only when actually armed; a parked wait that
                    // elapses just loops.
                    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                        deadline = None;
                        let actions = {
                            let mut manager = manager.lock().expect("sync manager poisoned");
                            manager.on_header_sync_stall_timeout()
                        };
                        peers.execute(actions);
                    }
                }
                // All senders dropped: the daemon is shutting down.
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
            }
        }
    });
    StallTimer {
        sender,
        stall: Arc::clone(&peers_stall),
        thread: Some(thread),
    }
}

/// The per-connection server state and message dispatch (the message
/// handling slice of dcrd's `serverPeer`).
pub struct ServerPeerHandler {
    ctx: Arc<ServerContext>,
    /// The peer's address-and-abuse bookkeeping (dcrd's per-peer
    /// `knownAddresses`/`banScore` state).
    addr_state: ServerPeerAddrState,
    /// The block hash of the final inventory of a full getblocks
    /// response; serving that block triggers a best-tip inventory to
    /// prompt the next batch (dcrd `serverPeer.continueHash`).
    continue_hash: Option<Hash>,
    /// The clock-and-randomness environment for the handlers.
    env: NodePeerEnv,
    /// Whether the init state was already sent on this connection
    /// (dcrd `serverPeer.initStateSent`).
    init_state_sent: bool,
    /// The sync-manager peer id once registered (dcrd `sp.syncMgrPeer`).
    sync_peer_id: Option<i32>,
    /// A socket handle handed to the registry so disconnect actions
    /// can interrupt this peer's read.
    socket: Option<TcpStream>,
}

impl ServerPeerHandler {
    /// Fresh per-peer server state (dcrd `newServerPeer`).
    pub fn new(
        ctx: Arc<ServerContext>,
        is_whitelisted: bool,
        socket: Option<TcpStream>,
    ) -> ServerPeerHandler {
        ServerPeerHandler {
            ctx,
            addr_state: ServerPeerAddrState::new(is_whitelisted),
            continue_hash: None,
            env: NodePeerEnv::new(),
            init_state_sent: false,
            sync_peer_id: None,
            socket,
        }
    }

    /// Register the handshaken peer with the sync manager and execute
    /// the actions it decides — for a data-serving peer on a stale
    /// chain this is where the header sync begins (dcrd `AddPeer`
    /// signalling `OnPeerConnected`).
    pub fn on_connected(
        &mut self,
        peer: &mut Peer,
        peer_handle: &Arc<Mutex<Peer>>,
        outbound: &OutboundQueue,
        remote_disable_relay_tx: bool,
    ) {
        // Update the address manager and request known addresses for
        // outbound connections, skipped on the simulation and
        // regression test networks (dcrd `OnVersion`'s outbound
        // branch).
        if !self.ctx.sim_or_reg_net && !peer.inbound() {
            let remote = crate::server::wire_to_addrmgr_net_address(peer.na());
            let mut mgr = self
                .ctx
                .addr_manager
                .lock()
                .expect("addrmgr mutex poisoned");

            // Advertise the local address when the server accepts
            // incoming connections and believes itself to be close to
            // the best known tip.
            let is_current = self
                .ctx
                .sync_manager
                .lock()
                .expect("sync manager poisoned")
                .is_current();
            if !self.ctx.disable_listen && is_current {
                let lna =
                    mgr.get_best_local_address(&remote, natf_supported(peer.protocol_version()));
                if lna.is_routable()
                    && let PushAddrOutcome::Queued(msg) = crate::server::push_addr_msg(
                        &mut self.addr_state,
                        peer,
                        &mut self.env,
                        &[lna],
                    )
                {
                    let _ = outbound.queue_message(*msg);
                }
            }

            // Request known addresses if the manager needs more.
            if mgr.need_more_addresses() {
                let _ = outbound.queue_message(Message::GetAddr);
            }

            // Mark the address as a known good address.
            let _ = mgr.good(&remote);
        }

        let id = self.ctx.next_peer_id.fetch_add(1, Ordering::SeqCst);
        self.sync_peer_id = Some(id);
        // The relay facts snapshot the handshake (dcrd reads them off
        // the live serverPeer; the headers preference is refreshed if
        // the peer later sends sendheaders).
        let relay = Arc::new(Mutex::new(RelayPeerState::new(
            crate::server::RelayPeerFacts {
                connected: true,
                services: peer.services(),
                wants_headers: peer.wants_headers(),
                disable_relay_tx: remote_disable_relay_tx,
                protocol_version: peer.protocol_version(),
            },
        )));
        // Capture the local connection address before the socket is
        // taken (getpeerinfo's `addrlocal`), and register the shared peer
        // for live stat snapshots.  `peer_handle` is only cloned here,
        // never locked: the caller already holds the peer guard across
        // this call, so locking the same mutex would self-deadlock.
        let local_addr = self
            .socket
            .as_ref()
            .and_then(|socket| socket.local_addr().ok())
            .map(|addr| addr.to_string());
        self.ctx.sync_peers.register(
            id,
            outbound.clone(),
            self.socket.take(),
            relay,
            Arc::clone(peer_handle),
            local_addr,
        );
        let actions = {
            let mut manager = self.ctx.sync_manager.lock().expect("sync manager poisoned");
            manager.on_peer_connected(dcroxide_netsync::manager::Peer::new(
                id,
                peer.inbound(),
                peer.services(),
                peer.protocol_version(),
                peer.last_block(),
            ))
        };
        self.ctx.sync_peers.execute(actions);
    }

    /// Deregister the departing peer from the sync manager, executing
    /// the re-request and sync-peer handoff actions it decides (dcrd
    /// `DonePeer` signalling `OnPeerDisconnected`).
    pub fn on_disconnected(&mut self, _peer: &mut Peer) {
        let Some(id) = self.sync_peer_id.take() else {
            return;
        };
        let actions = {
            let mut manager = self.ctx.sync_manager.lock().expect("sync manager poisoned");
            manager.on_peer_disconnected(id)
        };
        self.ctx.sync_peers.deregister(id);
        self.ctx.sync_peers.execute(actions);
    }

    /// Run a sync-manager intake for this registered peer and execute
    /// the actions it decides.
    fn drive_sync(&mut self, intake: impl FnOnce(&mut NodeSyncManager, i32) -> Vec<Action>) {
        let Some(id) = self.sync_peer_id else {
            return;
        };
        let actions = {
            let mut manager = self.ctx.sync_manager.lock().expect("sync manager poisoned");
            intake(&mut manager, id)
        };
        self.ctx.sync_peers.execute(actions);
    }

    /// Dispatch one incoming message to its server handler, queueing
    /// any responses to the peer (the `serverPeer` message listeners
    /// dcrd registers on the peer).
    pub fn handle_message(
        &mut self,
        peer: &mut Peer,
        msg: &Message,
        outbound: &OutboundQueue,
    ) -> ServeSignal {
        match msg {
            Message::GetHeaders(get_headers) => {
                self.on_get_headers(&get_headers.0, outbound);
                ServeSignal::Continue
            }
            Message::GetBlocks(get_blocks) => {
                self.on_get_blocks(peer, &get_blocks.0, outbound);
                ServeSignal::Continue
            }
            Message::GetData(get_data) => self.on_get_data(&get_data.inv_list, outbound),
            Message::GetAddr => {
                self.on_get_addr(peer, outbound);
                ServeSignal::Continue
            }
            Message::Addr(addr) => self.on_addr(peer, &addr.addr_list),
            Message::GetCFilterV2(get_cf) => {
                self.on_get_cfilter_v2(get_cf.block_hash, outbound);
                ServeSignal::Continue
            }
            Message::GetCFsV2(get_cfs) => {
                self.on_get_cfilters_v2(get_cfs.start_hash, get_cfs.end_hash, outbound);
                ServeSignal::Continue
            }
            Message::GetInitState(get_init) => {
                self.on_get_init_state(&get_init.types, outbound);
                ServeSignal::Continue
            }
            Message::Inv(inv) => {
                // Inventory the peer announces is known to it, so the
                // relay never echoes it back (dcrd `AddKnownInventory`).
                if let Some(id) = self.sync_peer_id {
                    for iv in &inv.inv_list {
                        self.ctx.sync_peers.mark_known_inventory(id, *iv);
                    }
                }
                self.on_inv(inv)
            }
            Message::Headers(headers) => {
                self.drive_sync(|manager, id| manager.on_headers(id, headers));
                ServeSignal::Continue
            }
            Message::Block(block) => {
                // The block the peer delivered is known to it, so the
                // announcement fan-out never echoes the inventory back
                // (dcrd `OnBlock`'s `AddKnownInventory` before the
                // sync-manager hand-off).
                if let Some(id) = self.sync_peer_id {
                    self.ctx.sync_peers.mark_known_inventory(
                        id,
                        InvVect {
                            inv_type: dcroxide_wire::InvType::BLOCK,
                            hash: block.header.block_hash(),
                        },
                    );
                }
                self.drive_sync(|manager, id| manager.on_block(id, block));
                ServeSignal::Continue
            }
            Message::Tx(tx) => {
                let mut accepted = Vec::new();
                self.drive_sync(|manager, id| {
                    accepted = manager.on_tx(id, tx);
                    Vec::new()
                });
                // dcrd's AnnounceNewTransactions: the websocket
                // notification half; the peer inventory relay arrives
                // with the relay fan-out piece.
                if !accepted.is_empty()
                    && let Some(ntfn) = &self.ctx.ntfn
                {
                    let pairs: Vec<(dcroxide_wire::MsgTx, i8)> = {
                        let pool = self.ctx.tx_pool.lock().expect("tx pool mutex poisoned");
                        accepted
                            .iter()
                            .filter_map(|hash| {
                                let tx = pool.fetch_transaction(hash)?;
                                let tree = if dcroxide_stake::determine_tx_type(&tx)
                                    == dcroxide_stake::TxType::Regular
                                {
                                    dcroxide_wire::TX_TREE_REGULAR
                                } else {
                                    dcroxide_wire::TX_TREE_STAKE
                                };
                                Some((tx, tree))
                            })
                            .collect()
                    };
                    ntfn.notify_new_transactions(pairs);
                }
                // The inventory half of dcrd's AnnounceNewTransactions:
                // the source peer already knows the transaction, and
                // every accepted transaction joins the
                // recently-advertised cache before fanning out.
                for hash in &accepted {
                    let inv = InvVect {
                        inv_type: InvType::TX,
                        hash: *hash,
                    };
                    if let Some(id) = self.sync_peer_id {
                        self.ctx.sync_peers.mark_known_inventory(id, inv);
                    }
                    let fetched = {
                        let pool = self.ctx.tx_pool.lock().expect("tx pool mutex poisoned");
                        pool.fetch_transaction(hash)
                    };
                    if let Some(tx) = fetched {
                        self.ctx
                            .recently_advertised
                            .lock()
                            .expect("recently advertised poisoned")
                            .put(*hash, tx);
                    }
                    self.ctx
                        .sync_peers
                        .relay_inventory(&crate::server::RelayInvFacts {
                            inv_type: InvType::TX,
                            inv_hash: *hash,
                            req_services: dcroxide_wire::ServiceFlag(0),
                            immediate: false,
                            data_is_block_header: false,
                            data_is_tx: true,
                        });
                }
                ServeSignal::Continue
            }
            Message::MemPool => {
                // Serve the pool's inventory (dcrd `OnMemPool`); the
                // flood guard applies its decaying ban score.
                let tx_hashes = {
                    let pool = self.ctx.tx_pool.lock().expect("tx pool mutex poisoned");
                    pool.tx_hashes()
                };
                match crate::server::on_mem_pool(
                    &mut self.addr_state,
                    &tx_hashes,
                    self.ctx.disable_banning,
                    self.ctx.ban_threshold,
                    now_unix(),
                ) {
                    crate::server::OnMemPoolOutcome::Banned => {
                        ServeSignal::Disconnect("ban score exceeds threshold")
                    }
                    crate::server::OnMemPoolOutcome::Inventory(invs) => {
                        // dcrd trickles through its inventory queue,
                        // which splits at the wire limit; the plain
                        // queue chunks the same way.
                        for chunk in invs.chunks(dcroxide_wire::MAX_INV_PER_MSG as usize) {
                            if chunk.is_empty() {
                                continue;
                            }
                            let _ = outbound.queue_message(Message::Inv(MsgInv {
                                inv_list: chunk.to_vec(),
                            }));
                        }
                        ServeSignal::Continue
                    }
                }
            }
            Message::SendHeaders => {
                // The peer prefers header announcements over invs from
                // now on (dcrd's peer marking `sendHeadersPreferred`
                // on the sendheaders message).
                if let Some(id) = self.sync_peer_id {
                    self.ctx.sync_peers.set_wants_headers(id);
                }
                ServeSignal::Continue
            }
            // The mix-message intake arrives with the mixpool wiring.
            _ => ServeSignal::Continue,
        }
    }

    /// Answer a getheaders request with the located headers, or with an
    /// empty headers message when the local best tip has too little
    /// cumulative work to be worth following (dcrd
    /// `serverPeer.OnGetHeaders`).
    fn on_get_headers(&self, locator: &dcroxide_wire::BlockLocator, outbound: &OutboundQueue) {
        let (work, located) = {
            let chain = self.ctx.chain.lock().expect("chain mutex poisoned");
            let best_hash = chain.best_snapshot().hash;
            (
                chain.chain_work(&best_hash),
                chain.locate_headers(&locator.block_locator_hashes, &locator.hash_stop),
            )
        };
        let min_known_work = self.ctx.min_known_work.unwrap_or_default();
        let tip_work_below_min = work.map(|work| work < min_known_work).unwrap_or(false);
        let headers = match build_get_headers_response(work.is_none(), tip_work_below_min, located)
        {
            GetHeadersResponse::Empty => Vec::new(),
            GetHeadersResponse::Headers(headers) => headers,
        };
        let _ = outbound.queue_message(Message::Headers(MsgHeaders { headers }));
    }

    /// Answer a getblocks request with the located block inventory,
    /// recording the continuation hash when the response fills an
    /// entire message (dcrd `serverPeer.OnGetBlocks`).
    fn on_get_blocks(
        &mut self,
        peer: &mut Peer,
        locator: &dcroxide_wire::BlockLocator,
        outbound: &OutboundQueue,
    ) {
        let located = {
            let chain = self.ctx.chain.lock().expect("chain mutex poisoned");
            chain.locate_blocks(
                &locator.block_locator_hashes,
                &locator.hash_stop,
                MAX_BLOCKS_PER_MSG as u32,
            )
        };
        // The known-inventory check touches the peer's LRU, so route the
        // shared reference through a cell for the decision core's `Fn`
        // seam.
        let peer = std::cell::RefCell::new(peer);
        let response =
            build_get_blocks_response(&located, |iv| peer.borrow_mut().is_known_inventory(iv));
        if let Some(continue_hash) = response.continue_hash {
            self.continue_hash = Some(continue_hash);
        }
        if !response.inv.is_empty() {
            let _ = outbound.queue_message(Message::Inv(MsgInv {
                inv_list: response.inv,
            }));
        }
    }

    /// Gate and serve a getdata request: apply dcrd's intake gates
    /// (ban empty requests, the decaying oversized-request ban score,
    /// the pending-request limits), then serve the batch inline —
    /// blocks from the chain, everything else answered in the
    /// consolidated notfound since the mempool and mix pool are not
    /// yet wired (matching a node whose pools are empty), and unknown
    /// inventory types skipped entirely (dcrd `serverPeer.OnGetData`
    /// plus `handleServeGetData`).
    fn on_get_data(&mut self, inv_list: &[InvVect], outbound: &OutboundQueue) -> ServeSignal {
        // The synchronous translation serves each batch before the next
        // getdata is read, so there are never prior pending requests.
        let outcome = on_get_data(
            &mut self.addr_state,
            inv_list.len() as u32,
            0,
            0,
            self.ctx.disable_banning,
            self.ctx.ban_threshold,
            now_unix(),
        );
        match outcome {
            // The ban outcomes drop the connection; the ban-list
            // bookkeeping refusing reconnects arrives with the
            // peer-state wiring.
            OnGetDataOutcome::BanEmpty => {
                return ServeSignal::Disconnect("sent an empty getdata request");
            }
            OnGetDataOutcome::BanScore => {
                return ServeSignal::Disconnect("ban score exceeds threshold");
            }
            OnGetDataOutcome::DisconnectConcurrent => {
                return ServeSignal::Disconnect("too many concurrent getdata requests");
            }
            OnGetDataOutcome::DisconnectPendingItems => {
                return ServeSignal::Disconnect("too many pending getdata item requests");
            }
            OnGetDataOutcome::Enqueue { .. } => {}
        }

        // Resolve each item against the chain, keeping the fetched
        // blocks so the serve actions can queue them in request order.
        let mut blocks = HashMap::new();
        let mut txs: HashMap<dcroxide_chainhash::Hash, dcroxide_wire::MsgTx> = HashMap::new();
        let (items, best_hash) = {
            let chain = self.ctx.chain.lock().expect("chain mutex poisoned");
            let items: Vec<(InvVect, GetDataResolution)> = inv_list
                .iter()
                .map(|iv| {
                    let resolution = match iv.inv_type {
                        InvType::BLOCK => match chain.block_by_hash(&iv.hash) {
                            Some(block) => {
                                blocks.insert(iv.hash, block);
                                GetDataResolution::Found
                            }
                            None => GetDataResolution::NotFound,
                        },
                        // Transactions and mix messages resolve against
                        // pools that are not yet wired, so they miss
                        // exactly like an empty mempool's fetch.
                        // Transactions serve from the mempool only:
                        // confirmed transactions are deliberately not
                        // servable over the network (dcrd's
                        // handleServeGetData; the recently-advertised
                        // cache arrives with the relay fan-out).
                        InvType::TX => {
                            // The recently-advertised cache serves
                            // first so announcements stay servable
                            // briefly after leaving the pool (dcrd's
                            // handleServeGetData order).
                            let advertised = self
                                .ctx
                                .recently_advertised
                                .lock()
                                .expect("recently advertised poisoned")
                                .get(&iv.hash);
                            let fetched = advertised.or_else(|| {
                                let pool = self.ctx.tx_pool.lock().expect("tx pool mutex poisoned");
                                pool.fetch_transaction(&iv.hash)
                            });
                            match fetched {
                                Some(tx) => {
                                    txs.insert(iv.hash, tx);
                                    GetDataResolution::Found
                                }
                                None => GetDataResolution::NotFound,
                            }
                        }
                        // Mix messages resolve against a pool that is
                        // not yet wired, so they miss exactly like an
                        // empty mixpool's fetch.
                        InvType::MIX => GetDataResolution::NotFound,
                        _ => GetDataResolution::UnknownType,
                    };
                    (*iv, resolution)
                })
                .collect();
            (items, chain.best_snapshot().hash)
        };

        let outcome = serve_get_data(&items, self.continue_hash, best_hash);
        for action in outcome.actions {
            let queued = match action {
                ServeGetDataAction::QueueData(iv) => {
                    if let Some(block) = blocks.remove(&iv.hash) {
                        outbound.queue_message(Message::Block(block))
                    } else if let Some(tx) = txs.remove(&iv.hash) {
                        outbound.queue_message(Message::Tx(tx))
                    } else {
                        Ok(())
                    }
                }
                ServeGetDataAction::QueueContinueInv(best) => {
                    outbound.queue_message(Message::Inv(MsgInv {
                        inv_list: vec![InvVect {
                            inv_type: InvType::BLOCK,
                            hash: best,
                        }],
                    }))
                }
                ServeGetDataAction::QueueNotFound(inv_list) => {
                    outbound.queue_message(Message::NotFound(MsgNotFound { inv_list }))
                }
            };
            if queued.is_err() {
                // The output loop already stopped; the input loop will
                // observe the teardown on its next read.
                return ServeSignal::Continue;
            }
        }
        if outcome.cleared_continue_hash {
            self.continue_hash = None;
        }
        ServeSignal::Continue
    }
}

impl ServerPeerHandler {
    /// Answer a getaddr request with a randomized subset of the address
    /// cache, once per connection and only for inbound peers (dcrd
    /// `serverPeer.OnGetAddr` over `pushAddrMsg`).
    fn on_get_addr(&mut self, peer: &mut Peer, outbound: &OutboundQueue) {
        let facts = GetAddrFacts {
            sim_or_reg_net: self.ctx.sim_or_reg_net,
            inbound: peer.inbound(),
        };
        let addr_cache = {
            let mut mgr = self
                .ctx
                .addr_manager
                .lock()
                .expect("addrmgr mutex poisoned");
            mgr.address_cache(natf_supported(peer.protocol_version()))
        };
        if let Some(PushAddrOutcome::Queued(msg)) = on_get_addr(
            &mut self.addr_state,
            peer,
            &mut self.env,
            &facts,
            &addr_cache,
        ) {
            let _ = outbound.queue_message(*msg);
        }
    }

    /// Track and forward advertised addresses to the address manager,
    /// banning a peer that sends an empty list (dcrd
    /// `serverPeer.OnAddr`).
    fn on_addr(&mut self, peer: &mut Peer, addr_list: &[dcroxide_wire::NetAddress]) -> ServeSignal {
        let facts = OnAddrFacts {
            sim_or_reg_net: self.ctx.sim_or_reg_net,
            // The synchronous handler runs on the connection's own
            // input thread, so the peer is connected by construction.
            connected: true,
            peer_na: *peer.na(),
        };
        let now_nanos = self.env.now_nanos();
        let mut mgr = self
            .ctx
            .addr_manager
            .lock()
            .expect("addrmgr mutex poisoned");
        match on_addr(&mut self.addr_state, &mut mgr, &facts, addr_list, now_nanos) {
            // The ban outcome drops the connection; the ban-list
            // bookkeeping arrives with the peer-state wiring.
            OnAddrOutcome::BanEmptyList => ServeSignal::Disconnect("sent an empty address list"),
            OnAddrOutcome::Ignored | OnAddrOutcome::Processed => ServeSignal::Continue,
        }
    }
}

impl ServerPeerHandler {
    /// Gate an inventory announcement: ban empty announcements, and in
    /// blocks-only mode disconnect peers announcing transactions or
    /// mix messages (dcrd `serverPeer.OnInv`).  Announcements that
    /// pass forward to the sync manager, whose driver arrives with the
    /// netsync pieces.
    fn on_inv(&mut self, inv: &MsgInv) -> ServeSignal {
        let inv_types: Vec<InvType> = inv.inv_list.iter().map(|iv| iv.inv_type).collect();
        match on_inv_classify(&inv_types, self.ctx.blocks_only) {
            // The ban outcome drops the connection; the ban-list
            // bookkeeping arrives with the peer-state wiring.
            OnInvOutcome::BanEmpty => ServeSignal::Disconnect("sent empty inventory announcement"),
            OnInvOutcome::DisconnectAnnouncement("transactions") => {
                ServeSignal::Disconnect("announcing transactions in blocks-only mode")
            }
            OnInvOutcome::DisconnectAnnouncement(_) => {
                ServeSignal::Disconnect("announcing mix messages in blocks-only mode")
            }
            OnInvOutcome::Forward => {
                self.drive_sync(|manager, id| manager.on_inv(id, inv));
                ServeSignal::Continue
            }
        }
    }

    /// Serve a version 2 committed filter with its inclusion proof,
    /// silently ignoring requests for unknown blocks or missing
    /// filters (dcrd `serverPeer.OnGetCFilterV2`).
    fn on_get_cfilter_v2(&self, block_hash: Hash, outbound: &OutboundQueue) {
        let fetched = {
            let chain = self.ctx.chain.lock().expect("chain mutex poisoned");
            chain.filter_by_block_hash(&block_hash)
        };
        let Ok((filter, proof)) = fetched else {
            return;
        };
        let _ = outbound.queue_message(Message::CFilterV2(MsgCFilterV2 {
            block_hash,
            data: filter.bytes().to_vec(),
            proof_index: proof.proof_index,
            proof_hashes: proof.proof_hashes,
        }));
    }

    /// Serve the batched committed filters for an ancestry range,
    /// silently ignoring invalid ranges (dcrd
    /// `serverPeer.OnGetCFiltersV2`).
    fn on_get_cfilters_v2(&self, start_hash: Hash, end_hash: Hash, outbound: &OutboundQueue) {
        let located = {
            let chain = self.ctx.chain.lock().expect("chain mutex poisoned");
            chain.locate_cfilters_v2(&start_hash, &end_hash)
        };
        let Ok(filters) = located else {
            return;
        };
        let _ = outbound.queue_message(Message::CFiltersV2(filters));
    }

    /// Answer a getinitstate request once per connection (dcrd
    /// `serverPeer.OnGetInitState`).  Before stake validation the
    /// response is the empty message; past it, the eligible head
    /// blocks, their votes, and the treasury spends come from the
    /// mempool and tip generation, which are not yet wired, so the
    /// filled response is empty until then (the daemon cannot sync
    /// past stake validation before the sync manager lands).
    fn on_get_init_state(&mut self, types: &[String], outbound: &OutboundQueue) {
        let wants = InitStateWants {
            blocks: types.iter().any(|t| t == INIT_STATE_HEAD_BLOCKS),
            votes: types.iter().any(|t| t == INIT_STATE_HEAD_BLOCK_VOTES),
            tspends: types.iter().any(|t| t == INIT_STATE_TSPENDS),
        };
        let best_height = {
            let chain = self.ctx.chain.lock().expect("chain mutex poisoned");
            chain.best_snapshot().height
        };
        let outcome = on_get_init_state(
            self.init_state_sent,
            best_height,
            self.ctx.stake_validation_height,
            wants,
            &[],
            |_| Vec::new(),
            &[],
        );
        if matches!(outcome, OnGetInitStateOutcome::AlreadySent) {
            return;
        }
        // dcrd marks the state sent right after the gate, before any
        // reply is built, so even a dropped over-limit response counts.
        self.init_state_sent = true;
        let msg = match outcome {
            OnGetInitStateOutcome::AlreadySent => unreachable!("handled above"),
            OnGetInitStateOutcome::Blank => MsgInitState::default(),
            OnGetInitStateOutcome::Filled {
                block_hashes,
                vote_hashes,
                tspend_hashes,
            } => MsgInitState {
                block_hashes,
                vote_hashes,
                tspend_hashes,
            },
            OnGetInitStateOutcome::BuildError => return,
        };
        let _ = outbound.queue_message(Message::InitState(msg));
    }
}

/// The current unix time in seconds for the decaying ban score (dcrd's
/// `time.Now()` at the score sites).
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay_facts(disable_relay_tx: bool) -> crate::server::RelayPeerFacts {
        crate::server::RelayPeerFacts {
            connected: true,
            services: dcroxide_wire::ServiceFlag(0),
            wants_headers: false,
            disable_relay_tx,
            protocol_version: dcroxide_wire::PROTOCOL_VERSION,
        }
    }

    /// A shared inbound peer with no I/O, standing in for a live
    /// connection's `Arc<Mutex<Peer>>` in the registry.
    fn test_peer_handle() -> Arc<Mutex<Peer>> {
        Arc::new(Mutex::new(Peer::new_inbound(
            dcroxide_peer::Config::default(),
        )))
    }

    fn tx_inv(byte: u8) -> InvVect {
        InvVect {
            inv_type: InvType::TX,
            hash: Hash([byte; 32]),
        }
    }

    fn tx_relay_msg(inv: &InvVect) -> crate::server::RelayInvFacts {
        crate::server::RelayInvFacts {
            inv_type: inv.inv_type,
            inv_hash: inv.hash,
            req_services: dcroxide_wire::ServiceFlag(0),
            immediate: false,
            data_is_block_header: false,
            data_is_tx: true,
        }
    }

    /// The fan-out relays a transaction announcement to relay-enabled
    /// peers only, dedups repeats through the known-inventory set, and
    /// never echoes inventory a peer already knows.
    #[test]
    fn relays_tx_inventory_with_dedup_and_relay_preference() {
        let peers = SyncPeers::new();
        let (queue_a, rx_a) = crate::peerloop::OutboundQueue::channel();
        let (queue_b, rx_b) = crate::peerloop::OutboundQueue::channel();
        peers.register(
            1,
            queue_a,
            None,
            Arc::new(Mutex::new(RelayPeerState::new(relay_facts(false)))),
            test_peer_handle(),
            None,
        );
        peers.register(
            2,
            queue_b,
            None,
            Arc::new(Mutex::new(RelayPeerState::new(relay_facts(true)))),
            test_peer_handle(),
            None,
        );

        // Relay reaches the relay-enabled peer only.
        let inv = tx_inv(0x01);
        peers.relay_inventory(&tx_relay_msg(&inv));
        match rx_a.try_recv().expect("peer 1 receives the inv") {
            Message::Inv(msg) => assert_eq!(msg.inv_list, vec![inv]),
            other => panic!("expected inv, got {other:?}"),
        }
        assert!(rx_b.try_recv().is_err(), "relay-disabled peer gets nothing");

        // Repeats dedup through the known-inventory set.
        peers.relay_inventory(&tx_relay_msg(&inv));
        assert!(rx_a.try_recv().is_err(), "repeat announcements dedup");

        // Inventory the peer announced itself is never echoed back.
        let echoed = tx_inv(0x02);
        peers.mark_known_inventory(1, echoed);
        peers.relay_inventory(&tx_relay_msg(&echoed));
        assert!(rx_a.try_recv().is_err(), "announced inventory not echoed");
    }

    /// `connected_peer_infos` snapshots each registered peer for
    /// `getpeerinfo`: the id is the registry key (not the snapshot's
    /// always-zero id), the nanosecond stat times fold to unix seconds,
    /// the byte counters pass through, the local address is carried, and
    /// tx-relay-disabled is read from the relay facts.
    #[test]
    fn connected_peer_infos_snapshots_registered_peers() {
        let peers = SyncPeers::new();
        let (queue, _rx) = crate::peerloop::OutboundQueue::channel();

        let handle = test_peer_handle();
        {
            let mut peer = handle.lock().expect("peer");
            peer.record_send(1000, 5_000_000_000);
            peer.record_recv(2000, 9_000_000_000);
        }

        // Register under a non-1 id to prove the id comes from the key,
        // not the snapshot (whose id the peer never assigns).
        peers.register(
            42,
            queue,
            None,
            Arc::new(Mutex::new(RelayPeerState::new(relay_facts(true)))),
            handle,
            Some("127.0.0.1:9108".to_string()),
        );

        let infos = peers.connected_peer_infos();
        assert_eq!(infos.len(), 1);
        let info = &infos[0];
        assert_eq!(info.id, 42, "id is the registry key, not the snapshot's 0");
        assert_eq!(info.local_addr.as_deref(), Some("127.0.0.1:9108"));
        assert!(info.tx_relay_disabled, "read from the relay facts");
        assert_eq!(info.bytes_sent, 1000);
        assert_eq!(info.bytes_recv, 2000);
        assert_eq!(info.last_send_unix, 5, "5e9 nanoseconds folds to 5 seconds");
        assert_eq!(info.last_recv_unix, 9);
        assert!(info.inbound, "a new_inbound peer");
        assert!(info.connected);
        assert_eq!(info.ban_score, 0, "documented v1 divergence");
        // `version` is the numeric advertised protocol version (0 here,
        // never negotiated), and `user_agent` is the version string — the
        // two are not swapped.  A fresh peer's negotiated protocol version
        // defaults nonzero, so a zero here proves the advertised field is
        // the source.
        assert_eq!(info.version, 0, "the advertised protocol version");
        assert_eq!(info.user_agent, "", "the user-agent string");
    }

    /// A deregistered peer vanishes from `getpeerinfo`: the disconnect
    /// path removes the whole registry entry, dropping its `Arc<Peer>` so
    /// it is neither reported nor kept alive.
    #[test]
    fn deregister_removes_the_peer_from_connected_peer_infos() {
        let peers = SyncPeers::new();
        let (queue, _rx) = crate::peerloop::OutboundQueue::channel();
        peers.register(
            9,
            queue,
            None,
            Arc::new(Mutex::new(RelayPeerState::new(relay_facts(false)))),
            test_peer_handle(),
            None,
        );
        assert_eq!(
            peers.connected_peer_infos().len(),
            1,
            "the peer is reported"
        );

        peers.deregister(9);
        assert!(
            peers.connected_peer_infos().is_empty(),
            "a departed peer vanishes from getpeerinfo"
        );
    }

    fn full_node_facts() -> crate::server::RelayPeerFacts {
        crate::server::RelayPeerFacts {
            connected: true,
            services: dcroxide_wire::ServiceFlag::NODE_NETWORK,
            wants_headers: false,
            disable_relay_tx: false,
            protocol_version: dcroxide_wire::PROTOCOL_VERSION,
        }
    }

    fn announce_header() -> dcroxide_wire::BlockHeader {
        dcroxide_wire::BlockHeader {
            version: 1,
            prev_block: Hash([0x11; 32]),
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
            height: 5,
            size: 0,
            timestamp: 0,
            nonce: 0,
            extra_data: [0u8; 32],
            stake_version: 0,
        }
    }

    /// Block announcements honor the required services, the headers
    /// preference, the per-peer announced-block toggle across the
    /// checked and accepted passes, and the known-inventory dedup
    /// (dcrd's `handleRelayPeerInvMsg` block branch).
    #[test]
    fn announces_blocks_with_headers_preference_and_dedup() {
        let peers = SyncPeers::new();
        let (queue_inv, rx_inv) = crate::peerloop::OutboundQueue::channel();
        let (queue_hdr, rx_hdr) = crate::peerloop::OutboundQueue::channel();
        let (queue_lite, rx_lite) = crate::peerloop::OutboundQueue::channel();
        peers.register(
            1,
            queue_inv,
            None,
            Arc::new(Mutex::new(RelayPeerState::new(full_node_facts()))),
            test_peer_handle(),
            None,
        );
        peers.register(
            2,
            queue_hdr,
            None,
            Arc::new(Mutex::new(RelayPeerState::new(full_node_facts()))),
            test_peer_handle(),
            None,
        );
        peers.register(
            3,
            queue_lite,
            None,
            Arc::new(Mutex::new(RelayPeerState::new(relay_facts(false)))),
            test_peer_handle(),
            None,
        );
        peers.set_wants_headers(2);

        let header = announce_header();
        let block_hash = header.block_hash();
        let inv = InvVect {
            inv_type: dcroxide_wire::InvType::BLOCK,
            hash: block_hash,
        };

        // The checked pass reaches full nodes only: the inv peer gets
        // the immediate inventory, the headers peer the header itself.
        peers.relay_block_announcement(&header, dcroxide_wire::ServiceFlag::NODE_NETWORK);
        match rx_inv.try_recv().expect("full node receives the inv") {
            Message::Inv(msg) => assert_eq!(msg.inv_list, vec![inv]),
            other => panic!("expected inv, got {other:?}"),
        }
        match rx_hdr.try_recv().expect("headers peer receives headers") {
            Message::Headers(msg) => assert_eq!(msg.headers, vec![header]),
            other => panic!("expected headers, got {other:?}"),
        }
        assert!(
            rx_lite.try_recv().is_err(),
            "peer without the required services skipped"
        );

        // The accepted pass reaches everyone; the already-announced
        // peers dedup through the announced-block toggle.
        peers.relay_block_announcement(&header, dcroxide_wire::ServiceFlag(0));
        assert!(rx_inv.try_recv().is_err(), "announced toggle suppresses");
        assert!(rx_hdr.try_recv().is_err(), "announced toggle suppresses");
        match rx_lite.try_recv().expect("light peer now receives the inv") {
            Message::Inv(msg) => assert_eq!(msg.inv_list, vec![inv]),
            other => panic!("expected inv, got {other:?}"),
        }

        // A third announcement of the same block toggles the marker
        // back on: the inv peers dedup through known inventory while
        // the headers path, which never records inventory, sends the
        // headers again (dcrd's toggle semantics kept bug for bug).
        peers.relay_block_announcement(&header, dcroxide_wire::ServiceFlag(0));
        assert!(rx_inv.try_recv().is_err(), "known inventory dedups");
        match rx_hdr.try_recv().expect("headers peer receives again") {
            Message::Headers(msg) => assert_eq!(msg.headers, vec![header]),
            other => panic!("expected headers, got {other:?}"),
        }
        assert!(rx_lite.try_recv().is_err(), "announced toggle suppresses");
    }
}
