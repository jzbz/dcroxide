// SPDX-License-Identifier: ISC
//! Server-handler behaviour pinned against dcrd's `serverPeer`, driven
//! directly on a genesis-chain server context:
//!
//! - `OnVersion` feeds the server's median time source, so the
//!   adjusted time every consensus and sync check reads follows the
//!   connected peers' clocks as dcrd's does.
//! - The outbound branch of peer registration reads the sync state
//!   before it locks the address manager, as dcrd's `handleAddPeer`
//!   holds no address-manager lock across `IsCurrent`.
//! - A registered peer is keyed by the id its version read assigned
//!   (dcrd's `nodeCount`), so peers rejected after that read still use
//!   one up, as `getpeerinfo` and `node disconnect` see in dcrd.
//! - Transaction and mix validation run with the sync-manager lock
//!   released, as dcrd's `OnTx` and `OnMixMsg` hold only `requestMtx`
//!   around their bookkeeping.
//! - The getminingstate, getinitstate and mempool handlers apply dcrd's
//!   bans and early returns before they touch the chain or the mempool.

use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use dcroxide_blockchain::process::Chain;
use dcroxide_database::{Database, Options};
use dcroxide_node::dispatch::{ServerContext, ServerPeerHandler};
use dcroxide_node::peerconn::{NodePeerEnv, net_address_v2_from_socket};
use dcroxide_node::peerloop::{OutboundQueue, ServeSignal};
use dcroxide_peer::{Config, MsgTransport, Peer, PeerEnv, PeerGlobals, ReadError};
use dcroxide_wire::{
    CurrencyNet, INIT_STATE_HEAD_BLOCK_VOTES, INIT_STATE_HEAD_BLOCKS, INIT_STATE_TSPENDS, Message,
    MixPairReqUTXO, MsgGetInitState, MsgInitState, MsgMixPairReq, MsgTx, MsgVersion, NetAddress,
    OutPoint, PROTOCOL_VERSION, ServiceFlag,
};

const NET: CurrencyNet = CurrencyNet::TEST_NET3;

/// A server context over a fresh genesis chain.  The temporary directory
/// is returned with it so it outlives the chain and the address manager.
fn genesis_server() -> (tempfile::TempDir, Arc<ServerContext>) {
    let params = dcroxide_chaincfg::testnet3_params();
    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain"),
    ));
    let tx_pool = dcroxide_node::txmempool::new_shared_tx_pool(
        Arc::clone(&chain),
        &params,
        false,
        100,
        10000,
        false,
        false,
    );
    let server = Arc::new(ServerContext {
        external_addr_candidates: Mutex::new(Default::default()),
        external_addr_facts: dcroxide_node::server::ExternalAddrFacts {
            listeners: Vec::new(),
            has_proxy: false,
            no_discover_ip: true,
            has_external_ips: false,
            listen_disabled: false,
            sim_or_reg_net: false,
            services: ServiceFlag::NODE_NETWORK,
            target_outbound: 8,
        },
        lookup: Box::new(|_| Err("no resolver in tests".to_string())),
        target_outbound: 8,
        chain: Arc::clone(&chain),
        min_known_work: params.min_known_chain_work,
        params: params.clone(),
        disable_banning: false,
        ban_threshold: 100,
        whitelists: Vec::new(),
        banned_hosts: Mutex::new(std::collections::BTreeMap::new()),
        ban_duration_nanos: 24 * 60 * 60 * 1_000_000_000,
        addr_manager: Arc::new(Mutex::new(dcroxide_addrmgr::AddrManager::new(dir.path()))),
        sim_or_reg_net: false,
        stake_validation_height: params.stake_validation_height,
        blocks_only: false,
        sync_manager: Arc::new(Mutex::new(dcroxide_node::sync::new_sync_manager(
            Arc::clone(&chain),
            &params,
            false,
            8,
            1000,
            Arc::clone(&tx_pool),
            dcroxide_node::mixnode::shared_mix_pool(Arc::clone(&chain), params.clone(), &tx_pool),
        ))),
        sync_peers: dcroxide_node::dispatch::SyncPeers::new(),
        net_totals: Arc::new(dcroxide_node::transport::NetByteTotals::new()),
        disable_listen: false,
        tx_pool: Arc::clone(&tx_pool),
        ntfn: None,
        recently_advertised: dcroxide_node::dispatch::new_recently_advertised(),
        mix_pool: dcroxide_node::mixnode::shared_mix_pool(
            Arc::clone(&chain),
            params.clone(),
            &tx_pool,
        ),
    });
    (dir, server)
}

fn peer_config() -> Config {
    Config {
        net: NET,
        services: ServiceFlag::NODE_NETWORK,
        user_agent_name: "review".to_string(),
        user_agent_version: "0.1.0".to_string(),
        protocol_version: 0,
        ..Config::default()
    }
}

/// An associated peer at a routable address, in either direction.
fn peer_at(addr: &str, inbound: bool) -> Peer {
    let mut peer = if inbound {
        Peer::new_inbound(peer_config())
    } else {
        Peer::new_outbound(peer_config(), addr).expect("outbound peer")
    };
    let na = net_address_v2_from_socket(addr.parse().expect("socket address"), ServiceFlag(0))
        .expect("net address");
    peer.associate(addr, na, NodePeerEnv::new().now_nanos());
    peer
}

fn wire_addr(port: u16) -> NetAddress {
    let mut ip = [0u8; 16];
    ip[10] = 0xff;
    ip[11] = 0xff;
    ip[12..16].copy_from_slice(&[8, 8, 8, 8]);
    NetAddress {
        timestamp: 0,
        services: ServiceFlag::NODE_NETWORK,
        ip,
        port,
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Every accepted version message adds its timestamp to the server's
/// median time source (dcrd `OnVersion` ending in
/// `sp.server.timeSource.AddTimeSample(sp.Addr(), msg.Timestamp)`), so
/// once five peers ten minutes ahead have connected the adjusted time
/// is ten minutes ahead too, and `getinfo`'s `timeoffset` says so.
///
/// Before the port had a median time source, the version timestamp was
/// never read and the adjusted time was always the local clock.
#[test]
fn version_timestamps_feed_the_median_time_source() {
    let (_dir, ctx) = genesis_server();
    let skew = 600;
    for i in 0..5u8 {
        let addr = format!("52.91.30.{}:9108", 10 + i);
        let peer = peer_at(&addr, true);
        let mut handler =
            ServerPeerHandler::new(Arc::clone(&ctx), false, None, false, None, addr.clone());
        let msg = MsgVersion {
            protocol_version: PROTOCOL_VERSION as i32,
            services: ServiceFlag::NODE_NETWORK,
            timestamp: now_unix() + skew,
            addr_you: wire_addr(9108),
            addr_me: wire_addr(9108),
            nonce: u64::from(i),
            user_agent: "/review:0.1.0/".to_string(),
            last_block: 0,
            disable_relay_tx: false,
        };
        handler
            .on_version(&peer, &msg)
            .expect("an inbound full node is accepted");
    }

    let source = dcroxide_node::mediantime::server_time_source();
    // The sample is taken against the local clock at whole-second
    // precision, so a second boundary between building the message and
    // recording it can shave one second off, as dcrd's own test allows.
    let offset = source.offset_secs();
    assert!(
        offset == skew || offset == skew - 1,
        "five peers {skew} s ahead must move the offset to {skew} s, got {offset}"
    );
    let adjusted = source.adjusted_time_unix();
    let local = now_unix();
    assert!(
        (local + skew - 2..=local + skew).contains(&adjusted),
        "the adjusted time {adjusted} must follow the peers, local {local}"
    );
}

/// Registering an outbound peer must not hold the address manager while
/// it waits on the sync manager.  dcrd's `handleAddPeer` calls
/// `syncManager.IsCurrent()` holding no address-manager lock (each
/// `addrManager` call locks internally); the sync manager's mutex is held
/// for the whole of block processing, so holding the address manager
/// across it froze every other peer's addr traffic and the dialer's
/// address selection for as long as a block took to connect.
#[test]
fn outbound_registration_reads_the_sync_state_before_locking_the_address_manager() {
    let (_dir, ctx) = genesis_server();
    let addr = "52.91.30.7:9108".to_string();
    let peer = Arc::new(Mutex::new(peer_at(&addr, false)));
    let (queue, _rx) = OutboundQueue::channel();
    let mut handler = ServerPeerHandler::new(Arc::clone(&ctx), false, None, false, Some(1), addr);

    // Stand in for block processing holding the sync manager.
    let sync_guard = ctx.sync_manager.lock().expect("sync manager");
    let registration = {
        let peer = Arc::clone(&peer);
        thread::spawn(move || {
            handler.on_connected(&peer, &queue, false);
        })
    };

    // Give the registration ample time to reach the sync-state read.
    thread::sleep(Duration::from_millis(300));
    let addr_manager_free = ctx.addr_manager.try_lock().is_ok();
    drop(sync_guard);
    registration.join().expect("the registration completes");
    assert!(
        addr_manager_free,
        "the address manager was held while waiting on the sync manager"
    );
}

/// Hands a handshake its scripted replies and swallows what it writes.
struct ScriptedTransport(std::vec::IntoIter<Message>);

impl MsgTransport for ScriptedTransport {
    fn read_message(&mut self) -> Result<Message, ReadError> {
        self.0.next().ok_or_else(|| ReadError::io("end of script"))
    }
    fn write_message(&mut self, _msg: &Message) -> Result<(), String> {
        Ok(())
    }
}

/// A version message from a remote full node at the given protocol
/// version.
fn remote_version(protocol_version: i32, nonce: u64) -> MsgVersion {
    MsgVersion {
        protocol_version,
        services: ServiceFlag::NODE_NETWORK,
        timestamp: now_unix(),
        addr_you: wire_addr(9108),
        addr_me: wire_addr(9108),
        nonce,
        user_agent: "/review:0.1.0/".to_string(),
        last_block: 0,
        disable_relay_tx: false,
    }
}

/// A registered peer's id is the one its version read assigned from the
/// process-wide counter (dcrd `readRemoteVersionMsg`,
/// `p.id = atomic.AddInt32(&nodeCount, 1)`, before `onVersion` and the
/// too-old check), and that id keys the sync manager, `getpeerinfo` and
/// `node disconnect`.  Two peers rejected for a too-old protocol version
/// after their version read each use an id up, so the third peer is 3.
///
/// Before, the registry drew its own id from a counter that only
/// completed handshakes advanced, which called this peer 1.
#[test]
fn a_peer_is_keyed_by_the_id_its_version_read_assigned() {
    let (_dir, ctx) = genesis_server();
    let globals = PeerGlobals::new();
    let addr = "52.91.30.40:9108";
    for nonce in [0x1001, 0x1002] {
        let mut rejected = peer_at(addr, true);
        let mut transport =
            ScriptedTransport(vec![Message::Version(remote_version(1, nonce))].into_iter());
        let mut env = NodePeerEnv::new();
        assert!(
            rejected
                .negotiate_inbound_protocol(&mut transport, &mut env, &globals, None)
                .is_err(),
            "a protocol version below the reject-removal version is refused"
        );
    }

    let mut accepted = peer_at(addr, true);
    let mut transport = ScriptedTransport(
        vec![
            Message::Version(remote_version(PROTOCOL_VERSION as i32, 0x1003)),
            Message::VerAck,
        ]
        .into_iter(),
    );
    let mut env = NodePeerEnv::new();
    accepted
        .negotiate_inbound_protocol(&mut transport, &mut env, &globals, None)
        .expect("a current full node is accepted");
    assert_eq!(accepted.id(), 3, "the rejected peers each used an id up");

    let peer = Arc::new(Mutex::new(accepted));
    let (queue, _rx) = OutboundQueue::channel();
    let mut handler =
        ServerPeerHandler::new(Arc::clone(&ctx), false, None, false, None, addr.to_string());
    handler.on_connected(&peer, &queue, false);

    let manager = ctx.sync_manager.lock().expect("sync manager");
    assert!(
        manager.peer(3).is_some(),
        "the peer is registered under its own id"
    );
    assert!(manager.peer(1).is_none(), "no registry counter of its own");
}

/// How long a handler gets to answer while the test holds a lock the
/// answer must not need.  Generous, so only a handler that really
/// waits on the lock runs out of it.
const ANSWER_WAIT: Duration = Duration::from_secs(5);

/// Hand `msg` to a fresh inbound handler on its own thread, returning
/// the channel its serve signal arrives on and the thread, which also
/// hands back the queue's receiver for inspecting what was sent.
fn handle_on_thread(
    ctx: &Arc<ServerContext>,
    prepare: impl FnOnce(&mut ServerPeerHandler, &Arc<Mutex<Peer>>, &OutboundQueue) + Send + 'static,
    msg: Message,
) -> (
    mpsc::Receiver<ServeSignal>,
    thread::JoinHandle<dcroxide_node::peerloop::OutboundReceiver>,
) {
    let addr = "52.91.30.41:9108".to_string();
    let mut handler =
        ServerPeerHandler::new(Arc::clone(ctx), false, None, false, None, addr.clone());
    let (done_tx, done_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let peer = Arc::new(Mutex::new(peer_at(&addr, true)));
        let (queue, rx) = OutboundQueue::channel();
        prepare(&mut handler, &peer, &queue);
        let signal = handler.handle_message(&peer, msg, None, &queue);
        let _ = done_tx.send(signal);
        rx
    });
    (done_rx, worker)
}

/// A getminingstate from a peer whose protocol version makes it a
/// knowing violation (almost every modern peer that sends one) is banned
/// before the chain or the mempool is touched: dcrd checks the protocol
/// version first and returns (`OnGetMiningState`, `server.go:1116-1122`).
///
/// Before, the handler sorted the tip generation by its mempool votes
/// under both locks and only then banned the peer.
#[test]
fn a_banned_getminingstate_never_waits_on_the_chain_or_mempool() {
    let (_dir, ctx) = genesis_server();
    let chain_guard = ctx.chain.lock().expect("chain");
    let pool_guard = ctx.tx_pool.lock().expect("tx pool");
    let (done, worker) = handle_on_thread(&ctx, |_, _, _| {}, Message::GetMiningState);
    let answered = done.recv_timeout(ANSWER_WAIT);
    drop(pool_guard);
    drop(chain_guard);
    worker.join().expect("the handler completes");
    assert!(
        matches!(answered, Ok(ServeSignal::Disconnect(_))),
        "the peer must be banned without the chain or mempool, got {answered:?}"
    );
}

/// A repeated getinitstate is banned before the chain is read (dcrd's
/// `initStateSent` latch comes first, `server.go:1231-1237`).
#[test]
fn a_repeated_getinitstate_bans_without_reading_the_chain() {
    let (_dir, ctx) = genesis_server();
    let types = vec![
        INIT_STATE_HEAD_BLOCKS.to_string(),
        INIT_STATE_HEAD_BLOCK_VOTES.to_string(),
        INIT_STATE_TSPENDS.to_string(),
    ];
    let request = Message::GetInitState(MsgGetInitState {
        types: types.clone(),
    });
    let (first_done_tx, first_done_rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let (done, worker) = handle_on_thread(
        &ctx,
        move |handler, peer, queue| {
            let first = handler.handle_message(
                peer,
                Message::GetInitState(MsgGetInitState { types }),
                None,
                queue,
            );
            let _ = first_done_tx.send(first);
            // The repeat waits until the test holds both locks.
            let _ = go_rx.recv();
        },
        request,
    );
    // The first request runs with the locks free.
    assert_eq!(
        first_done_rx.recv_timeout(ANSWER_WAIT),
        Ok(ServeSignal::Continue),
        "the first request is answered"
    );

    let chain_guard = ctx.chain.lock().expect("chain");
    let pool_guard = ctx.tx_pool.lock().expect("tx pool");
    go_tx.send(()).expect("release the repeat");
    let answered = done.recv_timeout(ANSWER_WAIT);
    drop(pool_guard);
    drop(chain_guard);
    worker.join().expect("the handler completes");
    assert!(
        matches!(answered, Ok(ServeSignal::Disconnect(_))),
        "a repeat must be banned without the chain or mempool, got {answered:?}"
    );
}

/// Below stake validation a getinitstate is answered with the blank
/// message before the tip generation, its votes or the treasury spends
/// are looked up (dcrd `server.go:1239-1244`), so the mempool is never
/// consulted.
#[test]
fn an_early_getinitstate_answers_blank_without_the_mempool() {
    let (_dir, ctx) = genesis_server();
    let pool_guard = ctx.tx_pool.lock().expect("tx pool");
    let (done, worker) = handle_on_thread(
        &ctx,
        |_, _, _| {},
        Message::GetInitState(MsgGetInitState {
            types: vec![
                INIT_STATE_HEAD_BLOCKS.to_string(),
                INIT_STATE_HEAD_BLOCK_VOTES.to_string(),
                INIT_STATE_TSPENDS.to_string(),
            ],
        }),
    );
    let answered = done.recv_timeout(ANSWER_WAIT);
    drop(pool_guard);
    let rx = worker.join().expect("the handler completes");
    assert_eq!(
        answered,
        Ok(ServeSignal::Continue),
        "answered without the mempool"
    );
    assert_eq!(
        rx.try_recv(),
        Ok(Message::InitState(MsgInitState::default())),
        "the genesis tip is short of stake validation, so the reply is blank"
    );
}

/// The mempool flood guard bans before the pool is enumerated (dcrd
/// `OnMemPool`'s `addBanScore` returns before `TxDescs`,
/// `server.go:1057`): three requests score 99 of the 100 allowed, and
/// the fourth is banned with the tx pool held elsewhere.
#[test]
fn a_mempool_flood_is_banned_before_the_pool_is_enumerated() {
    let (_dir, ctx) = genesis_server();
    let (ladder_tx, ladder_rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let (done, worker) = handle_on_thread(
        &ctx,
        move |handler, peer, queue| {
            let signals: Vec<ServeSignal> = (0..3)
                .map(|_| handler.handle_message(peer, Message::MemPool, None, queue))
                .collect();
            let _ = ladder_tx.send(signals);
            // The fourth request waits until the test holds the pool.
            let _ = go_rx.recv();
        },
        Message::MemPool,
    );
    assert_eq!(
        ladder_rx.recv_timeout(ANSWER_WAIT),
        Ok(vec![ServeSignal::Continue; 3]),
        "the first three requests stay under the threshold"
    );

    let pool_guard = ctx.tx_pool.lock().expect("tx pool");
    go_tx.send(()).expect("release the fourth request");
    let answered = done.recv_timeout(ANSWER_WAIT);
    drop(pool_guard);
    worker.join().expect("the handler completes");
    assert!(
        matches!(answered, Ok(ServeSignal::Disconnect(_))),
        "the flooding peer must be banned without the pool, got {answered:?}"
    );
}

/// Register a fresh inbound peer with the server, as the handshake's
/// add-peer step does.
fn register(handler: &mut ServerPeerHandler, peer: &Arc<Mutex<Peer>>, queue: &OutboundQueue) {
    handler.on_connected(peer, queue, false);
}

/// Poll the sync manager's lock while `busy` is still running, reporting
/// whether it was ever free.  The handler takes the lock briefly on
/// either side of the pool's validation, so one attempt could land in
/// that window; several spread over a few hundred milliseconds cannot
/// all do so unless the lock is held throughout.
fn sync_manager_free_while(ctx: &ServerContext, busy: &mpsc::Receiver<ServeSignal>) -> bool {
    for _ in 0..10 {
        thread::sleep(Duration::from_millis(50));
        if !matches!(busy.try_recv(), Err(mpsc::TryRecvError::Empty)) {
            return false;
        }
        if ctx.sync_manager.try_lock().is_ok() {
            return true;
        }
    }
    false
}

/// A transaction's mempool validation runs with the sync-manager lock
/// released, as dcrd's `OnTx` runs `ProcessTransaction` under the
/// mempool's own mutex with only `requestMtx` around the request-map
/// delete.  With the tx pool held elsewhere the validation waits, and
/// the sync manager -- which every peer's block, header and inventory
/// intake needs -- must stay free while it does.
///
/// Before, the whole intake ran under the sync-manager lock.
#[test]
fn transaction_validation_leaves_the_sync_manager_free() {
    let (_dir, ctx) = genesis_server();
    let pool_guard = ctx.tx_pool.lock().expect("tx pool");
    let (done, worker) = handle_on_thread(&ctx, register, Message::Tx(MsgTx::default()));
    let free = sync_manager_free_while(&ctx, &done);
    drop(pool_guard);
    let answered = done.recv_timeout(ANSWER_WAIT);
    worker.join().expect("the handler completes");
    assert_eq!(answered, Ok(ServeSignal::Continue));
    assert!(
        free,
        "the sync manager was held across the mempool validation"
    );
}

/// A mixing message's mixpool acceptance runs with the sync-manager lock
/// released, as dcrd's `OnMixMsg` runs `AcceptMessage` under the
/// mixpool's own mutex.  A pair request's acceptance first asks the tx
/// pool which of its outputs are already spent, so holding the tx pool
/// parks the acceptance there.
#[test]
fn mix_acceptance_leaves_the_sync_manager_free() {
    let (_dir, ctx) = genesis_server();
    let pr = MsgMixPairReq {
        signature: [0u8; 64],
        identity: [2u8; 33],
        expiry: 10,
        mix_amount: 10_000_000,
        script_class: dcroxide_mixing::SCRIPT_CLASS_P2PKH_V0.to_string(),
        tx_version: 1,
        lock_time: 0,
        message_count: 1,
        input_value: 10_100_000,
        utxos: vec![MixPairReqUTXO {
            out_point: OutPoint {
                hash: dcroxide_chainhash::Hash([7u8; 32]),
                index: 7,
                tree: 0,
            },
            ..MixPairReqUTXO::default()
        }],
        change: None,
        flags: 0,
        pairing_flags: 0,
    };
    let pool_guard = ctx.tx_pool.lock().expect("tx pool");
    let (done, worker) = handle_on_thread(&ctx, register, Message::MixPairReq(pr));
    let free = sync_manager_free_while(&ctx, &done);
    drop(pool_guard);
    let answered = done.recv_timeout(ANSWER_WAIT);
    worker.join().expect("the handler completes");
    assert!(
        answered.is_ok(),
        "the handler answers once the tx pool is free, got {answered:?}"
    );
    assert!(
        free,
        "the sync manager was held across the mixpool acceptance"
    );
}
