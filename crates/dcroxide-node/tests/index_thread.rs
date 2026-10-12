// SPDX-License-Identifier: ISC
//! The daemon's index thread: the bounded queue the chain handler's
//! drain feeds, and the one thread that hands each queued notification
//! to the index subscriber.
//!
//! dcrd sends every index notification on a 128-deep channel and one
//! goroutine processes them (`indexsubscriber.go` `Notify`,
//! `handleIndexUpdates`).  The daemon does the same with a thread named
//! "index".  Inline delivery, on the draining thread, stays for callers
//! without that thread and is the reference here: whatever is queued
//! must leave the indexes exactly as inline delivery of the same
//! notifications leaves them.
//!
//! - **The daemon's own wiring** (Linux): a real daemon mines blocks and
//!   its indexes answer for them with no restart to catch them up, which
//!   a thread that was never started, was dropped at once or was attached
//!   to the handler after its first clone cannot do.  The thread is also
//!   seen to have woken for those blocks, which it would not have under a
//!   handler that delivers on the draining thread beside it.
//! - **The overlay copy.**  The exists address index hands a connect's
//!   keys over together with the unconfirmed overlay.  A queued connect
//!   brings the overlay as it stood when it was queued, so a key the pool
//!   adds while the connect waits goes with the next connect, as it does
//!   under inline delivery.  dcrd reads the map when it processes the
//!   block.
//! - **Order and backpressure.**  A full queue blocks the sender and
//!   drops nothing; connects, disconnects and reconnects arrive in the
//!   chain's order.
//! - **Shutdown.**  Once the daemon's interrupt is set the thread drops
//!   what is queued, as dcrd's handler returns on `ctx.Done()`, and the
//!   next start's catch-up indexes those blocks.
//! - **An unclean stop in a catch-up.**  With the UTXO cache at its size
//!   limit and the chain not current, the durable commits are the ones
//!   the exists address index asks for, from whichever thread commits
//!   next.  What such a commit leaves on disk reopens to the right UTXO
//!   set and the right index.
//!
//! The tests that stall the index thread hold the database's writer on
//! the test thread: the thread then waits in its update with the index
//! mutex held, so those tests take every handle they need beforehand and
//! leave that mutex alone until the writer is released.

// Test-harness arithmetic over small counts and fixed deadlines.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::Params;
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_indexers::{
    ADDR_KEY_SIZE, CONNECT_NTFN, ChainQueryer, IndexNtfn, Interrupt, TxIndexEntry, addr_to_key,
};
use dcroxide_netsync::manager::SyncChain;
use dcroxide_node::chainntfns::ChainNtfnHandler;
use dcroxide_node::indexes::{
    INDEX_NTFN_BUFFER_SIZE, IndexLogs, IndexNotifier, IndexThread, NodeChainQueryer, NodeIndexes,
    start_indexes,
};
use dcroxide_node::sync::NodeSyncChain;
use dcroxide_testutil::unhex;
use dcroxide_txscript::stdaddr::{Address, new_address_pub_key_hash_ecdsa_secp256k1_v0};
use dcroxide_wire::{MsgBlock, MsgTx, TxOut, TxSerializeType};

type Key = [u8; ADDR_KEY_SIZE];

/// A transaction paying `addr`, for the mempool's hook: the unconfirmed
/// overlay reads only its outputs.
fn paying(addr: &Address) -> MsgTx {
    let (version, pk_script) = addr.payment_script();
    MsgTx {
        ser_type: TxSerializeType::Full,
        version: 1,
        tx_in: Vec::new(),
        tx_out: vec![TxOut {
            value: 1,
            version,
            pk_script,
        }],
        lock_time: 0,
        expiry: 0,
    }
}

/// A pay-to-pubkey-hash address no block of these tests pays, and its
/// index key.
fn fresh_address(params: &Params) -> (Address, Key) {
    let addr = new_address_pub_key_hash_ecdsa_secp256k1_v0(&[0x77; 20], params).expect("address");
    let key = addr_to_key(&addr).expect("key");
    (addr, key)
}

// ---------------------------------------------------------------------
// The queue alone, over a store at genesis
// ---------------------------------------------------------------------

/// A simnet store at genesis with the exists address index alone and an
/// index thread over it.  The thread is the first field, so it is joined
/// before the index handles and the database go, as in the daemon.
struct Rig {
    thread: IndexThread,
    indexes: NodeIndexes,
    db: Database,
    params: Params,
    _dir: tempfile::TempDir,
}

/// A [`Rig`] whose queue holds `capacity` notifications.
fn rig(capacity: usize) -> Rig {
    let params = dcroxide_chaincfg::simnet_params();
    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db.clone(), &params, params.assume_valid, false, 0).expect("open chain"),
    ));
    let indexes = start_indexes(
        Arc::new(AtomicBool::new(false)),
        Arc::new(db.clone()),
        chain,
        params.clone(),
        false,
        true,
        &IndexLogs::default(),
    )
    .expect("start indexes");
    let thread = IndexThread::start_with_capacity(&indexes, capacity).expect("index thread");
    Rig {
        thread,
        indexes,
        db,
        params,
        _dir: dir,
    }
}

/// A connect of a block at `height`.  The update path checks a
/// notification's height against the index tip and reads nothing of the
/// chain, so the genesis block with its height set stands in for a block
/// of the chain.
fn connect_at(params: &Params, height: u32) -> IndexNtfn {
    let mut block = params.genesis_block.clone();
    block.header.height = height;
    IndexNtfn {
        ntfn_type: CONNECT_NTFN,
        block: Arc::new(block),
        parent: Arc::new(params.genesis_block.clone()),
        is_treasury_enabled: false,
    }
}

/// A key the pool adds after a connect was queued is not handed over with
/// that connect, however late the index thread reaches it: it is still
/// answered from the overlay, and goes with the next connect.
///
/// The thread is stalled on the connect before the one under test, so
/// the one under test is certainly still queued when the pool adds the
/// key, and is taken off the queue only after it.  A copy of the overlay
/// made when the thread takes the connect, or no copy at all (dcrd's
/// read at processing time), would both hand the key over with it.
///
/// The same stall pins the barrier every queued test settles on: while
/// the two connects wait for the writer, `wait_processed` must still be
/// waiting, and it is answered once they have been applied.
#[test]
fn a_key_the_pool_adds_after_a_connect_is_queued_waits_for_the_next_connect() {
    let rig = rig(INDEX_NTFN_BUFFER_SIZE);
    let notifier = rig.thread.notifier();
    let index = rig.indexes.exists_addr_index.as_ref().expect("the index");
    let (unconfirmed, query) = {
        let index = index.lock().expect("index");
        (index.unconfirmed(), index.query())
    };
    let (fresh, fresh_key) = fresh_address(&rig.params);
    let keys = || index.lock().expect("index").logical_keys().expect("keys");

    let hold = rig.db.begin(true).expect("hold the writer");
    // Taken by the thread, which then waits for the writer.
    notifier.notify(connect_at(&rig.params, 1));
    // Queued behind it; its copy of the overlay is made here, empty.
    notifier.notify(connect_at(&rig.params, 2));
    unconfirmed.add_unconfirmed_tx(&paying(&fresh));

    // The barrier is answered only after what was queued ahead of it.
    let (answered_tx, answered) = mpsc::channel();
    let waiter = {
        let notifier = notifier.clone();
        std::thread::spawn(move || {
            let _ = answered_tx.send(notifier.wait_processed());
        })
    };
    assert!(
        answered.recv_timeout(Duration::from_millis(300)).is_err(),
        "the barrier was answered while two connects still waited for the writer"
    );
    hold.rollback().expect("release the writer");
    assert!(
        answered
            .recv_timeout(Duration::from_secs(60))
            .expect("the barrier is answered"),
        "the thread is running"
    );
    waiter.join().expect("waiter");
    assert_eq!(query.tip().expect("tip").0, 2, "both connects applied");
    assert!(
        !keys().contains(&fresh_key),
        "a key added after the connect was queued went with it"
    );
    assert!(
        query.exists_address(&fresh).expect("lookup"),
        "the key is still answered from the overlay"
    );

    notifier.notify(connect_at(&rig.params, 3));
    assert!(notifier.wait_processed(), "the thread is running");
    assert!(keys().contains(&fresh_key), "the next connect takes it");
    assert!(query.exists_address(&fresh).expect("lookup"));
}

/// The queue is dcrd's depth, and a sender finding it full waits for the
/// index thread instead of dropping its notification: with one slot and a
/// stalled thread, the first notification is in the thread's hands, the
/// second fills the slot and the third does not return until the thread
/// moves.  All three are then applied, in order -- an index refuses a
/// height that skips one, so the tip reaches three only that way.
#[test]
fn a_full_queue_blocks_the_sender_until_the_index_thread_catches_up() {
    assert_eq!(INDEX_NTFN_BUFFER_SIZE, 128, "dcrd's bufferSize");

    let rig = rig(1);
    let notifier = rig.thread.notifier();
    let query = rig
        .indexes
        .exists_addr_index
        .as_ref()
        .expect("the index")
        .lock()
        .expect("index")
        .query();

    let hold = rig.db.begin(true).expect("hold the writer");
    notifier.notify(connect_at(&rig.params, 1));
    notifier.notify(connect_at(&rig.params, 2));
    let (sent, returned) = mpsc::channel();
    let third = {
        let (notifier, ntfn) = (notifier.clone(), connect_at(&rig.params, 3));
        std::thread::spawn(move || {
            notifier.notify(ntfn);
            let _ = sent.send(());
        })
    };
    assert!(
        returned.recv_timeout(Duration::from_millis(300)).is_err(),
        "a send into a full queue returned"
    );

    hold.rollback().expect("release the writer");
    returned
        .recv_timeout(Duration::from_secs(60))
        .expect("the blocked send returns once the thread makes room");
    third.join().expect("sender");
    assert!(notifier.wait_processed(), "the thread is running");
    assert_eq!(
        query.tip().expect("tip").0,
        3,
        "every notification applied, in order"
    );
}

// ---------------------------------------------------------------------
// Queued against inline, over dcrd's full-block battery
// ---------------------------------------------------------------------

/// The leading consecutive main-chain prefix of accepted blocks from
/// dcrd's `fullblocktests.Generate` battery (fully signed regnet
/// blocks), with the battery's recorded generation time.
fn accepted_prefix(limit: usize) -> (i64, Vec<MsgBlock>) {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcroxide-blockchain/tests/data/fullblock_vectors.txt"
    );
    let data = std::fs::read_to_string(path).expect("fullblock vectors");
    let mut now: i64 = 0;
    let mut tip = dcroxide_chaincfg::regnet_params().genesis_hash;
    let mut blocks = Vec::new();
    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "now" => now = f[1].parse().expect("generation time"),
            // accept <name> <mainchain> <orphan> <blockhex>
            "accept" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                // Only the linear main-chain prefix: an accepted block
                // extending anything else is a side chain or orphan.
                if f[2] != "true" || block.header.prev_block != tip {
                    continue;
                }
                tip = block.header.block_hash();
                blocks.push(block);
                if blocks.len() == limit {
                    break;
                }
            }
            _ => {}
        }
    }
    assert_eq!(blocks.len(), limit, "battery must provide the prefix");
    (now, blocks)
}

/// How a [`Node`]'s chain handler delivers its index notifications.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Delivery {
    /// On the draining thread (`set_index_subscriber`).
    Inline,
    /// Through the index thread's queue (`set_index_notifier`), as the
    /// daemon does.
    Queued,
}

/// A regnet node as far as its indexes are concerned: the chain, both
/// indexes caught up to it, and the chain handler the daemon installs,
/// draining after every processing call.  The index thread, when there
/// is one, is the first field, so it is joined before the rest goes.
struct Node {
    thread: Option<IndexThread>,
    sync_chain: NodeSyncChain,
    handler: ChainNtfnHandler,
    indexes: NodeIndexes,
    interrupt: Interrupt,
    chain: Arc<Mutex<Chain>>,
    db: Database,
    params: Params,
    now: i64,
    _dir: tempfile::TempDir,
}

/// What a [`Node`]'s chain and indexes hold, for comparing two of them.
#[derive(PartialEq, Eq, Debug)]
struct State {
    chain_tip: (i64, Hash),
    exists_tip: (i64, Hash),
    tx_tip: (i64, Hash),
    /// Every key of the exists address index.
    keys: Vec<Key>,
    /// The transaction index's entry for each transaction asked about, as
    /// block hash, offset, length and position in its tree.
    entries: Vec<Option<(Hash, u32, u32, u32)>>,
}

impl Node {
    /// A node over a fresh store with `history` processed and both
    /// indexes caught up to it.
    fn new(delivery: Delivery, now: i64, history: &[MsgBlock]) -> Node {
        let params = dcroxide_chaincfg::regnet_params();
        let dir = tempfile::tempdir().expect("temp dir");
        let opts = Options::new(dir.path().join("blocks"), params.net.0);
        let db = Database::create(&opts).expect("create database");
        let chain = Arc::new(Mutex::new(
            Chain::open(db.clone(), &params, params.assume_valid, false, 0).expect("open chain"),
        ));
        for block in history {
            let (_, errs) = chain
                .lock()
                .expect("chain")
                .process_block(block, now, &params);
            assert!(errs.is_empty(), "history block must accept: {errs:?}");
        }
        let interrupt: Interrupt = Arc::new(AtomicBool::new(false));
        let indexes = start_indexes(
            Arc::clone(&interrupt),
            Arc::new(db.clone()),
            Arc::clone(&chain),
            params.clone(),
            true,
            true,
            &IndexLogs::default(),
        )
        .expect("start indexes");

        let tx_pool = dcroxide_node::txmempool::new_shared_tx_pool(
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
            dcroxide_node::sync::SyncGate::always_current(),
            None,
            tx_pool,
            dcroxide_node::dispatch::SyncPeers::new(),
            dcroxide_node::dispatch::new_recently_advertised(),
        );
        let thread = match delivery {
            Delivery::Inline => {
                handler.set_index_subscriber(Arc::clone(&indexes.subscriber));
                None
            }
            Delivery::Queued => {
                let thread = IndexThread::start(&indexes).expect("index thread");
                handler.set_index_notifier(thread.notifier());
                Some(thread)
            }
        };
        {
            let callback_handler = handler.clone();
            chain
                .lock()
                .expect("chain")
                .set_notification_callback(Box::new(move |n| callback_handler.handle(n)));
        }
        let mut sync_chain = NodeSyncChain::new(Arc::clone(&chain), params.clone());
        sync_chain.set_chain_ntfn_handler(handler.clone());
        Node {
            thread,
            sync_chain,
            handler,
            indexes,
            interrupt,
            chain,
            db,
            params,
            now,
            _dir: dir,
        }
    }

    /// The sending end of the index thread's queue.
    fn notifier(&self) -> IndexNotifier {
        self.thread.as_ref().expect("an index thread").notifier()
    }

    /// Wait until the indexes have seen everything the handler handed
    /// them: at once under inline delivery.
    fn settle(&self) {
        if let Some(thread) = &self.thread {
            assert!(thread.notifier().wait_processed(), "the thread is running");
        }
    }

    /// Connect `block` as the sync manager does: the processing call,
    /// then the handler's drain.
    fn connect(&mut self, block: &MsgBlock) {
        self.sync_chain
            .process_block(&Arc::new(block.clone()))
            .expect("live block");
    }

    /// Run a manual reorganization and the drain that follows it, as the
    /// RPC server's `invalidateblock` and `reconsiderblock` seams do.
    fn reorganize(&self, step: impl FnOnce(&mut Chain) -> Vec<dcroxide_blockchain::RuleError>) {
        let errs = step(&mut self.chain.lock().expect("chain"));
        assert!(errs.is_empty(), "the reorganization: {errs:?}");
        self.handler.drain_pending(&self.chain, self.now);
    }

    /// The chain and index state once the indexes have settled, with the
    /// transaction index's entry for each transaction of `blocks`.
    fn state(&self, blocks: &[MsgBlock]) -> State {
        self.settle();
        state_of(&self.chain, &self.indexes, blocks)
    }
}

/// The [`State`] of a chain and its indexes.
fn state_of(chain: &Arc<Mutex<Chain>>, indexes: &NodeIndexes, blocks: &[MsgBlock]) -> State {
    let chain_tip = {
        let chain = chain.lock().expect("chain");
        let best = chain.best_snapshot();
        (best.height, best.hash)
    };
    let exists = indexes.exists_addr_index.as_ref().expect("exists index");
    let tx_query = indexes
        .tx_index
        .as_ref()
        .expect("tx index")
        .lock()
        .expect("tx index")
        .query();
    let location = |entry: TxIndexEntry| {
        (
            entry.block_region.hash,
            entry.block_region.offset,
            entry.block_region.len,
            entry.block_index,
        )
    };
    let entries = blocks
        .iter()
        .flat_map(|block| block.transactions.iter().chain(&block.stransactions))
        .map(|tx| tx_query.entry(&tx.tx_hash()).expect("entry").map(location))
        .collect();
    let exists = exists.lock().expect("exists index");
    State {
        chain_tip,
        exists_tip: exists.query().tip().expect("exists tip"),
        tx_tip: tx_query.tip().expect("tx tip"),
        keys: exists.logical_keys().expect("keys"),
        entries,
    }
}

/// The index thread leaves both indexes exactly as inline delivery leaves
/// them, stage by stage, through connects, a mempool address, a
/// disconnect and its reconnect.
///
/// Two nodes take the same blocks through the handler the daemon
/// installs, one delivering inline and one through the queue.  The
/// disconnect and the reconnect come from `invalidateblock` and
/// `reconsiderblock` of the tip, drained as the RPC seams drain them.
/// After each stage the two must agree on the chain tip, both index tips,
/// every key of the exists address index and the transaction index's
/// entry for every transaction of every block.
#[test]
fn the_index_thread_builds_the_same_indexes_as_inline_delivery() {
    let (now, blocks) = accepted_prefix(6);
    let mut inline = Node::new(Delivery::Inline, now, &blocks[..2]);
    let mut queued = Node::new(Delivery::Queued, now, &blocks[..2]);
    let (fresh, fresh_key) = fresh_address(&inline.params);
    // The tip at a height, and how many transactions the blocks up to a
    // height hold: `State::entries` has one entry for each, in order.
    let tip = |at: usize| (at as i64, blocks[at - 1].header.block_hash());
    let txs_through = |at: usize| -> usize {
        blocks[..at]
            .iter()
            .map(|block| block.transactions.len() + block.stransactions.len())
            .sum()
    };
    let agree = |inline: &Node, queued: &Node, stage: &str| {
        let state = queued.state(&blocks);
        assert_eq!(
            state,
            inline.state(&blocks),
            "queued against inline {stage}"
        );
        state
    };

    let state = agree(&inline, &queued, "after the catch-up");
    assert_eq!((state.exists_tip, state.tx_tip), (tip(2), tip(2)));

    for block in &blocks[2..5] {
        inline.connect(block);
        queued.connect(block);
    }
    let state = agree(&inline, &queued, "after three connects");
    assert_eq!(state.chain_tip, tip(5));
    assert_eq!((state.exists_tip, state.tx_tip), (tip(5), tip(5)));
    let (indexed, ahead) = state.entries.split_at(txs_through(5));
    assert!(indexed.iter().all(Option::is_some), "the connected blocks");
    assert!(ahead.iter().all(Option::is_none), "the block still to come");
    assert!(!state.keys.contains(&fresh_key));

    // A mempool address, with nothing in flight on either node, and the
    // connect that takes it.
    for node in [&inline, &queued] {
        let exists = node.indexes.exists_addr_index.as_ref().expect("the index");
        let unconfirmed = exists.lock().expect("index").unconfirmed();
        unconfirmed.add_unconfirmed_tx(&paying(&fresh));
    }
    inline.connect(&blocks[5]);
    queued.connect(&blocks[5]);
    let connected = agree(&inline, &queued, "after the mempool address");
    assert_eq!((connected.exists_tip, connected.tx_tip), (tip(6), tip(6)));
    assert!(connected.keys.contains(&fresh_key), "handed over");
    assert!(connected.entries.iter().all(Option::is_some), "all indexed");

    // The tip is disconnected: both index tips step back, the exists
    // address index keeps its keys and the transaction index drops the
    // block's entries.
    let last = blocks[5].header.block_hash();
    for node in [&inline, &queued] {
        node.reorganize(|chain| chain.invalidate_block(&last, node.now, &node.params));
    }
    let disconnected = agree(&inline, &queued, "after the disconnect");
    assert_eq!(disconnected.chain_tip, tip(5));
    assert_eq!(
        (disconnected.exists_tip, disconnected.tx_tip),
        (tip(5), tip(5))
    );
    assert_eq!(
        disconnected.keys, connected.keys,
        "addresses are never removed"
    );
    let (kept, dropped) = disconnected.entries.split_at(txs_through(5));
    assert!(kept.iter().all(Option::is_some), "the blocks below stay");
    assert!(dropped.iter().all(Option::is_none), "the tip's entries go");

    // And reconnected.
    for node in [&inline, &queued] {
        node.reorganize(|chain| chain.reconsider_block(&last, node.now, &node.params));
    }
    let reconnected = agree(&inline, &queued, "after the reconnect");
    assert_eq!(reconnected, connected, "back where the connect left it");
}

/// The connect notification the chain handler builds for `block`, whose
/// parent is `parent`.
fn connect_of(node: &Node, block: &MsgBlock, parent: &MsgBlock) -> IndexNtfn {
    connect_ntfn(&node.indexes.queryer, block, parent)
}

/// [`connect_of`] for a chain behind `queryer`.
fn connect_ntfn(queryer: &NodeChainQueryer, block: &MsgBlock, parent: &MsgBlock) -> IndexNtfn {
    let is_treasury_enabled = queryer
        .is_treasury_agenda_active(&block.header.prev_block)
        .expect("agenda state");
    IndexNtfn {
        ntfn_type: CONNECT_NTFN,
        block: Arc::new(block.clone()),
        parent: Arc::new(parent.clone()),
        is_treasury_enabled,
    }
}

/// Once the daemon's interrupt is set the index thread processes nothing
/// more: what is queued is dropped and the indexes stay where they were,
/// with no update half applied.  The next start's catch-up then indexes
/// the blocks the queue lost, and leaves what inline delivery of those
/// blocks leaves.
#[test]
fn a_shutdown_request_drops_the_queue_and_the_next_start_catches_up() {
    let (now, blocks) = accepted_prefix(4);
    let hash_at = |at: usize| (at as i64, blocks[at - 1].header.block_hash());

    // The reference: the two later blocks delivered inline.
    let mut inline = Node::new(Delivery::Inline, now, &blocks[..2]);
    inline.connect(&blocks[2]);
    inline.connect(&blocks[3]);
    let expected = inline.state(&blocks);
    assert_eq!(
        (expected.exists_tip, expected.tx_tip),
        (hash_at(4), hash_at(4))
    );

    // The same two blocks reach the chain of a node whose index thread
    // sees the shutdown request before it sees either notification.
    let mut node = Node::new(Delivery::Queued, now, &blocks[..2]);
    let notifier = node.notifier();
    for block in &blocks[2..4] {
        let (_, errs) = node
            .chain
            .lock()
            .expect("chain")
            .process_block(block, now, &node.params);
        assert!(errs.is_empty(), "block must accept: {errs:?}");
    }
    // The chain callback queued both for the handler; left undrained,
    // they never reach the queue, so the test sends them itself, after
    // the interrupt.
    node.interrupt.store(true, Ordering::SeqCst);
    notifier.notify(connect_of(&node, &blocks[2], &blocks[1]));
    notifier.notify(connect_of(&node, &blocks[3], &blocks[2]));
    assert!(
        !notifier.wait_processed(),
        "the thread answered after the shutdown request"
    );
    let stopped = state_of(&node.chain, &node.indexes, &blocks);
    assert_eq!(stopped.chain_tip, hash_at(4));
    assert_eq!(
        (stopped.exists_tip, stopped.tx_tip),
        (hash_at(2), hash_at(2)),
        "a dropped notification moved an index"
    );
    // A send after the thread has gone is dropped without a wait.
    notifier.notify(connect_of(&node, &blocks[2], &blocks[1]));
    node.thread.take().expect("the thread").shutdown();

    // The next start, over the same store and chain.
    let Node {
        indexes, chain, db, ..
    } = node;
    drop(indexes);
    let restarted = start_indexes(
        Arc::new(AtomicBool::new(false)),
        Arc::new(db.clone()),
        Arc::clone(&chain),
        dcroxide_chaincfg::regnet_params(),
        true,
        true,
        &IndexLogs::default(),
    )
    .expect("restart the indexes");
    assert_eq!(
        state_of(&chain, &restarted, &blocks),
        expected,
        "the catch-up against inline delivery"
    );
}

// ---------------------------------------------------------------------
// An unclean stop in a catch-up
// ---------------------------------------------------------------------

// What only the unclean-stop test below uses.  It copies the files of a
// store that is still open, which Windows refuses: redb holds a
// byte-range lock on its file while the database is open.
#[cfg(not(windows))]
use std::path::Path;
#[cfg(not(windows))]
use std::sync::atomic::AtomicUsize;

#[cfg(not(windows))]
use dcroxide_blockchain::chaindb::{db_fetch_best_state, db_fetch_utxo_set_state};
#[cfg(not(windows))]
use dcroxide_blockchain::process::OpenConfig;
#[cfg(not(windows))]
use dcroxide_database::FlushObservation;
#[cfg(not(windows))]
use dcroxide_indexers::{ExistsAddrIndex, ExistsAddrPolicy, IndexSubscriber, NO_PREREQS};
#[cfg(not(windows))]
use dcroxide_node::indexes::start_indexes_with_policy;

#[cfg(not(windows))]
fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).expect("create the copy's directory");
    for entry in std::fs::read_dir(src).expect("read the directory") {
        let entry = entry.expect("directory entry");
        let to = dst.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_dir(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), &to).expect("copy a file");
        }
    }
}

/// A durable commit the exists address index asked for carries the UTXO
/// cache flushes before it that were not durable, with the connects and
/// the index tip rows committed between them, and what it leaves on disk
/// reopens to the right UTXO set and the right index.
///
/// This is the state an initial sync is in for most of its commits since
/// a UTXO cache flush that only its size limit tripped stopped forcing a
/// durable commit.  The chain is never current here and its cache is at
/// its limit after every connect, so no UTXO flush is durable, and the
/// index asks for a flush at its first unjournaled key, so the durable
/// commits are its requests, granted on whichever of the two threads
/// commits next.  Two mempool addresses give it a key to ask with part
/// way through the blocks.
///
/// The directory is copied with both threads idle and nothing flushed or
/// closed, which is what an unclean stop at that moment leaves.  In the
/// copy the utxo set state and the index tip are at or behind the best
/// state.  The chain then opens at the durable best state with the set
/// an uninterrupted chain has there, and the index catches up to it
/// holding the keys of those blocks and the mempool addresses of exactly
/// the connects whose tip row was durable.
#[cfg(not(windows))]
#[test]
fn an_unclean_stop_after_a_commit_the_index_asked_for_reopens_to_the_right_set_and_index() {
    const BLOCKS: usize = 30;
    // The connects that take a mempool address, by position in the
    // blocks, and the byte each address is made of.
    const MEMPOOL: [(usize, u8); 2] = [(10, 0x51), (20, 0x52)];

    let (now, blocks) = accepted_prefix(BLOCKS);
    let params = dcroxide_chaincfg::regnet_params();
    // Two days on, every block looks old, so the chain never latches to
    // current and no connect forces a durable flush.
    let old = now + 48 * 60 * 60;
    let policy = ExistsAddrPolicy {
        u_max: 1,
        ..ExistsAddrPolicy::tiny()
    };
    let open_config = || {
        let mut config = OpenConfig::new(params.assume_valid, false, 0);
        config.utxo_cache_max_bytes = 1;
        config
    };
    let mempool_key = |seed: u8| {
        let addr =
            new_address_pub_key_hash_ecdsa_secp256k1_v0(&[seed; 20], &params).expect("address");
        let key = addr_to_key(&addr).expect("key");
        (addr, key)
    };

    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("blocks");
    let durable = Arc::new(AtomicUsize::new(0));
    let mut opts = Options::new(&path, params.net.0);
    opts.flush_observer = Some({
        let durable = Arc::clone(&durable);
        Arc::new(move |_: &FlushObservation| {
            durable.fetch_add(1, Ordering::SeqCst);
        })
    });
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open_with_config(db.clone(), &params, open_config()).expect("open chain"),
    ));
    let indexes = start_indexes_with_policy(
        Arc::new(AtomicBool::new(false)),
        Arc::new(db.clone()),
        Arc::clone(&chain),
        params.clone(),
        false,
        true,
        &IndexLogs::default(),
        policy,
    )
    .expect("start indexes");
    let thread = IndexThread::start(&indexes).expect("index thread");
    let notifier = thread.notifier();
    db.flush().expect("flush what the start wrote");
    let started = durable.load(Ordering::SeqCst);

    let unconfirmed = indexes
        .exists_addr_index
        .as_ref()
        .expect("the index")
        .lock()
        .expect("index")
        .unconfirmed();
    for (at, block) in blocks.iter().enumerate() {
        if let Some((_, seed)) = MEMPOOL.iter().find(|(connect, _)| *connect == at) {
            unconfirmed.add_unconfirmed_tx(&paying(&mempool_key(*seed).0));
        }
        let (_, errs) = chain
            .lock()
            .expect("chain")
            .process_block(block, old, &params);
        assert!(errs.is_empty(), "block must accept: {errs:?}");
        let parent = match at {
            0 => &params.genesis_block,
            _ => &blocks[at - 1],
        };
        notifier.notify(connect_ntfn(&indexes.queryer, block, parent));
    }
    assert!(notifier.wait_processed(), "the thread is running");
    assert!(
        !chain.lock().expect("chain").is_current_at(old),
        "a current chain forces its flushes"
    );
    assert!(
        durable.load(Ordering::SeqCst) > started,
        "the index asked for no durable commit"
    );

    // What an unclean stop leaves.
    let copy = dir.path().join("unclean");
    copy_dir(&path, &copy);
    let copy_db = Database::open(&Options::new(&copy, params.net.0)).expect("open the copy");
    let mut recorded = None;
    copy_db
        .view(|tx| {
            let best = db_fetch_best_state(tx).expect("best state").hash;
            let set = db_fetch_utxo_set_state(tx)
                .expect("utxo set state")
                .expect("a recorded utxo set state");
            recorded = Some((best, set.last_flush_hash));
            Ok(())
        })
        .expect("read the states");
    let (best, set_state) = recorded.expect("the states");
    let main_chain: Vec<Hash> = std::iter::once(params.genesis_hash)
        .chain(blocks.iter().map(|block| block.header.block_hash()))
        .collect();
    let height_of = |hash: &Hash| {
        main_chain
            .iter()
            .position(|block| block == hash)
            .expect("a block of the chain")
    };
    let best_height = height_of(&best);
    assert!(
        height_of(&set_state) > 0,
        "no UTXO flush reached the disk in a commit the index asked for"
    );
    assert!(
        height_of(&set_state) <= best_height,
        "the utxo set state is past the best state"
    );

    // The next start: the chain replays its UTXO set to the best state,
    // and the index, whose tip is not past it either, catches up.
    let reopened = Arc::new(Mutex::new(
        Chain::open_with_config(copy_db.clone(), &params, open_config()).expect("reopen chain"),
    ));
    assert_eq!(reopened.lock().expect("chain").best_snapshot().hash, best);
    let queryer = Arc::new(NodeChainQueryer::new(Arc::clone(&reopened), params.clone()));
    let mut subscriber = IndexSubscriber::new(Arc::new(AtomicBool::new(false)), None);
    let index = ExistsAddrIndex::new_with_policy(
        &mut subscriber,
        Arc::new(copy_db.clone()),
        Arc::clone(&queryer) as Arc<dyn ChainQueryer>,
        NO_PREREQS,
        policy,
    )
    .expect("reopen the index");
    let tip_of = || {
        let index = index.lock().expect("index");
        index.query().tip().expect("index tip").1
    };
    let durable_index_height = height_of(&tip_of());
    assert!(
        durable_index_height <= best_height,
        "the index tip is past the best state"
    );
    subscriber.catch_up(&*queryer).expect("catch up");
    assert_eq!(tip_of(), best, "the index caught up to the best state");

    // The reference: the same blocks on a current chain, every flush
    // durable, indexed by a catch-up.
    let reference = Node::new(Delivery::Inline, now, &blocks[..best_height]);
    let mut expected = reference.state(&blocks[..best_height]).keys;
    for (connect, seed) in MEMPOOL {
        // The address went to the index with the connect of the block at
        // this position, one below its height.
        if connect < durable_index_height {
            expected.push(mempool_key(seed).1);
        }
    }
    expected.sort_unstable();
    expected.dedup();
    let mut keys = index.lock().expect("index").logical_keys().expect("keys");
    keys.sort_unstable();
    assert_eq!(keys, expected, "the index's keys after the catch-up");
    assert_eq!(
        reopened
            .lock()
            .expect("chain")
            .fetch_utxo_stats()
            .expect("stats"),
        reference
            .chain
            .lock()
            .expect("chain")
            .fetch_utxo_stats()
            .expect("reference stats"),
        "the replayed utxo set"
    );
}

// ---------------------------------------------------------------------
// The daemon's own wiring
// ---------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod daemon {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::process::{Child, Command, Stdio};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use dcroxide_testutil::unhex;
    use dcroxide_wire::MsgBlock;

    /// Kills a daemon however the test ends.
    struct KillOnDrop(Child);

    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// Collect everything a pipe carries, on a thread of its own, which
    /// ends when the pipe's writer has gone.
    fn collect(
        mut pipe: impl Read + Send + 'static,
    ) -> (Arc<Mutex<Vec<u8>>>, std::thread::JoinHandle<()>) {
        let collected = Arc::new(Mutex::new(Vec::<u8>::new()));
        let sink = Arc::clone(&collected);
        let reader = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = pipe.read(&mut buf) {
                if n == 0 {
                    break;
                }
                sink.lock().expect("sink").extend_from_slice(&buf[..n]);
            }
        });
        (collected, reader)
    }

    /// The payload of the first `rpclistenaddr` pipe message in the
    /// stream (dcrd `ipc.go` framing).
    fn rpc_listen_addr(bytes: &[u8]) -> Option<String> {
        const KIND: &[u8] = b"rpclistenaddr";
        let at = bytes
            .windows(2 + KIND.len())
            .position(|w| w[0] == 1 && w[1] as usize == KIND.len() && &w[2..] == KIND)?;
        let len_at = at + 2 + KIND.len();
        let len = u32::from_le_bytes(bytes.get(len_at..len_at + 4)?.try_into().ok()?) as usize;
        let payload = bytes.get(len_at + 4..len_at + 4 + len)?;
        Some(String::from_utf8_lossy(payload).into_owned())
    }

    /// One JSON-RPC request over plain HTTP with the `user`/`pass`
    /// credentials; the response body.
    fn rpc_call(addr: &str, method: &str, params: &str) -> String {
        let body = format!(r#"{{"jsonrpc":"1.0","id":1,"method":"{method}","params":{params}}}"#);
        let mut stream = TcpStream::connect(addr).expect("connect to the RPC server");
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .expect("timeout");
        write!(
            stream,
            "POST / HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .expect("send the request");
        let mut response = Vec::new();
        let _ = stream.read_to_end(&mut response);
        let response = String::from_utf8_lossy(&response).into_owned();
        match response.split_once("\r\n\r\n") {
            Some((_, body)) => body.to_string(),
            None => response,
        }
    }

    /// The string result of a JSON-RPC response.
    fn string_result(response: &str) -> String {
        let rest = response
            .split_once(r#""result":""#)
            .unwrap_or_else(|| panic!("no string result: {response}"))
            .1;
        rest[..rest.find('"').expect("closing quote")].to_string()
    }

    /// Ask until the answer holds `wanted`, for as long as the daemon
    /// answers that the index is behind: the reply to a caller that asks
    /// while the index thread still has the newest blocks queued.  Any
    /// other answer fails at once, and so does an index that stays behind
    /// until the deadline, which is how one nothing feeds answers once the
    /// chain is more than five blocks ahead of it.
    fn ask_until_synced(addr: &str, method: &str, params: &str, wanted: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let response = rpc_call(addr, method, params);
            if response.contains(wanted) {
                return response;
            }
            assert!(
                response.contains("index not synced"),
                "{method} {params}: {response}"
            );
            assert!(
                Instant::now() < deadline,
                "{method} {params}: the index never caught up with the chain: {response}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// The names of the daemon's threads.
    fn thread_names(pid: u32) -> Vec<String> {
        std::fs::read_dir(format!("/proc/{pid}/task"))
            .expect("the daemon's tasks")
            .filter_map(|task| std::fs::read_to_string(task.ok()?.path().join("comm")).ok())
            .map(|name| name.trim_end().to_string())
            .collect()
    }

    /// How many times the daemon's threads named `name` have blocked
    /// (`voluntary_ctxt_switches` in each one's `/proc` status).
    fn times_blocked(pid: u32, name: &str) -> u64 {
        std::fs::read_dir(format!("/proc/{pid}/task"))
            .expect("the daemon's tasks")
            .filter_map(|task| {
                let dir = task.ok()?.path();
                let comm = std::fs::read_to_string(dir.join("comm")).ok()?;
                (comm.trim_end() == name).then_some(dir)
            })
            .filter_map(|dir| std::fs::read_to_string(dir.join("status")).ok())
            .filter_map(|status| {
                status
                    .lines()
                    .find_map(|line| line.strip_prefix("voluntary_ctxt_switches:"))
                    .and_then(|n| n.trim().parse::<u64>().ok())
            })
            .sum()
    }

    /// What a line of the metadata flush log ends with: the name of the
    /// thread that ran the flush, if it has one, and the waits for the
    /// database's writer so far as the index thread's count and
    /// nanoseconds, then every other thread's.
    fn flush_log_tail(line: &str) -> (Option<&str>, [u64; 4]) {
        fn field<'a>(text: &'a str, key: &str) -> (&'a str, &'a str) {
            text.split_once(key)
                .unwrap_or_else(|| panic!("no {key} in {text}"))
        }
        let (_, tail) = field(line, r#","thread":"#);
        let (thread, waits) = field(tail, r#","writer_wait":{"index":{"count":"#);
        let thread = match thread {
            "null" => None,
            quoted => Some(
                quoted
                    .strip_prefix('"')
                    .and_then(|name| name.strip_suffix('"'))
                    .unwrap_or_else(|| panic!("an unquoted thread name in {line}")),
            ),
        };
        let (index_count, waits) = field(waits, r#","ns":"#);
        let (index_ns, waits) = field(waits, r#"},"other":{"count":"#);
        let (other_count, waits) = field(waits, r#","ns":"#);
        let other_ns = waits
            .strip_suffix("}}}")
            .unwrap_or_else(|| panic!("the waits do not end {line}"));
        let number = |text: &str| -> u64 {
            text.parse()
                .unwrap_or_else(|_| panic!("{text} is not a count in {line}"))
        };
        (
            thread,
            [
                number(index_count),
                number(index_ns),
                number(other_count),
                number(other_ns),
            ],
        )
    }

    /// The daemon's own wiring: both indexes follow the chain while the
    /// node runs, with no restart to catch them up.
    ///
    /// A simnet daemon mines eight blocks over RPC.  That is more than the
    /// five the RPC handlers let an index trail before they answer "index
    /// not synced" without waiting, so an index nothing feeds -- the
    /// thread never started or dropped at once, or its sending end given
    /// to the handler after a clone was taken -- answers that for ever,
    /// where every other test of the daemon would pass: they query an
    /// index only after a restart, whose catch-up rebuilds it from the
    /// chain.  Here `existsaddress` must find the mining address, which
    /// only the mined coinbases pay, and `getrawtransaction` must find the
    /// last block's coinbase through the transaction index.
    ///
    /// The daemon must also run exactly one thread named "index", stop
    /// cleanly, which joins that thread, and log no index error.  And
    /// that thread must be the one that did the indexing: it is seen to
    /// have blocked more often after the blocks than before them, which
    /// a thread left asleep by a handler that delivers on the draining
    /// thread would not have.
    ///
    /// The daemon is also asked for its metadata flush log
    /// (`DCROXIDE_DB_FLUSHLOG`), which must come out with a line for
    /// every flush.
    #[test]
    fn the_daemon_index_follows_the_chain_without_a_restart() {
        const BLOCKS: usize = 8;
        let params = dcroxide_chaincfg::simnet_params();
        let mining_addr = dcroxide_txscript::stdaddr::new_address_pub_key_hash_ecdsa_secp256k1_v0(
            &[0x5a; 20],
            &params,
        )
        .expect("mining address")
        .encode();
        let appdata = tempfile::tempdir().expect("appdata");
        let flush_log = appdata.path().join("flushes.jsonl");
        let mut child = Command::new(env!("CARGO_BIN_EXE_dcroxide"))
            .arg("--simnet")
            .arg(format!("--appdata={}", appdata.path().display()))
            .args([
                "--noseeders",
                "--nolisten",
                "--txindex",
                "--rpclisten=127.0.0.1:0",
                "--notls",
                "--rpcuser=user",
                "--rpcpass=pass",
                // The bound RPC address arrives over the pipe.
                "--pipetx=2",
                "--boundaddrevents",
            ])
            .arg(format!("--miningaddr={mining_addr}"))
            .env_remove("DCRD_APPDATA")
            .env("DCROXIDE_DB_FLUSHLOG", &flush_log)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn dcroxide");
        let (events, _) = collect(child.stderr.take().expect("stderr pipe"));
        let (log, log_reader) = collect(child.stdout.take().expect("stdout pipe"));
        let mut daemon = KillOnDrop(child);
        let log_text = || String::from_utf8_lossy(&log.lock().expect("log")).into_owned();

        let deadline = Instant::now() + Duration::from_secs(60);
        let addr = loop {
            if let Some(addr) = rpc_listen_addr(&events.lock().expect("events")) {
                break addr;
            }
            assert!(
                Instant::now() < deadline,
                "the RPC listener never announced its address: {}",
                log_text()
            );
            std::thread::sleep(Duration::from_millis(50));
        };

        let names = thread_names(daemon.0.id());
        assert_eq!(
            names.iter().filter(|name| name.as_str() == "index").count(),
            1,
            "one index thread among {names:?}"
        );
        let idle = times_blocked(daemon.0.id(), "index");

        let mined = rpc_call(&addr, "generate", &format!("[{BLOCKS}]"));
        assert!(mined.contains(r#""error":null"#), "{mined}");

        let found = ask_until_synced(
            &addr,
            "existsaddress",
            &format!(r#"["{mining_addr}"]"#),
            r#""result":true"#,
        );
        assert!(found.contains(r#""error":null"#), "{found}");

        // The index thread itself did the work: it woke for the queued
        // notifications and blocked again.  A daemon that started the
        // thread and delivered inline would leave it asleep.
        let deadline = Instant::now() + Duration::from_secs(30);
        while times_blocked(daemon.0.id(), "index") <= idle {
            assert!(
                Instant::now() < deadline,
                "the index thread never ran: {}",
                log_text()
            );
            std::thread::sleep(Duration::from_millis(50));
        }

        let tip = string_result(&rpc_call(&addr, "getblockhash", &format!("[{BLOCKS}]")));
        let raw = unhex(&string_result(&rpc_call(
            &addr,
            "getblock",
            &format!(r#"["{tip}",false]"#),
        )));
        let (block, _) = MsgBlock::from_bytes(&raw).expect("the tip block");
        let coinbase = &block.transactions[0];
        let fetched = ask_until_synced(
            &addr,
            "getrawtransaction",
            &format!(r#"["{}",0]"#, coinbase.tx_hash()),
            r#""error":null"#,
        );
        assert_eq!(
            unhex(&string_result(&fetched)),
            coinbase.serialize(),
            "the transaction index's region of the tip's coinbase"
        );

        let _ = rpc_call(&addr, "stop", "[]");
        let deadline = Instant::now() + Duration::from_secs(60);
        let status = loop {
            if let Some(status) = daemon.0.try_wait().expect("wait") {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "the daemon never stopped: {}",
                log_text()
            );
            std::thread::sleep(Duration::from_millis(50));
        };
        // The daemon held the pipe's only writing end, so the collector
        // reads to its end now.
        log_reader.join().expect("log reader");
        let output = log_text();
        assert!(status.success(), "{status:?}: {output}");
        assert!(output.contains("Server shutdown complete"), "{output}");
        assert!(
            !output.contains("missing index notification"),
            "an index missed a block: {output}"
        );
        // An update the stop request caught between an index's commit and
        // its return reports the interrupt, as it does under inline
        // delivery; every other index error is a failure.
        let index_errors: Vec<&str> = output
            .lines()
            .filter(|line| line.contains("[ERR] INDX: ") && !line.contains("interrupt requested"))
            .collect();
        assert!(index_errors.is_empty(), "{index_errors:?} in: {output}");

        // The flush log has a line for each flush in order, ending in
        // the thread that ran it and the running totals of the waits
        // for the database's writer.
        let flushes = std::fs::read_to_string(&flush_log).expect("the flush log");
        assert!(flushes.ends_with("}\n"), "whole lines: {flushes:?}");
        let mut totals = [0u64; 4];
        for (i, line) in flushes.lines().enumerate() {
            assert!(
                line.starts_with(&format!(r#"{{"seq":{},"end":"#, i + 1)),
                "flush {}: {line}",
                i + 1
            );
            let (thread, waits) = flush_log_tail(line);
            if let Some(name) = thread {
                // A name that reads the same quoted as JSON.
                assert!(
                    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
                    "the thread of flush {}: {line}",
                    i + 1
                );
            }
            for (now, before) in waits.iter().zip(totals) {
                assert!(*now >= before, "a total ran backwards: {flushes}");
            }
            totals = waits;
        }
    }
}
