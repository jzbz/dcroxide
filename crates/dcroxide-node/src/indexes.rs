// SPDX-License-Identifier: ISC
//! The daemon's optional index wiring (dcrd `newServer`'s index
//! block): the chain queryer the indexes consult, the startup path
//! that creates the enabled indexes and catches them up to the main
//! chain over one shared subscriber, the mempool's unconfirmed hook,
//! and the RPC-facing seams `getrawtransaction`, `existsaddress`,
//! and `existsaddresses` consume.
//!
//! dcrd delivers index notifications through a buffered channel into
//! the subscriber's handler goroutine, and so does the daemon.  The
//! chain handler's post-processing drain (see `chainntfns`) queues each
//! notification on a bounded first-in, first-out queue of dcrd's depth
//! ([`INDEX_NTFN_BUFFER_SIZE`]), and one thread named "index"
//! ([`IndexThread`]) takes them in order and calls the subscriber, whose
//! state transitions are dcrd's.  The thread that connected the block
//! only builds the notification, copies the exists address index's
//! unconfirmed overlay for a connect, and sends; a full queue blocks it,
//! as dcrd's channel blocks its notification handler.  Index maintenance
//! therefore overlaps the processing of the blocks that follow, and an
//! index can trail the chain by a little more than the queue's depth.
//! The RPC handlers allow for that as dcrd's do: through the seams below
//! they wait a few seconds for an index within five blocks of the chain
//! tip, and answer "index not synced" for one further behind.
//!
//! Two things are not dcrd's.  The overlay is copied when the connect is
//! queued, where dcrd's goroutine drains the map when it reaches the
//! block, so the keys that go to disk with a block do not depend on how
//! far the index trails.  And the daemon stops and joins the thread
//! before its final flushes, where dcrd flushes first.  What is still
//! queued at shutdown is dropped, as dcrd drops it, and the next start's
//! catch-up indexes those blocks.
//!
//! A chain handler given the subscriber itself
//! (`ChainNtfnHandler::set_index_subscriber`) calls it on the draining
//! thread instead, with no queue: that is for callers that run no index
//! thread, which today are in-process tests.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::Params;
use dcroxide_chainhash::Hash;
use dcroxide_database::{BlockRegion, Database};
use dcroxide_indexers::{
    CONNECT_NTFN, ChainQueryer, EXISTS_ADDRESS_INDEX_NAME, ExistsAddrIndex, ExistsAddrOverlayCopy,
    ExistsAddrPolicy, ExistsAddrQuery, ExistsAddrUnconfirmed, IdxError, IndexNtfn, IndexSubscriber,
    Interrupt, LogLevel, LogSink, NO_PREREQS, TX_INDEX_NAME, TxIndex, TxIndexQuery,
};
use dcroxide_rpc::server::{RpcDb, RpcExistsAddresser, RpcTxIndexEntry, RpcTxIndexer};
use dcroxide_txscript::stdaddr::Address;
use dcroxide_wire::{BlockHeader, MsgBlock};

/// How long the RPC seam waits for the index to reach the chain tip
/// before reporting it unsynced (dcrd rpcserver `syncWait`).
const SYNC_WAIT: Duration = Duration::from_secs(3);

/// How often the wait polls the sync condition; dcrd's subscriber
/// re-checks it on a 500ms ticker (`syncUpdateInterval`) and inline
/// after every processed notification, so polling the same condition
/// only trades latency.
const SYNC_POLL: Duration = Duration::from_millis(100);

/// The chain queryer the indexes consult, over the daemon's shared
/// chain (dcrd `blockchain.ChainQueryerAdapter`).
pub struct NodeChainQueryer {
    chain: Arc<Mutex<Chain>>,
    params: Params,
}

impl NodeChainQueryer {
    /// A queryer over the shared chain for the given network.
    pub fn new(chain: Arc<Mutex<Chain>>, params: Params) -> NodeChainQueryer {
        NodeChainQueryer { chain, params }
    }

    fn locked(&self) -> std::sync::MutexGuard<'_, Chain> {
        self.chain.lock().expect("chain mutex poisoned")
    }
}

impl ChainQueryer for NodeChainQueryer {
    fn main_chain_has_block(&self, hash: &Hash) -> bool {
        self.locked().main_chain_has_block(hash)
    }

    fn chain_params(&self) -> &Params {
        &self.params
    }

    fn best(&self) -> (i64, Hash) {
        let chain = self.locked();
        let best = chain.best_snapshot();
        (best.height, best.hash)
    }

    fn block_header_by_hash(&self, hash: &Hash) -> Result<BlockHeader, String> {
        self.locked()
            .header_by_hash(hash)
            .ok_or_else(|| format!("block {hash} is not known"))
    }

    fn block_hash_by_height(&self, height: i64) -> Result<Hash, String> {
        self.locked()
            .block_hash_by_height(height)
            .ok_or_else(|| format!("no block at height {height} exists"))
    }

    fn block_height_by_hash(&self, hash: &Hash) -> Result<i64, String> {
        self.locked()
            .block_height_by_hash(hash)
            .ok_or_else(|| format!("block {hash} is not in the main chain"))
    }

    fn block_by_hash(&self, hash: &Hash) -> Result<Arc<MsgBlock>, String> {
        self.locked()
            .block_by_hash(hash)
            .map(Arc::new)
            .ok_or_else(|| format!("unable to fetch block {hash}"))
    }

    fn is_treasury_agenda_active(&self, hash: &Hash) -> Result<bool, String> {
        self.locked()
            .is_treasury_agenda_active(hash, &self.params)
            .map_err(|e| e.description)
    }
}

/// The daemon's live indexes: the enabled index handles with the
/// subscriber that maintains them (dcrd's `server` holding `txIndex`,
/// `existsAddrIndex`, and `indexSubscriber`).
pub struct NodeIndexes {
    /// The shared transaction index, when enabled.
    pub tx_index: Option<Arc<Mutex<TxIndex>>>,
    /// The shared exists address index, when enabled.
    pub exists_addr_index: Option<Arc<Mutex<ExistsAddrIndex>>>,
    /// The subscriber feeding the indexes: the index thread calls it for
    /// each queued notification, and a chain handler set up for inline
    /// delivery calls it from its drain.
    pub subscriber: Arc<Mutex<IndexSubscriber>>,
    /// The queryer every index consults.
    pub queryer: Arc<NodeChainQueryer>,
}

/// Where the index startup logs.  The default logs nothing.
#[derive(Clone, Default)]
pub struct IndexLogs {
    /// The indexers' package logger (dcrd `indexers.UseLogger`), which
    /// both dcrd callers bind to `INDX` (`log.go:90`;
    /// `cmd/addblock/addblock.go:78`): a resumed drop, the recovery and
    /// the catch-up.
    pub indexers: Option<LogSink>,
    /// The caller's own logger for the "Transaction index is enabled"
    /// and "Exists address index is enabled" lines: `INDX` in the daemon
    /// (`indxLog.Info`, `server.go:4030`, `:4037`) and `MAIN` in addblock
    /// (`log.Info`, `cmd/addblock/import.go:344`, `:352`).
    pub announce: Option<LogSink>,
}

impl IndexLogs {
    /// Announce an enabled index, ahead of creating it.
    fn announce(&self, msg: &str) {
        if let Some(sink) = &self.announce {
            sink(LogLevel::Info, msg);
        }
    }
}

/// Create the enabled indexes and catch them up to the main chain
/// (dcrd `newServer`'s index block: `indexers.NewTxIndex` when
/// `cfg.TxIndex` is set, `indexers.NewExistsAddrIndex` when the
/// exists address index is not disabled, then one `CatchUp` over the
/// shared subscriber).  Creation recovers a tip that is no longer on
/// the main chain by rolling the index back first.
///
/// Each index is announced just ahead of its creation, as dcrd's callers
/// do, so the lines its creation logs -- a resumed drop, a recovery --
/// follow its own announcement and precede the next index's.
pub fn start_indexes(
    interrupt: Interrupt,
    db: Arc<Database>,
    chain: Arc<Mutex<Chain>>,
    params: Params,
    tx_index: bool,
    exists_addr_index: bool,
    logs: &IndexLogs,
) -> Result<NodeIndexes, IdxError> {
    start_indexes_with_policy(
        interrupt,
        db,
        chain,
        params,
        tx_index,
        exists_addr_index,
        logs,
        ExistsAddrPolicy::default(),
    )
}

/// [`start_indexes`] with the exists address index's memtable and merge
/// tuning given: the daemon passes what the developer-only
/// `DCROXIDE_EXISTSADDR_MEMTABLE_KEYS` sets, which changes the pages its
/// flushes write and the memory it holds, never an answer.
#[allow(
    clippy::too_many_arguments,
    reason = "start_indexes' arguments plus the one tuning value"
)]
pub fn start_indexes_with_policy(
    interrupt: Interrupt,
    db: Arc<Database>,
    chain: Arc<Mutex<Chain>>,
    params: Params,
    tx_index: bool,
    exists_addr_index: bool,
    logs: &IndexLogs,
    exists_addr_policy: ExistsAddrPolicy,
) -> Result<NodeIndexes, IdxError> {
    let queryer = Arc::new(NodeChainQueryer::new(chain, params));
    let mut subscriber = IndexSubscriber::new(interrupt, logs.indexers.clone());
    let tx_index = if tx_index {
        logs.announce("Transaction index is enabled");
        Some(TxIndex::new(
            &mut subscriber,
            Arc::clone(&db),
            Arc::clone(&queryer) as Arc<dyn ChainQueryer>,
        )?)
    } else {
        None
    };
    let exists_addr_index = if exists_addr_index {
        logs.announce("Exists address index is enabled");
        Some(ExistsAddrIndex::new_with_policy(
            &mut subscriber,
            db,
            Arc::clone(&queryer) as Arc<dyn ChainQueryer>,
            NO_PREREQS,
            exists_addr_policy,
        )?)
    } else {
        None
    };
    subscriber.catch_up(&*queryer)?;
    Ok(NodeIndexes {
        tx_index,
        exists_addr_index,
        subscriber: Arc::new(Mutex::new(subscriber)),
        queryer,
    })
}

/// How many index notifications queue for the index thread before
/// [`IndexNotifier::notify`] blocks its caller (dcrd `bufferSize`,
/// `indexsubscriber.go:34`).
pub const INDEX_NTFN_BUFFER_SIZE: usize = 128;

/// An entry of the index thread's queue.
enum IndexMsg {
    /// A notification and, for a connect, the exists address index's
    /// unconfirmed overlay as it stood when the connect was queued.
    Ntfn(IndexNtfn, Option<ExistsAddrOverlayCopy>),
    /// Answered once everything queued ahead of it has been processed
    /// (what dcrd's tests use `IndexNtfn.Done` for).
    Barrier(mpsc::Sender<()>),
}

/// Hand one notification to the subscribed indexes and log a failed
/// update (dcrd `handleIndexUpdates`' loop body).  A failed update is
/// logged and ends this notification's walk over the subscriptions, and
/// every later notification is still processed, exactly as in dcrd: the
/// `s.cancel()` there cancels only the context the indexes were
/// initialized with, while the handler loop runs on the server's context
/// and keeps consuming notifications.  An index that missed an update
/// therefore logs dcrd's missing-notification error for each later block
/// and resumes on its own once the heights line up again (a reorg
/// replacing the failed block).  The subscriber's `cancelled` latch,
/// dcrd's cancelled context, is deliberately not consulted.
///
/// The indexes need their notifications in the chain's emission order.
/// Both callers get that from the chain handler's drain lock, which every
/// production drain holds from taking a batch of block events to handing
/// over the last of them: the inline path calls this under it, and the
/// queued path sends under it into one first-in, first-out queue with one
/// consumer.  `ChainNtfnHandler::drain_pending_block_events` is the one
/// entry point that drains without that lock; its callers are tests, each
/// draining from a single thread.
///
/// `copy` is the queued path's: the exists address index's unconfirmed
/// overlay as copied when a connect was queued, which that index's
/// connect then hands over in place of the overlay as it stands now
/// (`ExistsAddrUnconfirmed::with_copy`).  The inline path passes `None`
/// and the connect copies the overlay itself, at the same point of the
/// drain.
pub(crate) fn deliver_index_ntfn(
    subscriber: &Mutex<IndexSubscriber>,
    ntfn: &IndexNtfn,
    copy: Option<(&ExistsAddrUnconfirmed, ExistsAddrOverlayCopy)>,
) {
    let mut subscriber = subscriber.lock().expect("index subscriber mutex poisoned");
    let updated = match copy {
        Some((unconfirmed, copy)) => unconfirmed.with_copy(copy, || subscriber.notify(ntfn)),
        None => subscriber.notify(ntfn),
    };
    if let Err(e) = updated {
        // dcrd's `log.Error(err)` under the INDX subsystem, once per
        // failed notification.
        crate::logging::error("INDX", &e.to_string());
    }
}

/// The sending end of the index thread's queue (dcrd
/// `IndexSubscriber.Notify` sending on the subscriber's channel).
#[derive(Clone)]
pub struct IndexNotifier {
    queue: SyncSender<IndexMsg>,
    /// The exists address index's unconfirmed overlay, when that index is
    /// enabled: what [`IndexNotifier::notify`] copies for a connect.
    unconfirmed: Option<ExistsAddrUnconfirmed>,
}

impl IndexNotifier {
    /// Queue a notification for the index thread (dcrd `Notify`).  Blocks
    /// while the queue is full, as dcrd's send does, and drops the
    /// notification once the thread has stopped, as dcrd's `quit` case
    /// does.  A connect's copy of the unconfirmed overlay is made here,
    /// before the wait, so it is the overlay as the block connected:
    /// where dcrd's handler goroutine drains the map when it reaches the
    /// block, the keys that go to disk with a block here do not depend on
    /// how far the index trails.
    pub fn notify(&self, ntfn: IndexNtfn) {
        let copy = match &self.unconfirmed {
            Some(unconfirmed) if ntfn.ntfn_type == CONNECT_NTFN => {
                Some(unconfirmed.copy_for_connect())
            }
            _ => None,
        };
        let _ = self.queue.send(IndexMsg::Ntfn(ntfn, copy));
    }

    /// Wait until the index thread has processed everything queued before
    /// this call; `false` when it has stopped instead.
    pub fn wait_processed(&self) -> bool {
        let (done, processed) = mpsc::channel();
        self.queue.send(IndexMsg::Barrier(done)).is_ok() && processed.recv().is_ok()
    }
}

/// The daemon's index thread (dcrd's `IndexSubscriber.Run` goroutine and
/// its `handleIndexUpdates` loop): the one consumer of a bounded queue of
/// index notifications, each of which it hands to the subscriber the
/// indexes were created over.
///
/// Stopping it is stop-and-join, not a drain: what is still queued is
/// dropped, as dcrd's handler drops it on `ctx.Done()`, and the next
/// start's catch-up indexes those blocks.  Dropping the handle stops and
/// joins the thread too, so it never outlives the index handles or the
/// database on any return path of its owner.
pub struct IndexThread {
    notifier: IndexNotifier,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl IndexThread {
    /// Start the thread over the live indexes with dcrd's queue depth.
    pub fn start(indexes: &NodeIndexes) -> std::io::Result<IndexThread> {
        IndexThread::start_with_capacity(indexes, INDEX_NTFN_BUFFER_SIZE)
    }

    /// [`IndexThread::start`] with the queue depth given (at least one),
    /// for tests.
    pub fn start_with_capacity(
        indexes: &NodeIndexes,
        capacity: usize,
    ) -> std::io::Result<IndexThread> {
        let unconfirmed = indexes.exists_addr_index.as_ref().map(|index| {
            index
                .lock()
                .expect("exists addr index mutex poisoned")
                .unconfirmed()
        });
        IndexThread::start_with(Arc::clone(&indexes.subscriber), unconfirmed, capacity)
    }

    /// [`IndexThread::start_with_capacity`] over the subscriber and the
    /// exists address index's unconfirmed overlay (`None` when that index
    /// is not subscribed), for callers that hold no [`NodeIndexes`].
    pub fn start_with(
        subscriber: Arc<Mutex<IndexSubscriber>>,
        unconfirmed: Option<ExistsAddrUnconfirmed>,
        capacity: usize,
    ) -> std::io::Result<IndexThread> {
        // At least one slot: the wake-up entry `stop_and_join` sends needs
        // somewhere to wait while the thread is busy.  A rendezvous queue
        // would refuse it, and the thread would then park in `recv` with
        // nothing to wake it.
        let (queue, entries) = mpsc::sync_channel(capacity.max(1));
        let interrupt = subscriber
            .lock()
            .expect("index subscriber mutex poisoned")
            .interrupt();
        let stop = Arc::new(AtomicBool::new(false));
        let (overlay, stopped) = (unconfirmed.clone(), Arc::clone(&stop));
        // The name the database totals this thread's waits for its
        // writer under.
        let thread = std::thread::Builder::new()
            .name(dcroxide_database::INDEX_THREAD_NAME.to_string())
            .spawn(move || {
                run_index_thread(
                    &entries,
                    &subscriber,
                    overlay.as_ref(),
                    &interrupt,
                    &stopped,
                );
            })?;
        Ok(IndexThread {
            notifier: IndexNotifier { queue, unconfirmed },
            stop,
            thread: Some(thread),
        })
    }

    /// A sending end for the chain handler.
    pub fn notifier(&self) -> IndexNotifier {
        self.notifier.clone()
    }

    /// Stop the thread and wait for it.  What is still queued is dropped,
    /// as dcrd drops it, and the next start's catch-up indexes it.
    pub fn shutdown(mut self) {
        self.stop_and_join();
    }

    fn stop_and_join(&mut self) {
        let Some(thread) = self.thread.take() else {
            return;
        };
        self.stop.store(true, Ordering::SeqCst);
        // Wake a thread idle in `recv`.  A full queue refuses this, and
        // then the thread is busy and reads the flag before its next entry.
        let (done, _unread) = mpsc::channel();
        let _ = self.notifier.queue.try_send(IndexMsg::Barrier(done));
        if thread.join().is_err() {
            crate::logging::error("INDX", "the index thread panicked");
        }
        // dcrd `IndexSubscriber.Run`'s closing line.
        crate::logging::trace("INDX", "Index subscriber stopped");
    }
}

impl Drop for IndexThread {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

/// The index thread's body (dcrd `handleIndexUpdates`): take the queue's
/// entries in order until a stop or the daemon's interrupt is seen, or
/// until every sending end is gone.  Returning drops the receiving end,
/// which releases a sender blocked on a full queue and makes every later
/// send a no-op.
fn run_index_thread(
    entries: &Receiver<IndexMsg>,
    subscriber: &Mutex<IndexSubscriber>,
    unconfirmed: Option<&ExistsAddrUnconfirmed>,
    interrupt: &Interrupt,
    stop: &AtomicBool,
) {
    while let Ok(entry) = entries.recv() {
        // dcrd's `case <-ctx.Done(): return`: nothing more is processed
        // once shutdown is requested, and what is queued is dropped.
        if stop.load(Ordering::SeqCst) || interrupt.load(Ordering::SeqCst) {
            break;
        }
        match entry {
            IndexMsg::Ntfn(ntfn, copy) => {
                deliver_index_ntfn(subscriber, &ntfn, unconfirmed.zip(copy));
            }
            IndexMsg::Barrier(done) => {
                let _ = done.send(());
            }
        }
    }
}

/// Whether the index tip matches the chain tip (dcrd
/// `maybeNotifySubscribers`' condition).  The index tip is read through
/// a query handle, never the index mutex, and the chain lock is taken
/// on its own, so the RPC thread never nests them.
fn index_synced(
    tip: &dyn Fn() -> Result<(i64, Hash), IdxError>,
    queryer: &NodeChainQueryer,
) -> Result<bool, String> {
    let (tip_height, tip_hash) = tip().map_err(|e| e.to_string())?;
    let (best_height, best_hash) = queryer.best();
    Ok(tip_height == best_height && tip_hash == best_hash)
}

/// The sync wait with an injectable deadline for the tests; dcrd
/// races the subscriber's sync signal against `syncWait`.
fn wait_for_index_sync(
    tip: &dyn Fn() -> Result<(i64, Hash), IdxError>,
    queryer: &NodeChainQueryer,
    deadline: Duration,
) -> bool {
    let start = Instant::now();
    loop {
        if index_synced(tip, queryer).unwrap_or(false) {
            return true;
        }
        if start.elapsed() >= deadline {
            return false;
        }
        std::thread::sleep(SYNC_POLL.min(deadline));
    }
}

/// The RPC transaction-index seam over the live index (dcrd assigns
/// the concrete `*indexers.TxIndex` to the rpcserver config's
/// `TxIndexer` interface directly).
///
/// dcrd's `Name`, `Tip` and `Entry` take no index-wide lock.  The seam
/// reads through a [`TxIndexQuery`] taken once at construction, so a
/// `getrawtransaction` never waits on the index writer, which holds the
/// index mutex through its database-writer wait and a block's work.
pub struct NodeRpcTxIndexer {
    query: TxIndexQuery,
    queryer: Arc<NodeChainQueryer>,
}

impl NodeRpcTxIndexer {
    /// A seam over the daemon's live transaction index.
    pub fn new(index: Arc<Mutex<TxIndex>>, queryer: Arc<NodeChainQueryer>) -> NodeRpcTxIndexer {
        let query = index.lock().expect("tx index mutex poisoned").query();
        NodeRpcTxIndexer { query, queryer }
    }
}

impl RpcTxIndexer for NodeRpcTxIndexer {
    fn name(&self) -> String {
        TX_INDEX_NAME.to_string()
    }

    fn tip(&self) -> Result<(i64, Hash), String> {
        self.query.tip().map_err(|e| e.to_string())
    }

    fn entry(&self, tx_hash: &Hash) -> Result<Option<RpcTxIndexEntry>, String> {
        let entry = self.query.entry(tx_hash).map_err(|e| e.to_string())?;
        Ok(entry.map(|e| RpcTxIndexEntry {
            block_hash: e.block_region.hash,
            offset: e.block_region.offset,
            len: e.block_region.len,
            block_index: e.block_index,
        }))
    }

    fn wait_for_sync(&self) -> bool {
        wait_for_index_sync(&|| self.query.tip(), &self.queryer, SYNC_WAIT)
    }
}

/// The RPC exists-address index seam over the live index (dcrd
/// assigns the concrete `*indexers.ExistsAddrIndex` to the rpcserver
/// config's `ExistsAddresser` interface directly).
pub struct NodeRpcExistsAddresser {
    query: ExistsAddrQuery,
    queryer: Arc<NodeChainQueryer>,
}

impl NodeRpcExistsAddresser {
    /// A seam over the daemon's live exists address index.  The lookup
    /// handle is taken once, here, and the index mutex is never touched
    /// again.
    pub fn new(
        index: Arc<Mutex<ExistsAddrIndex>>,
        queryer: Arc<NodeChainQueryer>,
    ) -> NodeRpcExistsAddresser {
        let query = index
            .lock()
            .expect("exists addr index mutex poisoned")
            .query();
        NodeRpcExistsAddresser { query, queryer }
    }

    /// The lookup handle, detached from the index mutex.
    ///
    /// The address lookups below are caller-sized — `existsaddresses`
    /// accepts as many addresses as fit the request body — and the index
    /// writer holds the index mutex through its wait for the database
    /// writer and a whole block's index work.  Reading through the mutex
    /// would stall the indexer for a large lookup, and a lookup behind
    /// the writer for as long as it waits.  dcrd has neither stall: its
    /// `ExistsAddress(es)`, `Tip` and `Name` take no index-wide lock at
    /// all (`existsaddrindex.go` 331-364).
    ///
    /// Pinned by `tests/b6_indexlock.rs` and
    /// `tests/review_index_locks.rs`.
    fn query(&self) -> &ExistsAddrQuery {
        &self.query
    }
}

impl RpcExistsAddresser for NodeRpcExistsAddresser {
    fn name(&self) -> String {
        EXISTS_ADDRESS_INDEX_NAME.to_string()
    }

    fn tip(&self) -> Result<(i64, Hash), String> {
        self.query().tip().map_err(|e| e.to_string())
    }

    fn wait_for_sync(&self) -> bool {
        wait_for_index_sync(&|| self.query().tip(), &self.queryer, SYNC_WAIT)
    }

    fn exists_address(&self, addr: &Address) -> Result<bool, String> {
        self.query().exists_address(addr).map_err(|e| e.to_string())
    }

    fn exists_addresses(&self, addrs: &[Address]) -> Result<Vec<bool>, String> {
        self.query()
            .exists_addresses(addrs)
            .map_err(|e| e.to_string())
    }
}

/// The mempool's unconfirmed-transaction hook over the live exists
/// address index (dcrd's mempool config carrying the concrete
/// `*indexers.ExistsAddrIndex`; `AddUnconfirmedTx` records the
/// transaction's addresses in the memory-only overlay under
/// `unconfirmedLock` alone).
///
/// The hook runs inside `TxPool::add_transaction` with the pool mutex
/// held, so it holds an [`ExistsAddrUnconfirmed`] handle rather than
/// the index mutex: admission never waits on the index writer.
pub struct NodeUnconfirmedAddrIndexer {
    unconfirmed: ExistsAddrUnconfirmed,
}

impl NodeUnconfirmedAddrIndexer {
    /// A hook over the daemon's live exists address index.
    pub fn new(index: Arc<Mutex<ExistsAddrIndex>>) -> NodeUnconfirmedAddrIndexer {
        let unconfirmed = index
            .lock()
            .expect("exists addr index mutex poisoned")
            .unconfirmed();
        NodeUnconfirmedAddrIndexer { unconfirmed }
    }
}

impl dcroxide_mempool::UnconfirmedAddrIndexer for NodeUnconfirmedAddrIndexer {
    fn add_unconfirmed_tx(&mut self, tx: &dcroxide_wire::MsgTx) {
        self.unconfirmed.add_unconfirmed_tx(tx);
    }
}

/// The RPC database seam over the daemon's shared block database
/// (dcrd handing its `database.DB` to the rpcserver config), with the
/// chain whose block index supplies each block's height.
///
/// The database keys a stored block by its height and hash (see
/// `dcroxide_database::Transaction::fetch_block_region` and ADR-0010),
/// where dcrd's ffldb keys it by hash, and a transaction index entry
/// names only the hash.  Every block the index names was connected, so
/// the block index has its node, and the height comes from there, under
/// the chain lock for the lookup alone; the read itself runs with the
/// lock released, as before.  The RPC handler holds no other lock when
/// it calls this.
pub struct NodeRpcDb {
    db: Database,
    chain: Arc<Mutex<Chain>>,
}

impl NodeRpcDb {
    /// A seam over the shared database handle and chain.
    pub fn new(db: Database, chain: Arc<Mutex<Chain>>) -> NodeRpcDb {
        NodeRpcDb { db, chain }
    }
}

impl RpcDb for NodeRpcDb {
    fn fetch_block_region(
        &self,
        block_hash: &Hash,
        offset: u32,
        len: u32,
    ) -> Result<Vec<u8>, String> {
        let height = {
            let chain = self.chain.lock().expect("chain mutex");
            chain
                .index
                .lookup_node(block_hash)
                .map(|node| chain.store.node(node).height as u32)
        };
        // A block the block index does not know is answered as the
        // database answers a block it does not store.
        let Some(height) = height else {
            return Err(format!("block {block_hash} does not exist"));
        };
        let tx = self.db.begin(false).map_err(|e| e.to_string())?;
        let result = tx
            .fetch_block_region(
                &BlockRegion {
                    hash: *block_hash,
                    offset,
                    len,
                },
                height,
            )
            .map_err(|e| e.to_string());
        let _ = tx.rollback();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcroxide_database::Options;

    fn open_genesis_chain(params: &Params) -> (tempfile::TempDir, Database, Arc<Mutex<Chain>>) {
        let dir = tempfile::tempdir().expect("temp dir");
        let opts = Options::new(dir.path().join("blocks"), params.net.0);
        let db = Database::create(&opts).expect("create database");
        let chain = Arc::new(Mutex::new(
            Chain::open(db.clone(), params, params.assume_valid, false, 0).expect("open chain"),
        ));
        (dir, db, chain)
    }

    /// The queryer answers every chain question the indexes ask over
    /// the shared genesis chain.
    #[test]
    fn chain_queryer_answers_over_the_genesis_chain() {
        let params = dcroxide_chaincfg::testnet3_params();
        let genesis_hash = params.genesis_hash;
        let (_dir, _db, chain) = open_genesis_chain(&params);
        let queryer = NodeChainQueryer::new(Arc::clone(&chain), params.clone());

        assert_eq!(queryer.best(), (0, genesis_hash));
        assert!(queryer.main_chain_has_block(&genesis_hash));
        assert!(!queryer.main_chain_has_block(&Hash([7u8; 32])));
        assert_eq!(queryer.chain_params().net, params.net);
        assert_eq!(queryer.block_hash_by_height(0), Ok(genesis_hash));
        assert!(queryer.block_hash_by_height(9).is_err());
        assert_eq!(queryer.block_height_by_hash(&genesis_hash), Ok(0));
        assert!(queryer.block_height_by_hash(&Hash([7u8; 32])).is_err());
        let header = queryer
            .block_header_by_hash(&genesis_hash)
            .expect("genesis header");
        assert_eq!(header.block_hash(), genesis_hash);
        assert!(queryer.block_header_by_hash(&Hash([7u8; 32])).is_err());
        let block = queryer.block_by_hash(&genesis_hash).expect("genesis block");
        assert_eq!(block.header.block_hash(), genesis_hash);
        assert!(queryer.block_by_hash(&Hash([7u8; 32])).is_err());
        let expected = chain
            .lock()
            .expect("chain")
            .is_treasury_agenda_active(&genesis_hash, &params)
            .expect("agenda state");
        assert_eq!(
            queryer.is_treasury_agenda_active(&genesis_hash),
            Ok(expected)
        );
    }

    /// The database seam serves the stored genesis block's regions.
    #[test]
    fn rpc_db_fetches_stored_block_regions() {
        let params = dcroxide_chaincfg::testnet3_params();
        let genesis_hash = params.genesis_hash;
        let (_dir, db, chain) = open_genesis_chain(&params);
        let genesis = chain
            .lock()
            .expect("chain")
            .block_by_hash(&genesis_hash)
            .expect("genesis block");
        let serialized = genesis.serialize();

        let rpc_db = NodeRpcDb::new(db, Arc::clone(&chain));
        let whole = rpc_db
            .fetch_block_region(&genesis_hash, 0, serialized.len() as u32)
            .expect("whole block region");
        assert_eq!(whole, serialized);
        let slice = rpc_db
            .fetch_block_region(&genesis_hash, 8, 16)
            .expect("inner region");
        assert_eq!(slice, serialized[8..24]);
        assert!(rpc_db.fetch_block_region(&Hash([7u8; 32]), 0, 4).is_err());
    }

    /// The index seam over a freshly caught-up index at the genesis
    /// tip: synced immediately, no entries, dcrd's index name.
    #[test]
    fn rpc_tx_indexer_over_a_synced_genesis_index() {
        let params = dcroxide_chaincfg::testnet3_params();
        let genesis_hash = params.genesis_hash;
        let (_dir, db, chain) = open_genesis_chain(&params);
        let interrupt: Interrupt = Arc::new(core::sync::atomic::AtomicBool::new(false));
        let indexes = start_indexes(
            interrupt,
            Arc::new(db),
            chain,
            params,
            true,
            true,
            &IndexLogs::default(),
        )
        .expect("start");
        let tx_index = indexes.tx_index.as_ref().expect("tx index enabled");

        let seam = NodeRpcTxIndexer::new(Arc::clone(tx_index), Arc::clone(&indexes.queryer));
        assert_eq!(seam.name(), "transaction index");
        assert_eq!(seam.tip(), Ok((0, genesis_hash)));
        assert!(matches!(seam.entry(&Hash([7u8; 32])), Ok(None)));
        assert!(seam.wait_for_sync());

        // The exists address index shares the subscriber and answers
        // over the same synced tip.
        let exists = indexes
            .exists_addr_index
            .as_ref()
            .expect("exists index enabled");
        let seam = NodeRpcExistsAddresser::new(Arc::clone(exists), Arc::clone(&indexes.queryer));
        assert_eq!(seam.name(), "exists address index");
        assert_eq!(seam.tip(), Ok((0, genesis_hash)));
        assert!(seam.wait_for_sync());
    }

    /// The sync wait reports false once the deadline passes while the
    /// index tip disagrees with the chain tip (dcrd's `syncWait`
    /// timeout producing the "index not synced" error).
    #[test]
    fn wait_for_sync_times_out_on_a_lagging_index() {
        let simnet = dcroxide_chaincfg::simnet_params();
        let (_dir1, db1, chain1) = open_genesis_chain(&simnet);
        let interrupt: Interrupt = Arc::new(core::sync::atomic::AtomicBool::new(false));
        let indexes = start_indexes(
            interrupt,
            Arc::new(db1),
            chain1,
            simnet,
            true,
            false,
            &IndexLogs::default(),
        )
        .expect("start");
        let tx_index = indexes.tx_index.as_ref().expect("tx index enabled");
        assert!(indexes.exists_addr_index.is_none());

        // A queryer over a different chain makes the tips disagree
        // permanently for the duration of the wait.
        let testnet = dcroxide_chaincfg::testnet3_params();
        let (_dir2, _db2, chain2) = open_genesis_chain(&testnet);
        let other = Arc::new(NodeChainQueryer::new(chain2, testnet));
        let query = tx_index.lock().expect("tx index").query();
        assert!(!wait_for_index_sync(
            &|| query.tip(),
            &other,
            Duration::from_millis(200)
        ));
    }

    /// The daemon shares these seams across the RPC, sync, and signal
    /// threads.
    #[test]
    fn index_seams_are_send() {
        fn assert_send<T: Send>() {}
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NodeChainQueryer>();
        assert_send::<NodeRpcTxIndexer>();
        assert_send::<NodeRpcDb>();
        assert_send::<NodeIndexes>();
        assert_send::<NodeRpcExistsAddresser>();
        assert_send::<NodeUnconfirmedAddrIndexer>();
        // The index thread's handle moves to whichever thread shuts the
        // daemon down, and its sending end is cloned into the chain
        // handler, which the peer, generator and RPC threads share.
        assert_send::<IndexThread>();
        assert_send_sync::<IndexNotifier>();
    }

    /// Stopping the index thread drops what is queued and releases a
    /// sender blocked on the full queue, so neither the shutdown nor the
    /// sender can wait on the other (dcrd's handler returning on
    /// `ctx.Done()`, and `Notify`'s `quit` case).
    ///
    /// One slot, and the thread stalled on the database writer with the
    /// first notification in hand: the second fills the slot and the third
    /// blocks its sender.  The stop request is then made through the flag
    /// itself, before the writer is released, so the thread is certain to
    /// see it at its next entry; `stop` -- [`IndexThread::shutdown`], or
    /// dropping the handle -- makes the same request and joins.  The
    /// notification in hand is not interrupted.
    ///
    /// The join is what the daemon's shutdown order rests on: `stop` must
    /// not return while the thread still has that notification in hand,
    /// or the thread's last commit could land behind the final chain
    /// flush and the closing of the database.  So `stop` is watched for
    /// as long as the writer is held, and must still be waiting.
    fn assert_stopping_joins_the_thread_and_releases_a_blocked_sender(
        stop: impl FnOnce(IndexThread) + Send + 'static,
    ) {
        let params = dcroxide_chaincfg::simnet_params();
        let (_dir, db, chain) = open_genesis_chain(&params);
        let interrupt: Interrupt = Arc::new(AtomicBool::new(false));
        let indexes = start_indexes(
            interrupt,
            Arc::new(db.clone()),
            chain,
            params.clone(),
            false,
            true,
            &IndexLogs::default(),
        )
        .expect("start");
        // Taken before the stall: the stalled thread holds the index
        // mutex while it waits for the writer.
        let query = indexes
            .exists_addr_index
            .as_ref()
            .expect("exists index enabled")
            .lock()
            .expect("exists index")
            .query();
        let thread = IndexThread::start_with_capacity(&indexes, 1).expect("index thread");
        let notifier = thread.notifier();
        // The update path checks only a notification's height against the
        // index tip, so the genesis block with its height set stands in
        // for a block of the chain.
        let connect_at = |height: u32| {
            let mut block = params.genesis_block.clone();
            block.header.height = height;
            IndexNtfn {
                ntfn_type: CONNECT_NTFN,
                block: Arc::new(block),
                parent: Arc::new(params.genesis_block.clone()),
                is_treasury_enabled: false,
            }
        };

        let hold = db.begin(true).expect("hold the writer");
        notifier.notify(connect_at(1));
        notifier.notify(connect_at(2));
        let (sent, returned) = mpsc::channel();
        let third = {
            let (notifier, ntfn) = (notifier.clone(), connect_at(3));
            std::thread::spawn(move || {
                notifier.notify(ntfn);
                let _ = sent.send(());
            })
        };
        assert!(
            returned.recv_timeout(Duration::from_millis(300)).is_err(),
            "a send into a full queue returned"
        );

        // The thread is inside the first update once it holds the index
        // mutex, which it keeps while it waits for the writer.
        let index = Arc::clone(
            indexes
                .exists_addr_index
                .as_ref()
                .expect("exists index enabled"),
        );
        let waiting_since = Instant::now();
        while index.try_lock().is_ok() {
            assert!(
                waiting_since.elapsed() < Duration::from_secs(60),
                "the thread never took the first notification"
            );
            std::thread::yield_now();
        }

        thread.stop.store(true, Ordering::SeqCst);
        let (joined_tx, joined) = mpsc::channel();
        let stopper = std::thread::spawn(move || {
            stop(thread);
            let _ = joined_tx.send(());
        });
        assert!(
            joined.recv_timeout(Duration::from_millis(300)).is_err(),
            "the stop returned while the thread still held a notification"
        );
        hold.rollback().expect("release the writer");
        stopper.join().expect("the stop returns");
        returned
            .recv_timeout(Duration::from_secs(60))
            .expect("the blocked sender is released");
        third.join().expect("sender");

        let tip = query.tip().expect("tip").0;
        assert!(tip <= 1, "a queued notification was processed: tip {tip}");
        assert!(!notifier.wait_processed(), "a stopped thread answered");
        // A send after the stop is dropped without a wait.
        notifier.notify(connect_at(2));
        assert_eq!(query.tip().expect("tip").0, tip);
    }

    /// [`IndexThread::shutdown`] joins the thread (see
    /// [`assert_stopping_joins_the_thread_and_releases_a_blocked_sender`]).
    #[test]
    fn a_stopped_index_thread_releases_a_blocked_sender() {
        assert_stopping_joins_the_thread_and_releases_a_blocked_sender(IndexThread::shutdown);
    }

    /// Dropping the handle joins the thread too, which is what every
    /// early return of the daemon relies on (see
    /// [`assert_stopping_joins_the_thread_and_releases_a_blocked_sender`]).
    #[test]
    fn a_dropped_index_thread_is_joined_and_releases_a_blocked_sender() {
        assert_stopping_joins_the_thread_and_releases_a_blocked_sender(drop);
    }
}
