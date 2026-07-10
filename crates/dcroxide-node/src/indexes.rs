// SPDX-License-Identifier: ISC
//! The daemon's optional index wiring (dcrd `newServer`'s index
//! block): the chain queryer the indexes consult, the startup path
//! that creates the enabled indexes and catches them up to the main
//! chain over one shared subscriber, the mempool's unconfirmed hook,
//! and the RPC-facing seams `getrawtransaction`, `existsaddress`,
//! and `existsaddresses` consume.
//!
//! dcrd delivers index notifications through a buffered channel into
//! the subscriber's handler goroutine; the daemon delivers them
//! synchronously from the chain handler's post-processing drain with
//! identical state transitions (see `chainntfns`), so the only
//! concurrency here is the shared handles crossing the peer, sync,
//! and RPC threads.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::Params;
use dcroxide_chainhash::Hash;
use dcroxide_database::{BlockRegion, Database};
use dcroxide_indexers::{
    ChainQueryer, ExistsAddrIndex, IdxError, IndexSubscriber, Indexer, Interrupt, TxIndex,
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
    /// The subscriber feeding the indexes; the chain handler's drain
    /// notifies through this handle.
    pub subscriber: Arc<Mutex<IndexSubscriber>>,
    /// The queryer every index consults.
    pub queryer: Arc<NodeChainQueryer>,
}

/// Create the enabled indexes and catch them up to the main chain
/// (dcrd `newServer`'s index block: `indexers.NewTxIndex` when
/// `cfg.TxIndex` is set, `indexers.NewExistsAddrIndex` when the
/// exists address index is not disabled, then one `CatchUp` over the
/// shared subscriber).  Creation recovers a tip that is no longer on
/// the main chain by rolling the index back first.
pub fn start_indexes(
    interrupt: Interrupt,
    db: Arc<Database>,
    chain: Arc<Mutex<Chain>>,
    params: Params,
    tx_index: bool,
    exists_addr_index: bool,
) -> Result<NodeIndexes, IdxError> {
    let queryer = Arc::new(NodeChainQueryer::new(chain, params));
    let mut subscriber = IndexSubscriber::new(interrupt);
    let tx_index = if tx_index {
        Some(TxIndex::new(
            &mut subscriber,
            Arc::clone(&db),
            Arc::clone(&queryer) as Arc<dyn ChainQueryer>,
        )?)
    } else {
        None
    };
    let exists_addr_index = if exists_addr_index {
        Some(ExistsAddrIndex::new(
            &mut subscriber,
            db,
            Arc::clone(&queryer) as Arc<dyn ChainQueryer>,
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

/// Whether the index tip matches the chain tip (dcrd
/// `maybeNotifySubscribers`' condition).  The locks are taken one at
/// a time so the RPC thread never nests them.
fn index_synced<I: Indexer>(
    index: &Arc<Mutex<I>>,
    queryer: &NodeChainQueryer,
) -> Result<bool, String> {
    let (tip_height, tip_hash) = index
        .lock()
        .expect("index mutex poisoned")
        .tip()
        .map_err(|e| e.to_string())?;
    let (best_height, best_hash) = queryer.best();
    Ok(tip_height == best_height && tip_hash == best_hash)
}

/// The sync wait with an injectable deadline for the tests; dcrd
/// races the subscriber's sync signal against `syncWait`.
fn wait_for_index_sync<I: Indexer>(
    index: &Arc<Mutex<I>>,
    queryer: &NodeChainQueryer,
    deadline: Duration,
) -> bool {
    let start = Instant::now();
    loop {
        if index_synced(index, queryer).unwrap_or(false) {
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
pub struct NodeRpcTxIndexer {
    index: Arc<Mutex<TxIndex>>,
    queryer: Arc<NodeChainQueryer>,
}

impl NodeRpcTxIndexer {
    /// A seam over the daemon's live transaction index.
    pub fn new(index: Arc<Mutex<TxIndex>>, queryer: Arc<NodeChainQueryer>) -> NodeRpcTxIndexer {
        NodeRpcTxIndexer { index, queryer }
    }
}

impl RpcTxIndexer for NodeRpcTxIndexer {
    fn name(&mut self) -> String {
        self.index
            .lock()
            .expect("tx index mutex poisoned")
            .name()
            .to_string()
    }

    fn tip(&mut self) -> Result<(i64, Hash), String> {
        self.index
            .lock()
            .expect("tx index mutex poisoned")
            .tip()
            .map_err(|e| e.to_string())
    }

    fn entry(&mut self, tx_hash: &Hash) -> Result<Option<RpcTxIndexEntry>, String> {
        let entry = self
            .index
            .lock()
            .expect("tx index mutex poisoned")
            .entry(tx_hash)
            .map_err(|e| e.to_string())?;
        Ok(entry.map(|e| RpcTxIndexEntry {
            block_hash: e.block_region.hash,
            offset: e.block_region.offset,
            len: e.block_region.len,
            block_index: e.block_index,
        }))
    }

    fn wait_for_sync(&mut self) -> bool {
        wait_for_index_sync(&self.index, &self.queryer, SYNC_WAIT)
    }
}

/// The RPC exists-address index seam over the live index (dcrd
/// assigns the concrete `*indexers.ExistsAddrIndex` to the rpcserver
/// config's `ExistsAddresser` interface directly).
pub struct NodeRpcExistsAddresser {
    index: Arc<Mutex<ExistsAddrIndex>>,
    queryer: Arc<NodeChainQueryer>,
}

impl NodeRpcExistsAddresser {
    /// A seam over the daemon's live exists address index.
    pub fn new(
        index: Arc<Mutex<ExistsAddrIndex>>,
        queryer: Arc<NodeChainQueryer>,
    ) -> NodeRpcExistsAddresser {
        NodeRpcExistsAddresser { index, queryer }
    }
}

impl RpcExistsAddresser for NodeRpcExistsAddresser {
    fn name(&mut self) -> String {
        self.index
            .lock()
            .expect("exists addr index mutex poisoned")
            .name()
            .to_string()
    }

    fn tip(&mut self) -> Result<(i64, Hash), String> {
        self.index
            .lock()
            .expect("exists addr index mutex poisoned")
            .tip()
            .map_err(|e| e.to_string())
    }

    fn wait_for_sync(&mut self) -> bool {
        wait_for_index_sync(&self.index, &self.queryer, SYNC_WAIT)
    }

    fn exists_address(&mut self, addr: &Address) -> Result<bool, String> {
        self.index
            .lock()
            .expect("exists addr index mutex poisoned")
            .exists_address(addr)
            .map_err(|e| e.to_string())
    }

    fn exists_addresses(&mut self, addrs: &[Address]) -> Result<Vec<bool>, String> {
        self.index
            .lock()
            .expect("exists addr index mutex poisoned")
            .exists_addresses(addrs)
            .map_err(|e| e.to_string())
    }
}

/// The mempool's unconfirmed-transaction hook over the live exists
/// address index (dcrd's mempool config carrying the concrete
/// `*indexers.ExistsAddrIndex`; `AddUnconfirmedTx` records the
/// transaction's addresses in the memory-only overlay).
pub struct NodeUnconfirmedAddrIndexer {
    index: Arc<Mutex<ExistsAddrIndex>>,
}

impl NodeUnconfirmedAddrIndexer {
    /// A hook over the daemon's live exists address index.
    pub fn new(index: Arc<Mutex<ExistsAddrIndex>>) -> NodeUnconfirmedAddrIndexer {
        NodeUnconfirmedAddrIndexer { index }
    }
}

impl dcroxide_mempool::UnconfirmedAddrIndexer for NodeUnconfirmedAddrIndexer {
    fn add_unconfirmed_tx(&mut self, tx: &dcroxide_wire::MsgTx) {
        self.index
            .lock()
            .expect("exists addr index mutex poisoned")
            .add_unconfirmed_tx(tx);
    }
}

/// The RPC database seam over the daemon's shared block database
/// (dcrd handing its `database.DB` to the rpcserver config).
pub struct NodeRpcDb {
    db: Database,
}

impl NodeRpcDb {
    /// A seam over the shared database handle.
    pub fn new(db: Database) -> NodeRpcDb {
        NodeRpcDb { db }
    }
}

impl RpcDb for NodeRpcDb {
    fn fetch_block_region(
        &mut self,
        block_hash: &Hash,
        offset: u32,
        len: u32,
    ) -> Result<Vec<u8>, String> {
        let tx = self.db.begin(false).map_err(|e| e.to_string())?;
        let result = tx
            .fetch_block_region(&BlockRegion {
                hash: *block_hash,
                offset,
                len,
            })
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

        let mut rpc_db = NodeRpcDb::new(db);
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
        let indexes =
            start_indexes(interrupt, Arc::new(db), chain, params, true, true).expect("start");
        let tx_index = indexes.tx_index.as_ref().expect("tx index enabled");

        let mut seam = NodeRpcTxIndexer::new(Arc::clone(tx_index), Arc::clone(&indexes.queryer));
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
        let mut seam =
            NodeRpcExistsAddresser::new(Arc::clone(exists), Arc::clone(&indexes.queryer));
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
        let indexes =
            start_indexes(interrupt, Arc::new(db1), chain1, simnet, true, false).expect("start");
        let tx_index = indexes.tx_index.as_ref().expect("tx index enabled");
        assert!(indexes.exists_addr_index.is_none());

        // A queryer over a different chain makes the tips disagree
        // permanently for the duration of the wait.
        let testnet = dcroxide_chaincfg::testnet3_params();
        let (_dir2, _db2, chain2) = open_genesis_chain(&testnet);
        let other = Arc::new(NodeChainQueryer::new(chain2, testnet));
        assert!(!wait_for_index_sync(
            tx_index,
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
    }
}
