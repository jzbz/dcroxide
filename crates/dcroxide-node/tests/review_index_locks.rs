// SPDX-License-Identifier: ISC
//! The index readers never wait on the index writer.
//!
//! The daemon shares each index behind a mutex, and the index writer
//! holds it through `Database::begin(true)` (a wait for the database
//! writer, which a metadata or UTXO flush can hold for a long time) and
//! through a whole block's index work.  Every other user of that mutex
//! used to wait for all of it:
//!
//! - the mempool's `add_unconfirmed_tx` hook, which runs inside
//!   `TxPool::add_transaction` with the pool mutex held, so transaction
//!   admission and everything queued on the pool stalled with it;
//! - `existsaddress`/`existsaddresses`, and the seam's `name` and `tip`;
//! - `getrawtransaction`'s `name`, `tip` and `entry`.
//!
//! dcrd couples none of them to the writer: `AddUnconfirmedTx` takes only
//! `unconfirmedLock` (`existsaddrindex.go:571-575`), and `ExistsAddress`,
//! `ExistsAddresses`, `Entry`, `Tip` and `Name` take no index-wide lock.
//!
//! Each test holds the index mutex, as the writer does mid-update, and
//! requires the reader to finish anyway.

use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dcroxide_blockchain::process::Chain;
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_indexers::Interrupt;
use dcroxide_mempool::UnconfirmedAddrIndexer;
use dcroxide_node::indexes::{
    NodeIndexes, NodeRpcExistsAddresser, NodeRpcTxIndexer, NodeUnconfirmedAddrIndexer,
    start_indexes,
};
use dcroxide_rpc::server::{RpcExistsAddresser, RpcTxIndexer};
use dcroxide_txscript::stdaddr::new_address_pub_key_hash_ecdsa_secp256k1_v0;
use dcroxide_wire::{MsgTx, TxOut, TxSerializeType};

/// How long a reader may take while the index mutex is held.  Far above
/// what any of these calls needs; a reader blocked on the mutex never
/// finishes at all.
const DEADLINE: Duration = Duration::from_secs(20);

fn start() -> (tempfile::TempDir, NodeIndexes) {
    let params = dcroxide_chaincfg::simnet_params();
    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db.clone(), &params, params.assume_valid, false, 0).expect("open chain"),
    ));
    let indexes = start_indexes(
        Interrupt::default(),
        Arc::new(db),
        chain,
        params,
        true,
        true,
        &dcroxide_node::indexes::IndexLogs::default(),
    )
    .expect("start indexes");
    (dir, indexes)
}

/// Run `f` on another thread and report whether it finished in time.
fn finishes<F: FnOnce() + Send + 'static>(f: F) -> (bool, std::thread::JoinHandle<()>) {
    let (done_tx, done_rx) = mpsc::channel();
    let handle = std::thread::spawn(move || {
        f();
        let _ = done_tx.send(());
    });
    (done_rx.recv_timeout(DEADLINE).is_ok(), handle)
}

/// Mempool admission records a transaction's addresses, and an
/// `existsaddress` sees them, while the exists-address index mutex is
/// held.
#[test]
fn the_mempool_hook_and_address_lookups_never_wait_on_the_index_writer() {
    let (_dir, indexes) = start();
    let params = dcroxide_chaincfg::simnet_params();
    let index = indexes.exists_addr_index.clone().expect("exists index");
    let mut hook = NodeUnconfirmedAddrIndexer::new(Arc::clone(&index));
    let addresser = NodeRpcExistsAddresser::new(Arc::clone(&index), Arc::clone(&indexes.queryer));

    let addr = new_address_pub_key_hash_ecdsa_secp256k1_v0(&[7u8; 20], &params).expect("addr");
    let (version, pk_script) = addr.payment_script();
    let tx = MsgTx {
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
    };

    let writer = index.lock().expect("exists addr index mutex poisoned");
    let (finished, reader) = finishes(move || {
        hook.add_unconfirmed_tx(&tx);
        assert_eq!(addresser.name(), "exists address index");
        assert_eq!(
            addresser.tip(),
            Ok((0, dcroxide_chaincfg::simnet_params().genesis_hash))
        );
        assert_eq!(addresser.exists_address(&addr), Ok(true));
        assert_eq!(addresser.exists_addresses(&[addr]), Ok(vec![true]));
        assert!(addresser.wait_for_sync());
    });
    drop(writer);
    reader.join().expect("reader thread");
    assert!(
        finished,
        "the mempool hook or an exists-address lookup waited on the index mutex"
    );
}

/// `getrawtransaction`'s index lookups finish while the transaction
/// index mutex is held.
#[test]
fn transaction_index_lookups_never_wait_on_the_index_writer() {
    let (_dir, indexes) = start();
    let index = indexes.tx_index.clone().expect("tx index");
    let seam = NodeRpcTxIndexer::new(Arc::clone(&index), Arc::clone(&indexes.queryer));

    let writer = index.lock().expect("tx index mutex poisoned");
    let (finished, reader) = finishes(move || {
        assert_eq!(seam.name(), "transaction index");
        assert_eq!(
            seam.tip(),
            Ok((0, dcroxide_chaincfg::simnet_params().genesis_hash))
        );
        assert!(matches!(seam.entry(&Hash([7u8; 32])), Ok(None)));
        assert!(seam.wait_for_sync());
    });
    drop(writer);
    reader.join().expect("reader thread");
    assert!(
        finished,
        "a transaction index lookup waited on the index mutex"
    );
}

/// The exists address index's commit hook and its flush participant run
/// under the database's writer semaphore, where waiting on a node mutex
/// would stall every commit in the process behind whoever holds it.  They
/// touch only the index's memtable and the mempool overlay, each behind
/// its own leaf lock: with the index, chain and pool mutexes all held
/// elsewhere, a connect's commit (which runs the hook) and a flush (which
/// runs the participant's `contribute` and `finished`) still finish.
#[test]
fn the_commit_hook_and_the_flush_participant_take_no_node_mutex() {
    use dcroxide_indexers::{CONNECT_NTFN, IndexNtfn, Indexer};

    let params = dcroxide_chaincfg::simnet_params();
    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db.clone(), &params, params.assume_valid, false, 0).expect("open chain"),
    ));
    let indexes = start_indexes(
        Interrupt::default(),
        Arc::new(db.clone()),
        Arc::clone(&chain),
        params.clone(),
        false,
        true,
        &dcroxide_node::indexes::IndexLogs::default(),
    )
    .expect("start indexes");
    let pool = dcroxide_node::txmempool::new_shared_tx_pool(
        Arc::clone(&chain),
        &params,
        false,
        100,
        10000,
        false,
        false,
    );
    let index = indexes.exists_addr_index.clone().expect("exists index");

    // A mempool address, so the connect's hook has a key to move and the
    // flush a key to journal.
    let addr = new_address_pub_key_hash_ecdsa_secp256k1_v0(&[9u8; 20], &params).expect("addr");
    let (version, pk_script) = addr.payment_script();
    NodeUnconfirmedAddrIndexer::new(Arc::clone(&index)).add_unconfirmed_tx(&MsgTx {
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
    });
    let genesis = Arc::new(params.genesis_block.clone());
    let mut next = params.genesis_block.clone();
    next.header.height = 1;
    next.header.prev_block = genesis.header.block_hash();
    let ntfn = IndexNtfn {
        ntfn_type: CONNECT_NTFN,
        block: Arc::new(next),
        parent: genesis,
        is_treasury_enabled: false,
    };

    let (ready_tx, ready_rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let writer_index = Arc::clone(&index);
    let writer_db = db.clone();
    let writer = std::thread::spawn(move || {
        // The connect's index work, under the index mutex as the
        // subscriber does it; the mutex is released before the commit.
        let tx = writer_db.begin(true).expect("begin");
        writer_index
            .lock()
            .expect("index")
            .process_notification(&tx, &ntfn)
            .expect("connect");
        ready_tx.send(()).expect("ready");
        go_rx.recv().expect("go");
        tx.commit().expect("commit runs the hook");
        writer_db.flush().expect("flush runs the participant");
    });
    ready_rx.recv().expect("the writer is ready");
    let held = (
        index.lock().expect("index mutex"),
        chain.lock().expect("chain mutex"),
        pool.lock().expect("pool mutex"),
    );
    go_tx.send(()).expect("go");
    let deadline = std::time::Instant::now() + DEADLINE;
    while !writer.is_finished() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    let finished = writer.is_finished();
    drop(held);
    writer.join().expect("writer thread");
    assert!(
        finished,
        "the commit hook or the flush participant waited on a node mutex"
    );
    let query = index.lock().expect("index").query();
    assert_eq!(query.exists_address(&addr), Ok(true));
    let tx = db.begin(false).expect("begin");
    let journaled = tx
        .metadata()
        .bucket(dcroxide_indexers::EXISTS_ADDR_INDEX_KEY)
        .and_then(|b| b.get(b"M"))
        .is_some();
    tx.rollback().expect("rollback");
    assert!(journaled, "the flush ran the participant");
}
