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
