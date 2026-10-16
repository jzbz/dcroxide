// SPDX-License-Identifier: ISC
//! End-to-end checks for the confirmed-transaction bookkeeping (dcrd
//! `TransactionConfirmed`): connected blocks drained through the
//! chain handler feed every non-coinbase transaction into the shared
//! recently-confirmed filter — the sync manager's duplicate-request
//! gate and the RPC duplicate classification consult it — while the
//! coinbase is skipped, and the removals and the prune go to the
//! rebroadcast sink without stalling the drain.

use std::sync::{Arc, Mutex};

use dcroxide_blockchain::notifications::{BlockConnectedNtfnsData, Notification};
use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::validate::AgendaFlags;
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx, OutPoint, TxIn, TxOut};

fn zero_header() -> BlockHeader {
    BlockHeader {
        version: 1,
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
        height: 0,
        size: 0,
        timestamp: 0,
        nonce: 0,
        extra_data: [0u8; 32],
        stake_version: 0,
    }
}

fn tagged_tx(tag: u8) -> MsgTx {
    MsgTx {
        tx_in: vec![TxIn {
            previous_out_point: OutPoint {
                hash: Hash([tag; 32]),
                index: 0,
                tree: dcroxide_wire::TX_TREE_REGULAR,
            },
            ..TxIn::default()
        }],
        tx_out: vec![TxOut {
            value: i64::from(tag),
            ..TxOut::default()
        }],
        ..MsgTx::default()
    }
}

#[test]
fn confirmed_transactions_feed_the_shared_filter() {
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

    // The daemon wiring: the confirmed filter is shared with the sync
    // manager, and the removals and prunes go to the rebroadcast sink
    // (which sends its thread none of them, as it tracks nothing here;
    // the thread's first fire is dcrd's five minutes out).
    let filter = Arc::new(Mutex::new(dcroxide_containers::apbf::new_filter(
        23000, 0.000001,
    )));
    let rebroadcaster = dcroxide_node::rebroadcast::start_rebroadcaster(
        Arc::clone(&chain),
        dcroxide_node::dispatch::SyncPeers::new(),
        dcroxide_node::dispatch::new_recently_advertised(),
    );
    let mut handler = dcroxide_node::chainntfns::ChainNtfnHandler::new(
        None,
        params.clone(),
        false,
        dcroxide_node::sync::SyncGate::always_current(),
        None,
        tx_pool,
        dcroxide_node::dispatch::SyncPeers::new(),
        dcroxide_node::dispatch::new_recently_advertised(),
    );
    handler.set_recently_confirmed(Arc::clone(&filter));
    handler.set_rebroadcast(rebroadcaster.sink());

    // A connected block with a coinbase, one regular transaction, and
    // one stake transaction, queued through the callback path and
    // drained like the sync adapter does after a processing call.
    let coinbase = tagged_tx(1);
    let regular = tagged_tx(2);
    let stake = tagged_tx(3);
    let block = MsgBlock {
        header: zero_header(),
        transactions: vec![coinbase.clone(), regular.clone()],
        stransactions: vec![stake.clone()],
    };
    let parent = MsgBlock {
        header: zero_header(),
        transactions: Vec::new(),
        stransactions: Vec::new(),
    };
    handler.handle(&Notification::BlockConnected(BlockConnectedNtfnsData::new(
        Arc::new(block),
        Arc::new(parent),
        AgendaFlags(0),
    )));
    handler.drain_pending_block_events();

    let filter = filter.lock().expect("filter");
    assert!(
        filter.contains(&regular.tx_hash().0),
        "the regular transaction must be recorded as confirmed"
    );
    assert!(
        filter.contains(&stake.tx_hash().0),
        "the stake transaction must be recorded as confirmed (no \
         treasury: the whole stake tree counts)"
    );
    assert!(
        !filter.contains(&coinbase.tx_hash().0),
        "the coinbase is never recorded"
    );
    drop(filter);

    rebroadcaster.shutdown();
}

/// With the treasury agenda active the first stake transaction is the
/// treasurybase, which the maintenance skips like the coinbase --
/// together with its hash.  The stake transactions and the hashes that
/// came with the block on the connected event are walked side by side,
/// so skipping one without the other would handle every stake
/// transaction under its neighbour's hash.
#[test]
fn the_treasurybase_is_skipped_together_with_its_hash() {
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
    let filter = Arc::new(Mutex::new(dcroxide_containers::apbf::new_filter(
        23000, 0.000001,
    )));
    let rebroadcaster = dcroxide_node::rebroadcast::start_rebroadcaster(
        Arc::clone(&chain),
        dcroxide_node::dispatch::SyncPeers::new(),
        dcroxide_node::dispatch::new_recently_advertised(),
    );
    let mut handler = dcroxide_node::chainntfns::ChainNtfnHandler::new(
        None,
        params.clone(),
        false,
        dcroxide_node::sync::SyncGate::always_current(),
        None,
        tx_pool,
        dcroxide_node::dispatch::SyncPeers::new(),
        dcroxide_node::dispatch::new_recently_advertised(),
    );
    handler.set_recently_confirmed(Arc::clone(&filter));
    handler.set_rebroadcast(rebroadcaster.sink());

    // A connected block whose stake tree leads with a treasurybase,
    // followed by two more stake transactions.
    let coinbase = tagged_tx(1);
    let regular = tagged_tx(2);
    let (treasurybase, vote, ticket) = (tagged_tx(3), tagged_tx(4), tagged_tx(5));
    let block = MsgBlock {
        header: zero_header(),
        transactions: vec![coinbase.clone(), regular.clone()],
        stransactions: vec![treasurybase.clone(), vote.clone(), ticket.clone()],
    };
    let parent = MsgBlock {
        header: zero_header(),
        transactions: Vec::new(),
        stransactions: Vec::new(),
    };
    handler.handle(&Notification::BlockConnected(BlockConnectedNtfnsData::new(
        Arc::new(block),
        Arc::new(parent),
        AgendaFlags::TREASURY_ENABLED,
    )));
    handler.drain_pending_block_events();

    let filter = filter.lock().expect("filter");
    assert!(
        filter.contains(&regular.tx_hash().0),
        "the regular transaction must be recorded as confirmed"
    );
    assert!(
        filter.contains(&vote.tx_hash().0),
        "the stake transaction after the treasurybase must be recorded"
    );
    assert!(
        filter.contains(&ticket.tx_hash().0),
        "the last stake transaction must be recorded"
    );
    assert!(
        !filter.contains(&treasurybase.tx_hash().0),
        "the treasurybase is skipped with its hash"
    );
    assert!(
        !filter.contains(&coinbase.tx_hash().0),
        "the coinbase is never recorded"
    );
    drop(filter);

    rebroadcaster.shutdown();
}
