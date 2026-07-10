// SPDX-License-Identifier: ISC
//! Checks for the netsync chain adapter: the shared genesis chain
//! answers the sync manager's trait queries with the same values the
//! chain itself reports, and the null pools behave like empty pools.

use std::sync::{Arc, Mutex};

use dcroxide_blockchain::process::Chain;
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_netsync::manager::{SyncChain, SyncMixPool, SyncTxPool};
use dcroxide_node::sync::{NodeSyncChain, NullMixPool, NullTxPool};

#[test]
fn adapts_a_genesis_chain_for_the_sync_manager() {
    let params = dcroxide_chaincfg::testnet3_params();
    let genesis_hash = params.genesis_hash;

    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain"),
    ));

    let mut sync_chain = NodeSyncChain::new(Arc::clone(&chain), params.clone());

    // The best header and snapshot are the genesis block.
    assert_eq!(sync_chain.best_header(), (genesis_hash, 0));
    let snapshot = sync_chain.best_snapshot();
    assert_eq!(snapshot.hash, genesis_hash);
    assert_eq!(snapshot.height, 0);
    assert_eq!(snapshot.next_stake_diff, params.minimum_stake_diff);

    // Header and block presence for genesis and an unknown hash.
    assert!(sync_chain.have_header(&genesis_hash));
    assert!(sync_chain.have_block(&genesis_hash));
    let unknown = Hash([0x55; 32]);
    assert!(!sync_chain.have_header(&unknown));
    assert!(!sync_chain.have_block(&unknown));
    assert!(sync_chain.header_by_hash(&unknown).is_none());
    assert_eq!(
        sync_chain
            .header_by_hash(&genesis_hash)
            .expect("genesis header")
            .block_hash(),
        genesis_hash
    );

    // The locator from the tip is just the genesis hash, work is
    // reported, and nothing more is needed to reach the best header.
    assert_eq!(
        sync_chain.block_locator_from_hash(&genesis_hash),
        vec![genesis_hash]
    );
    assert!(sync_chain.chain_work(&genesis_hash).is_some());
    assert!(sync_chain.chain_work(&unknown).is_none());
    assert!(sync_chain.put_next_needed_blocks(16).is_empty());

    // A chain whose tip is the decade-old testnet genesis is not
    // current, and the latch does not flip.
    sync_chain.maybe_update_is_current();
    assert!(!sync_chain.is_current());

    // A duplicate genesis submission reports dcrd's duplicate-block
    // classification.
    let genesis_block = params.genesis_block.clone();
    let failure = sync_chain
        .process_block(&genesis_block)
        .expect_err("genesis is already present");
    assert!(failure.is_duplicate_block, "{}", failure.message);

    // The null pools answer like empty pools.
    let mut txpool = NullTxPool;
    assert!(!txpool.have_transaction(&genesis_hash));
    assert!(
        txpool
            .process_transaction(&genesis_block.transactions[0], true, false, 0)
            .is_err()
    );
    let mut mixpool = NullMixPool;
    assert!(!mixpool.recent_message(&genesis_hash));
}
