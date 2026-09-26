// SPDX-License-Identifier: ISC
//! gettreasurybalance answers for blocks below the chain's recent
//! treasury window (review finding RG01#1).
//!
//! The chain's `treasury_state` became a recent-window mirror of the
//! treasury bucket (B1-p#7), evicted by every prune, while the RPC seam
//! (R4-c#1) kept reading only that mirror.  Any block deeper than the
//! window then failed with "treasury db missing key", where dcrd's
//! `TreasuryBalance` reads the row with `dbFetchTreasuryBalance` on
//! every call (`treasury.go:522-530`).  This drives the daemon's own
//! adapter over dcrd's simnet treasury corpus (simnet forces the
//! treasury agenda) replayed into a database-backed chain whose mirror
//! is then pruned.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::{Arc, Mutex};

use dcroxide_blockchain::blockindex::BlockStatus;
use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::simnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_node::rpcrun::NodeRpcChain;
use dcroxide_rpc::server::RpcChain;
use dcroxide_testutil::unhex;
use dcroxide_wire::MsgBlock;

/// Replay dcrd's treasury corpus into a database-backed simnet chain
/// the way the blockchain crate's `treasury_persist.rs` does, returning
/// the block hashes in order.
fn treasury_chain(dir: &std::path::Path) -> (Arc<Mutex<Chain>>, Vec<Hash>) {
    let params = simnet_params();
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcroxide-blockchain/tests/data/treasury_vectors.txt"
    );
    let data = std::fs::read_to_string(path).expect("treasury vectors");
    let opts = Options::new(dir.join("chain"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let mut chain = Chain::open(db, &params, Hash::ZERO, false, 0).expect("open chain");
    let mut hashes = Vec::new();
    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        if f[0] != "blk" {
            continue;
        }
        let (block, _) = MsgBlock::from_bytes(&unhex(f[1])).expect("block");
        let prev = chain
            .index
            .lookup_node(&block.header.prev_block)
            .expect("previous node");
        let id = chain.store.new_node(&block.header, Some(prev));
        {
            let node = chain.store.node_mut(id);
            node.status = BlockStatus(BlockStatus::DATA_STORED.0 | BlockStatus::VALIDATED.0);
            node.is_fully_linked = true;
        }
        chain.index.add_node(&chain.store, id);
        if let Some(db) = chain.db.as_ref() {
            db.update(|tx| tx.store_block(&block).map(|_| ()))
                .expect("store block");
        }
        chain.blocks.insert(
            block.header.block_hash().0,
            std::sync::Arc::new(block.clone()),
        );
        chain
            .fetch_stake_node(id, &params)
            .unwrap_or_else(|e| panic!("stake node: {e:?}"));
        chain
            .put_treasury_records(id, &block, &params)
            .unwrap_or_else(|e| panic!("treasury records: {e:?}"));
        chain.best_chain.set_tip(&chain.store, Some(id));
        hashes.push(block.header.block_hash());
    }
    (Arc::new(Mutex::new(chain)), hashes)
}

#[test]
fn treasury_balance_reads_rows_below_the_mirror_window() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (chain, hashes) = treasury_chain(dir.path());
    let adapter = NodeRpcChain::new(Arc::clone(&chain), simnet_params());

    // Record every answer the treasury-active blocks give while their
    // rows are still resident.
    let resident: Vec<_> = hashes
        .iter()
        .filter_map(|hash| {
            adapter
                .treasury_balance(hash)
                .ok()
                .map(|info| (*hash, info))
        })
        .collect();
    assert!(
        resident.len() > 200,
        "the corpus must be treasury-active: {} answers",
        resident.len()
    );
    assert!(
        resident.iter().any(|(_, info)| info.balance != 0),
        "the corpus must carry a non-zero balance"
    );

    // Prune the mirrors down to the two newest blocks, as the timed
    // prune and the connect-time prune do on a running node.
    chain.lock().expect("chain").prune_chain_memory(2);
    let evicted = {
        let chain = chain.lock().expect("chain");
        resident
            .iter()
            .filter(|(hash, _)| !chain.treasury_state.contains_key(&hash.0))
            .count()
    };
    assert!(
        evicted + 2 >= resident.len(),
        "the prune must evict all but the newest rows: {evicted} of {}",
        resident.len()
    );

    // dcrd answers from the database for every one of them, with the
    // same height, balance and updates.
    for (hash, want) in &resident {
        let got = adapter.treasury_balance(hash).unwrap_or_else(|f| {
            panic!(
                "gettreasurybalance {hash} after the prune: {} (unknown block {}, no treasury {})",
                f.message, f.is_unknown_block, f.is_no_treasury_balance
            )
        });
        assert_eq!(got.block_height, want.block_height, "{hash}");
        assert_eq!(got.balance, want.balance, "{hash}");
        assert_eq!(got.updates, want.updates, "{hash}");
    }
}
