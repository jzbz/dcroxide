// SPDX-License-Identifier: ISC
//! A discrete `generate` returns once the block that reaches its target
//! connects, as dcrd's does: `GenerateNBlocks` selects on the
//! `notifyBlocks` feed the server fills from every `BlockConnected`
//! (`cpuminer.go:980-984`) and leaves as soon as a connected block is at
//! the target height.  The port waited for the next template instead,
//! which past stake validation height waits for votes on the new block,
//! or for the 5.5 s template timeout, so every call returned seconds
//! after its last block.
//!
//! Here the generator is never told about connected blocks, so no second
//! template ever arrives: only the connected block can end the call.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dcroxide_blockchain::process::Chain;
use dcroxide_database::{Database, Options};
use dcroxide_mining::MiningPolicy;
use dcroxide_node::bgtemplate::start_generator;
use dcroxide_node::cpuminer::NodeCpuMiner;
use dcroxide_node::dispatch::SyncPeers;
use dcroxide_rpc::server::RpcCpuMiner;
use dcroxide_testutil::unhex;
use dcroxide_wire::MsgBlock;

/// The leading consecutive main-chain prefix of accepted blocks from
/// dcrd's `fullblocktests.Generate` battery, with the generation time.
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
            "accept" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
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

#[test]
fn generate_returns_when_its_target_block_connects() {
    let params = dcroxide_chaincfg::regnet_params();
    let (now, blocks) = accepted_prefix(2);
    let dir = tempfile::tempdir().expect("temp dir");
    let db = Database::create(&Options::new(dir.path().join("blocks"), params.net.0))
        .expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain"),
    ));
    for block in &blocks {
        let (_, errs) = chain
            .lock()
            .expect("chain")
            .process_block(block, now, &params);
        assert!(errs.is_empty(), "history block must accept: {errs:?}");
    }

    let tx_pool = dcroxide_node::txmempool::new_shared_tx_pool(
        Arc::clone(&chain),
        &params,
        false,
        100,
        10000,
        false,
        false,
    );
    let sync_manager = Arc::new(Mutex::new(dcroxide_node::sync::new_sync_manager(
        Arc::clone(&chain),
        &params,
        false,
        8,
        1000,
        Arc::clone(&tx_pool),
        dcroxide_node::mixnode::shared_mix_pool(Arc::clone(&chain), params.clone(), &tx_pool),
    )));
    let policy = MiningPolicy {
        block_max_size: params.maximum_block_sizes[0] as u32,
        tx_min_free_fee: 10000,
        aggressive_mining: true,
    };
    let mining_address =
        dcroxide_txscript::stdaddr::decode_address("RsKrWb7Vny1jnzL1sDLgKTAteh9RZcRr5g6", &params)
            .expect("mining address");
    let generator = start_generator(
        Arc::clone(&chain),
        Arc::clone(&tx_pool),
        params.clone(),
        vec![mining_address],
        policy.clone(),
        0,
        true,
        dcroxide_node::sync::SyncGate::always_current(),
        None,
        None,
    );
    let miner = NodeCpuMiner::new(
        generator.current_handle(),
        generator.subscribers_handle(),
        generator.sink(),
        Arc::clone(&chain),
        Arc::clone(&sync_manager),
        Arc::clone(&tx_pool),
        params.clone(),
        policy,
        0,
        SyncPeers::new(),
        true,
    );

    let orig_height = chain.lock().expect("chain").best_snapshot().height;
    let started = Instant::now();
    let hashes = miner.generate_n_blocks(1).expect("generate one block");
    let elapsed = started.elapsed();

    let (tip_height, tip_hash) = {
        let chain = chain.lock().expect("chain");
        let tip = chain.best_snapshot();
        (tip.height, tip.hash)
    };
    assert_eq!(tip_height, orig_height + 1, "the block was mined");
    assert_eq!(hashes, vec![tip_hash], "and its hash returned");
    assert!(
        elapsed < Duration::from_secs(3),
        "generate must return once its block connects, not on the \
         template timeout; it took {elapsed:?}"
    );

    generator.shutdown();
}
