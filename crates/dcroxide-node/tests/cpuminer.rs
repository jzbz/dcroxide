// SPDX-License-Identifier: ISC
//! The CPU miner's discrete `generate` path end to end: over a regnet
//! chain with the live template generator and the block-submit seam,
//! `generate N` solves fresh templates and mines real blocks that
//! become the main-chain tip.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::{Arc, Mutex};

use dcroxide_blockchain::process::Chain;
use dcroxide_database::{Database, Options};
use dcroxide_mining::MiningPolicy;
use dcroxide_node::bgtemplate::start_generator;
use dcroxide_node::chainntfns::ChainNtfnHandler;
use dcroxide_node::cpuminer::NodeCpuMiner;
use dcroxide_node::dispatch::{SyncPeers, new_recently_advertised};
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

/// A regnet chain with the first `history` accepted battery blocks
/// processed.
fn regnet_chain(history: usize) -> (tempfile::TempDir, Arc<Mutex<Chain>>) {
    let params = dcroxide_chaincfg::regnet_params();
    let (now, blocks) = accepted_prefix(history);
    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
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
    (dir, chain)
}

/// A regnet premine pay-to-pubkey-hash payout used as the mining
/// address.
fn mining_address() -> dcroxide_txscript::stdaddr::Address {
    let params = dcroxide_chaincfg::regnet_params();
    dcroxide_txscript::stdaddr::decode_address("RsKrWb7Vny1jnzL1sDLgKTAteh9RZcRr5g6", &params)
        .expect("mining address")
}

/// The mining policy the daemon builds from its configuration.
fn mining_policy() -> MiningPolicy {
    let params = dcroxide_chaincfg::regnet_params();
    MiningPolicy {
        block_max_size: params.maximum_block_sizes[0] as u32,
        tx_min_free_fee: 10000,
        aggressive_mining: true,
    }
}

/// The best main-chain height and hash.
fn best(chain: &Arc<Mutex<Chain>>) -> (i64, dcroxide_chainhash::Hash) {
    let chain = chain.lock().expect("chain");
    let snapshot = chain.best_snapshot();
    (snapshot.height, snapshot.hash)
}

/// `generate N` mines real blocks that extend the main chain, and
/// `generate 0` is a no-op.
#[test]
fn generate_mines_blocks_onto_the_chain() {
    let params = dcroxide_chaincfg::regnet_params();
    let (_dir, chain) = regnet_chain(2);
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
    )));

    let generator = start_generator(
        Arc::clone(&chain),
        Arc::clone(&tx_pool),
        params.clone(),
        vec![mining_address()],
        mining_policy(),
        0,
        true,
        None,
        None,
    );

    // Wire the chain handler so a mined block feeds the generator, which
    // regenerates the next template (dcrd's chain notifications driving
    // `s.bg`), and install it on the chain callback and the sync manager
    // exactly as the daemon does.
    let mut handler = ChainNtfnHandler::new(
        None,
        params.clone(),
        true,
        Arc::clone(&tx_pool),
        SyncPeers::new(),
        new_recently_advertised(),
    );
    handler.set_generator(generator.sink());
    {
        let callback = handler.clone();
        chain
            .lock()
            .expect("chain")
            .set_notification_callback(Box::new(move |n| callback.handle(n)));
    }
    sync_manager
        .lock()
        .expect("sync manager")
        .chain_mut()
        .set_chain_ntfn_handler(handler);

    let mut miner = NodeCpuMiner::new(
        generator.current_handle(),
        generator.subscribers_handle(),
        generator.sink(),
        Arc::clone(&chain),
        Arc::clone(&sync_manager),
        Arc::clone(&tx_pool),
        params.clone(),
        mining_policy(),
        0,
    );

    // The idle miner reports dcrd's defaults before any mining, and
    // set_num_workers records the count with dcrd's clamping.
    assert!(!miner.is_mining(), "the miner is idle before generate");
    assert_eq!(miner.num_workers(), 1, "the default worker count");
    miner.set_num_workers(4);
    assert_eq!(miner.num_workers(), 4, "a positive count is recorded");
    miner.set_num_workers(-1);
    assert_eq!(
        miner.num_workers(),
        1,
        "a negative count selects the default"
    );
    miner.set_num_workers(i32::MAX);
    assert!(
        miner.num_workers() >= 2 && miner.num_workers() < i32::MAX,
        "an oversized count is clamped to the maximum"
    );
    assert_eq!(miner.hashes_per_second(), 0.0, "the idle hash rate is zero");

    let (orig_height, _) = best(&chain);

    // Mine one block: it solves a template's proof of work and submits
    // it, advancing the tip.
    let hashes = miner.generate_n_blocks(1).expect("generate one block");
    assert_eq!(hashes.len(), 1, "one hash for one block");
    let (height, tip) = best(&chain);
    assert_eq!(height, orig_height + 1, "the mined block advanced the tip");
    assert_eq!(hashes[0], tip, "the returned hash is the new tip");

    // Mine three more: the miner tracks the target height across the
    // regenerated templates.
    let hashes = miner.generate_n_blocks(3).expect("generate three blocks");
    assert_eq!(hashes.len(), 3, "three hashes for three blocks");
    let (height, tip) = best(&chain);
    assert_eq!(
        height,
        orig_height + 4,
        "three more blocks extended the tip"
    );
    assert_eq!(hashes[2], tip, "the last returned hash is the new tip");

    // Zero blocks is a no-op that returns no hashes.
    assert!(
        miner
            .generate_n_blocks(0)
            .expect("generate zero")
            .is_empty(),
        "generate 0 mines nothing"
    );

    // The discrete-mining flag is cleared after each call, so the miner
    // is idle again (the Drop guard ran on every return path).
    assert!(!miner.is_mining(), "the miner is idle after generate");

    generator.shutdown();
}
