// SPDX-License-Identifier: ISC
//! An end-to-end block template over the live daemon chain: a regnet
//! chain built from dcrd's own full-block battery backs the
//! `NodeTemplateChain` and `NodeTemplateTxSource` adapters, and the
//! ported generator assembles a template the chain itself fully
//! validates (`CheckConnectBlockTemplate`) short of the proof of
//! work.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::{Arc, Mutex};

use dcroxide_blockchain::process::Chain;
use dcroxide_database::{Database, Options};
use dcroxide_mining::{BlkTmplGenerator, ExtraNonces, MiningPolicy};
use dcroxide_node::mining::{NodeTemplateChain, NodeTemplateTxSource};
use dcroxide_testutil::unhex;
use dcroxide_wire::MsgBlock;

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

#[test]
fn builds_a_template_over_the_live_chain() {
    let params = dcroxide_chaincfg::regnet_params();
    let (now, blocks) = accepted_prefix(2);

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
        assert!(errs.is_empty(), "battery block must accept: {errs:?}");
    }
    let best_hash = chain.lock().expect("chain").best_snapshot().hash;

    // The real pool over the shared chain; empty, so the template
    // carries only the coinbase.
    let tx_pool = dcroxide_node::txmempool::new_shared_tx_pool(
        Arc::clone(&chain),
        &params,
        false,
        100,
        10000,
        false,
        false,
    );

    // A regnet premine pay-to-pubkey-hash payout as the mining
    // address.
    let mining_addr =
        dcroxide_txscript::stdaddr::decode_address("RsKrWb7Vny1jnzL1sDLgKTAteh9RZcRr5g6", &params)
            .expect("mining address");

    let policy = MiningPolicy {
        block_max_size: params.maximum_block_sizes[0] as u32,
        tx_min_free_fee: 10000,
        aggressive_mining: true,
    };
    let mut generator = BlkTmplGenerator::new(
        policy,
        &params,
        NodeTemplateChain::new(Arc::clone(&chain), params.clone()),
        NodeTemplateTxSource::new(tx_pool),
        0,
    );
    let template = generator
        .new_block_template(
            Some(&mining_addr),
            &ExtraNonces {
                coinbase: 7,
                treasury: 7,
            },
        )
        .expect("template builds over the live chain")
        .expect("a template is produced below stake validation height");

    // The template extends the live tip; the generator ran the
    // chain's own CheckConnectBlockTemplate during assembly, so a
    // successful return proves consensus validity short of the proof
    // of work.
    assert_eq!(template.height, 3, "template height");
    assert_eq!(template.block.header.height, 3, "header height");
    assert_eq!(
        template.block.header.prev_block, best_hash,
        "template must extend the live tip"
    );
    assert!(template.valid_pay_address, "coinbase pays the address");

    // The coinbase carries an output paying the mining address.
    let (_, pay_script) = mining_addr.payment_script();
    let coinbase = &template.block.transactions[0];
    assert!(
        coinbase
            .tx_out
            .iter()
            .any(|out| out.pk_script == pay_script),
        "coinbase must pay the mining address"
    );
}
