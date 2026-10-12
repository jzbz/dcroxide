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
use dcroxide_mining::{BlkTmplGenerator, ExtraNonces, MiningPolicy, TemplateChain};
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

/// The template chain's snapshot carries the missed tickets as the
/// list dcrd's `BestState.MissedTickets` is (`chain.go:654-658`): the
/// tip stake node's missed tickets in key order.  The chain holds them
/// as a handle on that node's treap, and the adapter builds the list
/// the generator's revocation eligibility check reads
/// (`mining.go:1649-1650`).
#[test]
fn the_template_snapshot_lists_the_tips_missed_tickets() {
    let params = dcroxide_chaincfg::regnet_params();
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcroxide-blockchain/tests/data/fullblock_vectors.txt"
    );
    let data = std::fs::read_to_string(path).expect("fullblock vectors");

    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain"),
    ));
    let template_chain = NodeTemplateChain::new(Arc::clone(&chain), params.clone());

    // Every accepted block of the battery in file order, side chains
    // and reorganizations included, up to the first state with a
    // missed ticket.
    let mut now: i64 = 0;
    let mut states = 0;
    let mut missed = Vec::new();
    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "now" => now = f[1].parse().expect("generation time"),
            // accept <name> <mainchain> <orphan> <blockhex>
            "accept" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                let want = {
                    let mut chain = chain.lock().expect("chain");
                    let (_, errs) = chain.process_block(&block, now, &params);
                    assert_eq!(errs.is_empty(), f[3] == "false", "{}: {errs:?}", f[1]);
                    let tip = chain.best_chain.tip().expect("tip");
                    chain
                        .fetch_stake_node(tip, &params)
                        .expect("tip stake node")
                        .missed_tickets()
                };
                let best = template_chain.best_snapshot();
                assert_eq!(best.missed_tickets, want, "{}: missed tickets", f[1]);
                states += 1;
                if !want.is_empty() {
                    missed = want;
                    break;
                }
            }
            _ => {}
        }
    }
    assert!(states > 100, "the first miss is deep in the battery");
    assert_eq!(missed.len(), 1, "the battery misses one ticket");
}

/// The adapter lists every missed ticket of the snapshot's handle, in
/// key order, however many there are.  dcrd's full-block battery never
/// has more than one missed ticket at a time, so the handles here are
/// those of dcrd's ticket state vectors (120 connected blocks with
/// misses, revocations and expiries), each put into the chain's best
/// state as connecting its block would leave it.  A ticket the list
/// lost would no longer be eligible for revocation
/// (`mining.go:1649-1650`).
#[test]
fn the_template_snapshot_lists_every_missed_ticket_in_key_order() {
    use dcroxide_chainhash::Hash;
    use dcroxide_stake::ticketnode::{Node, StakeNodeParams};

    let params = dcroxide_chaincfg::regnet_params();
    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain"),
    ));
    let template_chain = NodeTemplateChain::new(Arc::clone(&chain), params.clone());

    let hashes = |field: &str| -> Vec<Hash> {
        if field == "-" {
            return Vec::new();
        }
        field
            .split(',')
            .map(|hex| Hash(unhex(hex).try_into().expect("a 32-byte hash")))
            .collect()
    };
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcroxide-stake/tests/data/ticketnode_vectors.txt"
    );
    let data = std::fs::read_to_string(path).expect("ticket state vectors");
    // The parameters the vectors were generated with.
    let mut node = Node::genesis(StakeNodeParams {
        votes_per_block: 5,
        stake_validation_begin_height: 24,
        stake_enable_height: 8,
        ticket_expiry_blocks: 40,
    });
    let mut largest = 0;
    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        // blk <height> <lottery iv> <voted> <revoked> <new>
        if f[0] != "blk" {
            continue;
        }
        node = node
            .connect(hashes(f[2])[0], &hashes(f[3]), &hashes(f[4]), &hashes(f[5]))
            .unwrap_or_else(|e| panic!("block {}: connect failed: {e:?}", f[1]));
        let want = node.missed_tickets();
        assert!(
            want.windows(2).all(|pair| pair[0].0 < pair[1].0),
            "block {}: the node lists its missed tickets in key order",
            f[1]
        );
        chain.lock().expect("chain").state_snapshot.missed_tickets = node.missed_ticket_set();
        let best = template_chain.best_snapshot();
        assert_eq!(best.missed_tickets, want, "block {}: missed tickets", f[1]);
        largest = largest.max(want.len());
    }
    assert!(
        largest >= 8,
        "the order and the count need a long list, got {largest}"
    );
}
