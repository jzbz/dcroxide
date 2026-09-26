// SPDX-License-Identifier: ISC
//! The daemon's `livetickets` and `existslivetickets` seams walk a copy
//! of the tip's stake node taken under the chain mutex, the way dcrd's
//! `LiveTickets` and `CheckLiveTickets` walk `bestChain.Tip().stakeNode`
//! after releasing `chainLock` (review finding R1-p#3).  They used to run
//! the whole walk under the mutex, forwarding to the chain's own
//! methods; these tests pin that the answers are still exactly the
//! chain's, over a regnet chain from dcrd's full-block battery whose
//! tickets are live.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::{Arc, Mutex};

use dcroxide_blockchain::process::Chain;
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_node::rpcrun::NodeRpcChain;
use dcroxide_rpc::server::RpcChain;
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
/// connected.
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
        assert!(errs.is_empty(), "battery block must accept: {errs:?}");
    }
    (dir, chain)
}

/// `livetickets`, `existslivetickets` and `existsliveticket` answer what
/// the chain answers for its tip: every live ticket in the treap's key
/// order, and the membership of each probed hash, in the order asked.
#[test]
fn live_ticket_seams_answer_what_the_chain_answers() {
    // Past the stake enabled height, so the battery's tickets are live.
    let (_dir, chain) = regnet_chain(60);
    let adapter = NodeRpcChain::new(Arc::clone(&chain), dcroxide_chaincfg::regnet_params());

    let live = chain.lock().expect("chain").live_tickets();
    assert!(live.len() > 1, "the battery has live tickets by now");
    assert_eq!(adapter.live_tickets().expect("live tickets"), live);

    let unknown = Hash([0x5a; 32]);
    let last = live[live.len() - 1];
    let probe = [last, unknown, live[0], unknown, last];
    let expected = chain.lock().expect("chain").check_live_tickets(&probe);
    assert_eq!(expected, [true, false, true, false, true]);
    assert_eq!(adapter.check_live_tickets(&probe), expected);
    assert_eq!(adapter.check_live_tickets(&[]), Vec::<bool>::new());
    assert!(adapter.check_live_ticket(&live[0]));
    assert!(!adapter.check_live_ticket(&unknown));
}

/// Below the stake enabled height the tip's stake node holds no live
/// ticket, and the seams answer that rather than an error.
#[test]
fn live_ticket_seams_answer_an_empty_pool() {
    let (_dir, chain) = regnet_chain(3);
    let adapter = NodeRpcChain::new(Arc::clone(&chain), dcroxide_chaincfg::regnet_params());
    assert!(chain.lock().expect("chain").live_tickets().is_empty());
    assert_eq!(adapter.live_tickets().expect("live tickets"), Vec::new());
    let probe = [Hash([1; 32]), Hash([2; 32])];
    assert_eq!(adapter.check_live_tickets(&probe), [false, false]);
}
