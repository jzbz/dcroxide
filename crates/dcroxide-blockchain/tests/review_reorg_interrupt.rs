// SPDX-License-Identifier: ISC
//! A shutdown request stops a reorganization before its next block.
//!
//! dcrd checks `b.interrupt` before every block `reorganizeChainInternal`
//! detaches or attaches (`chain.go:1065-1069`, `:1160-1164`) and at the
//! top of every `reorganizeChain` attempt (`:1293-1297`), and returns
//! `errInterruptRequested` without trying another candidate
//! (`:1328-1331`).  The port held the interrupt but checked it only in
//! the startup UTXO catch-up, so a long reorganization ran to the end
//! after SIGTERM (review finding RG01#4).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use dcroxide_blockchain::RuleErrorKind;
use dcroxide_blockchain::notifications::Notification;
use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::{Params, regnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_testutil::unhex;
use dcroxide_wire::MsgBlock;
use tempfile::TempDir;

/// The start of the full block battery's main chain, each block
/// extending the one before, with the battery's clock.
fn main_chain_blocks(count: usize) -> (Vec<MsgBlock>, i64) {
    let mut now = 0;
    let mut blocks: Vec<MsgBlock> = Vec::new();
    for line in include_str!("data/fullblock_vectors.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "now" => now = f[1].parse().expect("now"),
            "accept" if f[2] == "true" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                if let Some(prev) = blocks.last() {
                    assert_eq!(block.header.prev_block, prev.header.block_hash());
                }
                blocks.push(block);
                if blocks.len() == count {
                    return (blocks, now);
                }
            }
            _ => {}
        }
    }
    panic!("the battery has fewer than {count} main chain blocks");
}

fn open(params: &Params, interrupt: &Arc<AtomicBool>) -> (TempDir, Chain) {
    let dir = TempDir::new().expect("tempdir");
    let db = Database::create(&Options::new(dir.path().join("chain"), params.net.0))
        .expect("create database");
    let chain = Chain::open_with_interrupt(
        db,
        params,
        Hash::ZERO,
        false,
        0,
        Some(Arc::clone(interrupt)),
    )
    .expect("open chain");
    (dir, chain)
}

fn tip_hash(chain: &Chain) -> Hash {
    chain.store.node(chain.best_chain.tip().expect("tip")).hash
}

/// dcrd's `errInterruptRequested`: its text, and not a rule violation,
/// so the daemon logs "Failed to process block" rather than blaming a
/// peer.
fn assert_interrupted(errs: &[dcroxide_blockchain::RuleError]) {
    assert_eq!(errs.len(), 1, "{errs:?}");
    assert_eq!(errs[0].description, "interrupt requested");
    assert!(!errs[0].kind.is_rule_violation());
    assert_ne!(errs[0].kind, RuleErrorKind::UtxoBackendCorruption);
    assert_ne!(errs[0].kind, RuleErrorKind::UnknownBlock);
}

/// Record the notifications by name, setting the interrupt at the
/// first one named `trip`.
fn record(
    chain: &mut Chain,
    interrupt: &Arc<AtomicBool>,
    trip: &'static str,
) -> Arc<Mutex<Vec<&'static str>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (seen_in, interrupt) = (Arc::clone(&seen), Arc::clone(interrupt));
    let mut tripped = false;
    chain.set_notification_callback(Box::new(move |n| {
        let name = match n {
            Notification::BlockConnected(_) => "connected",
            Notification::BlockDisconnected(_) => "disconnected",
            Notification::ChainReorgStarted => "reorg started",
            Notification::ChainReorgDone => "reorg done",
            Notification::Reorganization(_) => "reorganization",
            _ => return,
        };
        seen_in.lock().expect("lock").push(name);
        if name == trip && !tripped {
            tripped = true;
            interrupt.store(true, Ordering::SeqCst);
        }
    }));
    seen
}

/// Checked at the top of every attempt: a block extending the tip is
/// stored but not connected while a shutdown is pending.
#[test]
fn a_pending_shutdown_stops_the_reorganization_before_it_starts() {
    let params = regnet_params();
    let interrupt = Arc::new(AtomicBool::new(false));
    let (_dir, mut chain) = open(&params, &interrupt);
    let (blocks, now) = main_chain_blocks(12);
    for block in &blocks[..10] {
        let (_, errs) = chain.process_block(block, now, &params);
        assert!(errs.is_empty(), "{errs:?}");
    }
    let tip = tip_hash(&chain);

    interrupt.store(true, Ordering::SeqCst);
    let (_, errs) = chain.process_block(&blocks[10], now, &params);
    assert_interrupted(&errs);
    assert_eq!(tip_hash(&chain), tip, "the tip moved during shutdown");

    // Invalidating the tip rolls back through the same attempt, so it
    // stops there too and leaves the block valid.
    let errs = chain.invalidate_block(&tip, now, &params);
    assert_interrupted(&errs);
    assert_eq!(tip_hash(&chain), tip);

    // Once the shutdown is withdrawn the stored block connects with the
    // next one.
    interrupt.store(false, Ordering::SeqCst);
    let (_, errs) = chain.process_block(&blocks[11], now, &params);
    assert!(errs.is_empty(), "{errs:?}");
    assert_eq!(tip_hash(&chain), blocks[11].header.block_hash());
}

/// Checked before every block the detach loop disconnects: a roll-back
/// of four blocks stops after the first once a shutdown is requested,
/// and only the completion event dcrd defers follows the start.
#[test]
fn a_shutdown_stops_the_detach_loop_at_the_next_block() {
    let params = regnet_params();
    let interrupt = Arc::new(AtomicBool::new(false));
    let (_dir, mut chain) = open(&params, &interrupt);
    let (blocks, now) = main_chain_blocks(12);
    for block in &blocks {
        let (_, errs) = chain.process_block(block, now, &params);
        assert!(errs.is_empty(), "{errs:?}");
    }

    let seen = record(&mut chain, &interrupt, "disconnected");
    let errs = chain.invalidate_block(&blocks[8].header.block_hash(), now, &params);
    assert_interrupted(&errs);
    assert_eq!(tip_hash(&chain), blocks[10].header.block_hash());
    assert_eq!(
        *seen.lock().expect("lock"),
        ["reorg started", "disconnected", "reorg done"]
    );
}

/// Checked before every block the attach loop connects: blocks linked
/// at once by their missing ancestor connect one at a time until a
/// shutdown is requested.
#[test]
fn a_shutdown_stops_the_attach_loop_at_the_next_block() {
    let params = regnet_params();
    let interrupt = Arc::new(AtomicBool::new(false));
    let (_dir, mut chain) = open(&params, &interrupt);
    let (blocks, now) = main_chain_blocks(12);
    for block in &blocks[..6] {
        let (_, errs) = chain.process_block(block, now, &params);
        assert!(errs.is_empty(), "{errs:?}");
    }

    // The next five headers, then every body but the first: none can
    // link until the first body arrives.
    for block in &blocks[6..11] {
        chain
            .process_block_header(&block.header, now, &params)
            .expect("header");
    }
    for block in &blocks[7..11] {
        let (_, errs) = chain.process_block(block, now, &params);
        assert!(errs.is_empty(), "{errs:?}");
        assert_eq!(tip_hash(&chain), blocks[5].header.block_hash());
    }

    let seen = record(&mut chain, &interrupt, "connected");
    let (_, errs) = chain.process_block(&blocks[6], now, &params);
    assert_interrupted(&errs);
    assert_eq!(tip_hash(&chain), blocks[6].header.block_hash());
    assert_eq!(*seen.lock().expect("lock"), ["connected"]);

    // The rest connect once the shutdown is withdrawn.
    interrupt.store(false, Ordering::SeqCst);
    let (_, errs) = chain.process_block(&blocks[11], now, &params);
    assert!(errs.is_empty(), "{errs:?}");
    assert_eq!(tip_hash(&chain), blocks[11].header.block_hash());
}
