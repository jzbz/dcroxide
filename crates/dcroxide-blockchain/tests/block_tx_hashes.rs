// SPDX-License-Identifier: ISC
//! The connect and the connected-block event reuse the transaction
//! hashes `Chain::process_block` computed for the block.
//!
//! `process_block` hashes every transaction of the block it is handed
//! (`BlockTxHashes`), and the merkle check, the duplicate check, the
//! connect and the connected event all read those hashes when the block
//! extends the tip.  The hashes belong to the block instance they were
//! computed from: every other block a call connects -- a
//! reorganization's -- is hashed again, which `Chain::tx_hash_recomputes`
//! counts.
//!
//! Under debug assertions every consumer of the hashes re-hashes its
//! block and compares, so the whole suite cross-checks the values.  The
//! tests here pin what that cannot: that every event carries the hashes
//! of its own block, that the hand-down is not a silent no-op (a block
//! that extends the tip is not hashed a second time to connect it), and
//! that it also holds on the branch initial sync takes, where a block
//! skips full validation.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::{Arc, Mutex};

use dcroxide_blockchain::notifications::Notification;
use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::{BlockTxHashes, RuleErrorKind};
use dcroxide_chaincfg::regnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_testutil::unhex;
use dcroxide_wire::{MsgBlock, MsgTx};

/// The block and the transaction hashes of each connected event.
type Connected = Vec<(Arc<MsgBlock>, Arc<BlockTxHashes>)>;

/// Collect what every connected event of the chain carries.
fn watch_connects(chain: &mut Chain) -> Arc<Mutex<Connected>> {
    let connected: Arc<Mutex<Connected>> = Arc::default();
    let sink = Arc::clone(&connected);
    chain.set_notification_callback(Box::new(move |ntfn| {
        if let Notification::BlockConnected(data) = ntfn {
            sink.lock()
                .expect("sink")
                .push((Arc::clone(&data.block), Arc::clone(data.tx_hashes())));
        }
    }));
    connected
}

/// The hash of each transaction, computed here.
fn fresh(txs: &[MsgTx]) -> Vec<Hash> {
    txs.iter().map(MsgTx::tx_hash).collect()
}

/// The event's hashes are those of the event's own block.
fn assert_own_hashes(label: &str, block: &MsgBlock, tx_hashes: &BlockTxHashes) {
    assert!(tx_hashes.fits(block), "{label}: one hash per transaction");
    assert_eq!(
        tx_hashes.regular(),
        fresh(&block.transactions),
        "{label}: regular tree"
    );
    assert_eq!(
        tx_hashes.stake(),
        fresh(&block.stransactions),
        "{label}: stake tree"
    );
}

/// The whole battery, rejected blocks included, through `process_block`.
#[test]
fn events_carry_their_own_hashes_and_a_tip_extension_is_connected_with_the_filed_hashes() {
    let params = regnet_params();
    let mut chain = Chain::new(&params, Hash::ZERO, false);
    let connected = watch_connects(&mut chain);

    let mut now: i64 = 0;
    let mut main_chain_rows = 0usize;
    let mut events = 0usize;
    let mut calls_with_several_connects = 0usize;
    let mut tip_extensions = 0usize;
    for line in include_str!("data/fullblock_vectors.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let (name, hex, accept) = match f[0] {
            "now" => {
                now = f[1].parse().expect("now");
                continue;
            }
            // accept <name> <mainchain> <orphan> <blockhex>
            "accept" => (f[1], f[4], true),
            // reject <name> <kind> <blockhex>
            "reject" => (f[1], f[3], false),
            // orphanorreject <name> <blockhex>
            "orphanorreject" => (f[1], f[2], false),
            _ => continue,
        };
        let (block, _) = MsgBlock::from_bytes(&unhex(hex)).expect("block");
        let tip_before = chain.best_chain.tip();
        let recomputes_before = chain.tx_hash_recomputes;
        let (_, errs) = chain.process_block(&block, now, &params);

        // Every block the call connected, whichever it was, went out
        // with its own hashes.
        let seen = core::mem::take(&mut *connected.lock().expect("connected"));
        for (connected_block, tx_hashes) in &seen {
            assert_own_hashes(name, connected_block, tx_hashes);
        }
        events += seen.len();
        calls_with_several_connects += usize::from(seen.len() > 1);

        if !accept {
            assert!(!errs.is_empty(), "{name} should have been refused");
            continue;
        }
        let is_orphan = errs.len() == 1 && errs[0].kind == RuleErrorKind::MissingParent;
        assert!(errs.is_empty() || is_orphan, "{name}: {errs:?}");
        main_chain_rows += usize::from(f[2] == "true");

        // The block became the tip on top of the old tip: it was
        // connected with the hashes `process_block` computed, so the
        // connect did not hash it again.
        let tip = chain.best_chain.tip().expect("tip");
        let tip_node = chain.store.node(tip);
        if tip_node.hash == block.header.block_hash() && tip_node.parent == tip_before {
            assert_eq!(seen.len(), 1, "{name}: one connect for a tip extension");
            assert_eq!(
                chain.tx_hash_recomputes, recomputes_before,
                "{name}: hashed again to be connected"
            );
            tip_extensions += 1;
        }
    }

    // Every main-chain row connected at least once; reorganizations
    // connect some blocks again.
    assert!(main_chain_rows > 0, "the battery has main-chain rows");
    assert!(
        events >= main_chain_rows,
        "{events} connected events for {main_chain_rows} main-chain rows"
    );
    assert!(
        calls_with_several_connects > 0,
        "the battery reorganizes, connecting several blocks in one call"
    );
    assert!(
        tip_extensions >= 20,
        "only {tip_extensions} blocks extended the tip"
    );
    // And the blocks a reorganization attached, which are not the block
    // being processed, were hashed for themselves.
    assert!(
        chain.tx_hash_recomputes > 0,
        "the reorganizations took the fresh path"
    );
}

/// The battery's leading run of main-chain blocks, before its first
/// side-chain block, with the battery's clock.  The rejected blocks in
/// between never enter a chain, so leaving them out changes nothing.
fn leading_main_chain_blocks() -> (i64, Vec<(String, MsgBlock)>) {
    let mut now = 0;
    let mut blocks = Vec::new();
    for line in include_str!("data/fullblock_vectors.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "now" => now = f[1].parse().expect("now"),
            "accept" if f[2] == "true" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                blocks.push((f[1].to_string(), block));
            }
            "accept" => break,
            _ => {}
        }
    }
    (now, blocks)
}

/// Initial sync connects blocks below the assumed-valid block without
/// full validation, through `UtxoView::connect_block` rather than
/// `check_connect_block`.  A bulk import takes that same branch: each
/// block is connected with the hashes filed for it, and the chain ends
/// where a fully validating one does, UTXO set included.
#[test]
fn a_block_that_skips_validation_is_connected_with_the_filed_hashes() {
    let params = regnet_params();
    let (now, blocks) = leading_main_chain_blocks();
    assert!(blocks.len() >= 100, "{} leading blocks", blocks.len());

    let mut validating = Chain::new(&params, Hash::ZERO, false);
    let mut importing = Chain::new(&params, Hash::ZERO, false);
    importing.bulk_import_mode = true;
    let connected = watch_connects(&mut importing);
    let mut with_stake_tree = 0usize;
    for (name, block) in &blocks {
        let (_, errs) = validating.process_block(block, now, &params);
        assert!(errs.is_empty(), "{name} validating: {errs:?}");
        let (_, errs) = importing.process_block(block, now, &params);
        assert!(errs.is_empty(), "{name} importing: {errs:?}");

        let seen = core::mem::take(&mut *connected.lock().expect("connected"));
        assert_eq!(seen.len(), 1, "{name}: one connect");
        let (connected_block, tx_hashes) = &seen[0];
        assert_eq!(
            connected_block.header.block_hash(),
            block.header.block_hash(),
            "{name}"
        );
        assert_own_hashes(name, connected_block, tx_hashes);
        with_stake_tree += usize::from(!block.stransactions.is_empty());
    }
    assert!(with_stake_tree > 0, "the run has stake transactions");

    // Neither chain hashed a block a second time to connect it.
    assert_eq!(importing.tx_hash_recomputes, 0);
    assert_eq!(validating.tx_hash_recomputes, 0);

    // And the import ends in the validating chain's state.
    let tip = |chain: &Chain| chain.store.node(chain.best_chain.tip().expect("tip")).hash;
    assert_eq!(tip(&importing), tip(&validating));
    assert_eq!(
        format!("{:?}", importing.state_snapshot),
        format!("{:?}", validating.state_snapshot)
    );
    assert_eq!(
        importing.fetch_utxo_stats().expect("import stats"),
        validating.fetch_utxo_stats().expect("validating stats")
    );
}
