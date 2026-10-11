// SPDX-License-Identifier: ISC
//! The maturing tickets of a block come from a cache of recent blocks'
//! ticket purchases, not from re-reading the block `ticket_maturity`
//! below it.
//!
//! `maybe_fetch_new_tickets` (dcrd `maybeFetchNewTickets`) lists the
//! ticket purchases of the ancestor `ticket_maturity` blocks back.
//! During initial sync that ancestor's body has already left memory, so
//! each connect read it from the block files, checksummed it and decoded
//! it whole.  The chain now files each accepted block's ticket purchases
//! under its hash and looks there first.
//!
//! The battery is replayed behind a header far ahead, the shape of
//! headers-first sync, so every connect prunes its parent and the old
//! path would read a block back each time.  The tests pin that the cache
//! answers instead, that what it holds is exactly what the block gives,
//! and that a chain whose cache is emptied behind it ends in the same
//! state through the fallback.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::RuleErrorKind;
use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::{Params, regnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_testutil::unhex;
use dcroxide_wire::MsgBlock;
use tempfile::TempDir;

/// The battery's clock and its accepted blocks in file order.
fn battery() -> (i64, Vec<(String, MsgBlock)>) {
    let mut now = 0;
    let mut blocks = Vec::new();
    for line in include_str!("data/fullblock_vectors.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "now" => now = f[1].parse().expect("now"),
            "accept" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                blocks.push((f[1].to_string(), block));
            }
            _ => {}
        }
    }
    (now, blocks)
}

fn process(chain: &mut Chain, label: &str, block: &MsgBlock, now: i64, params: &Params) {
    let (_, errs) = chain.process_block(block, now, params);
    let is_orphan = errs.len() == 1 && errs[0].kind == RuleErrorKind::MissingParent;
    assert!(errs.is_empty() || is_orphan, "{label}: {errs:?}");
}

/// A block's ticket purchases, computed here from the block alone.
fn purchases(block: &MsgBlock) -> Vec<Hash> {
    block
        .stransactions
        .iter()
        .filter(|stx| dcroxide_stake::is_sstx(stx))
        .map(|stx| stx.tx_hash())
        .collect()
}

/// The chain state a replay ends with.
#[derive(Debug, PartialEq)]
struct Outcome {
    tip: Hash,
    snapshot: String,
    missed: Vec<Hash>,
    revoked: Vec<Hash>,
    live: Vec<Hash>,
}

fn outcome(chain: &mut Chain, params: &Params) -> Outcome {
    let tip = chain.best_chain.tip().expect("tip");
    let stake_node = chain.fetch_stake_node(tip, params).expect("tip stake node");
    Outcome {
        tip: chain.store.node(tip).hash,
        snapshot: format!("{:?}", chain.state_snapshot),
        missed: stake_node.missed_tickets(),
        revoked: stake_node.revoked_tickets(),
        live: stake_node.live_tickets(),
    }
}

fn open_chain(dir: &TempDir, params: &Params) -> Chain {
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    Chain::open(db, params, Hash::ZERO, false, 0).expect("open chain")
}

/// Put a header 10,000 blocks ahead of the tip that nothing in the
/// battery can overtake, so each later connect prunes its parent.
fn lead_with_a_far_header(chain: &mut Chain) {
    let tip = chain.best_chain.tip().expect("tip");
    let mut header = chain.store.header(tip);
    header.prev_block = chain.store.node(tip).hash;
    header.height += 10_000;
    header.bits = 0x0300_0001;
    header.nonce = header.nonce.wrapping_add(1);
    let ahead = chain.store.new_node(&header, Some(tip));
    chain.index.add_node(&chain.store, ahead);
    assert_eq!(chain.index.best_header(), Some(ahead));
}

/// Replay the battery behind a far header.  `forget` empties the cache
/// before every block, which forces the fallback throughout.
fn replay(forget: bool) -> (Chain, TempDir, Outcome, Vec<(String, MsgBlock)>) {
    let params = regnet_params();
    let (now, blocks) = battery();
    let split = blocks
        .iter()
        .position(|(label, _)| label == "bsv0")
        .expect("bsv0 in the battery");
    let dir = TempDir::new().expect("tempdir");
    let mut chain = open_chain(&dir, &params);
    for (label, block) in &blocks[..split] {
        process(&mut chain, label, block, now, &params);
    }
    lead_with_a_far_header(&mut chain);
    chain.ticket_purchase_misses = 0;
    for (label, block) in &blocks[split..] {
        if forget {
            chain.ticket_purchases.clear();
        }
        process(&mut chain, label, block, now, &params);
    }
    let end = outcome(&mut chain, &params);
    (chain, dir, end, blocks)
}

#[test]
fn the_cache_answers_and_the_fallback_agrees() {
    let (cached, _dir_a, with_cache, blocks) = replay(false);
    let (forgetful, _dir_b, without_cache, _) = replay(true);

    // Behind a far header every connect prunes its parent, so without
    // the cache each lookup past the stake-enabled height reads a block
    // back: the forgetful replay shows how many there are to save.
    assert!(
        forgetful.ticket_purchase_misses > 100,
        "the battery should exercise the lookup: {} misses",
        forgetful.ticket_purchase_misses
    );
    // With the cache, the only lookups that may miss are those whose
    // ancestor was accepted before the cache's window: none on the
    // battery's main line, a few across its deepest reorganizations.
    assert!(
        cached.ticket_purchase_misses * 20 < forgetful.ticket_purchase_misses,
        "the cache missed {} of {} lookups",
        cached.ticket_purchase_misses,
        forgetful.ticket_purchase_misses
    );

    // Both end in the same state: tip, snapshot and every ticket set.
    assert_eq!(with_cache, without_cache);

    // And every entry the cache holds is its block's own list.
    let by_hash: std::collections::BTreeMap<[u8; 32], &MsgBlock> = blocks
        .iter()
        .map(|(_, block)| (block.header.block_hash().0, block))
        .collect();
    assert!(!cached.ticket_purchases.is_empty());
    let mut with_tickets = 0;
    for (hash, tickets) in &cached.ticket_purchases {
        let block = by_hash
            .get(hash)
            .expect("a cached block is a battery block");
        assert_eq!(tickets, &purchases(block), "block {}", Hash(*hash));
        with_tickets += usize::from(!tickets.is_empty());
    }
    assert!(with_tickets > 0, "no cached block bought a ticket");
}

#[test]
fn the_cache_keeps_twice_the_ticket_maturity() {
    let params = regnet_params();
    let (cached, _dir, _, blocks) = replay(false);
    let keep = usize::from(params.ticket_maturity) * 2;
    assert!(blocks.len() > keep, "the battery outgrows the window");
    assert_eq!(cached.ticket_purchases.len(), keep);

    // And they are the last ones accepted, whichever chain they are on.
    let want: std::collections::BTreeSet<[u8; 32]> = blocks[blocks.len() - keep..]
        .iter()
        .map(|(_, block)| block.header.block_hash().0)
        .collect();
    let got: std::collections::BTreeSet<[u8; 32]> =
        cached.ticket_purchases.keys().copied().collect();
    assert_eq!(got, want, "the window is the last {keep} blocks accepted");
}

/// A body its header does not commit to files nothing, and the real
/// block's own list is what its hash holds afterwards.
#[test]
fn a_body_the_header_does_not_commit_to_files_nothing() {
    let params = regnet_params();
    let (now, blocks) = battery();
    let split = blocks
        .iter()
        .position(|(label, _)| label == "bsv0")
        .expect("bsv0 in the battery");
    let dir = TempDir::new().expect("tempdir");
    let mut chain = open_chain(&dir, &params);
    for (label, block) in &blocks[..split] {
        process(&mut chain, label, block, now, &params);
    }
    let (label, real) = &blocks[split];
    let hash = real.header.block_hash();
    assert!(purchases(real).len() >= 2, "{label} buys tickets");

    // The same header over a stake tree with one purchase taken out.
    let mut forged = real.clone();
    let at = forged
        .stransactions
        .iter()
        .position(dcroxide_stake::is_sstx)
        .expect("a purchase");
    forged.stransactions.remove(at);
    let (_, errs) = chain.process_block(&forged, now, &params);
    assert_eq!(errs.len(), 1, "{errs:?}");
    assert_eq!(errs[0].kind, RuleErrorKind::BadMerkleRoot, "{errs:?}");
    assert!(
        !chain.ticket_purchases.contains_key(&hash.0),
        "a rejected body was filed"
    );

    process(&mut chain, label, real, now, &params);
    assert_eq!(chain.ticket_purchases.get(&hash.0), Some(&purchases(real)));
}
