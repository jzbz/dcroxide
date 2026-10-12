// SPDX-License-Identifier: ISC
//! The best state's missed tickets, held as a handle on the tip stake
//! node's missed treap, read as the list dcrd's `BestState` carries.
//!
//! dcrd builds `BestState.MissedTickets` from the stake node of the
//! new tip on every connect (`chain.go:654-658`), every disconnect
//! (`chain.go:853-857`) and at load (`chainio.go:1767-1771`).  The
//! port keeps a handle instead and builds the list when asked, so
//! these replay dcrd's full-block battery, reorganizations included,
//! and check that the handle reads exactly as that list does at every
//! state: after each connect, after a block is taken off the tip with
//! nothing connected in its place, and after the chain is loaded from
//! its database.
//!
//! The battery misses one ticket at a time, so the order of a longer
//! list is checked where the handle is defined, against dcrd's ticket
//! state vectors (`dcroxide-stake`, `tests/missed_ticket_set.rs`).

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

fn create(opts: &Options, params: &Params) -> Chain {
    let db = Database::create(opts).expect("create database");
    Chain::open(db, params, Hash::ZERO, false, 0).expect("open chain")
}

fn process(chain: &mut Chain, label: &str, block: &MsgBlock, now: i64, params: &Params) {
    let (_, errs) = chain.process_block(block, now, params);
    let is_orphan = errs.len() == 1 && errs[0].kind == RuleErrorKind::MissingParent;
    assert!(errs.is_empty() || is_orphan, "{label}: {errs:?}");
}

/// Check every way the handle in the best state can be read against
/// the list dcrd's best state carries at the current tip, the tip
/// stake node's `MissedTickets`, and return that list.
fn check_snapshot(chain: &mut Chain, params: &Params, what: &str) -> Vec<Hash> {
    let tip = chain.best_chain.tip().expect("tip");
    let stake_node = chain.fetch_stake_node(tip, params).expect("tip stake node");
    let want = stake_node.missed_tickets();
    let (live, revoked) = (stake_node.live_tickets(), stake_node.revoked_tickets());

    let got = &chain.best_snapshot().missed_tickets;
    assert_eq!(got.to_vec(), want, "{what}: the list");
    assert_eq!(got.len(), want.len(), "{what}: the count");
    assert_eq!(got.is_empty(), want.is_empty(), "{what}: emptiness");
    for ticket in &want {
        assert!(got.contains(ticket), "{what}: {ticket} is missed");
    }
    // A ticket is in one set at a time, so the other two sets hold
    // only tickets that are not missed.
    for ticket in live.iter().chain(&revoked) {
        assert!(!got.contains(ticket), "{what}: {ticket} is not missed");
    }
    assert_eq!(
        format!("{got:?}"),
        format!("{want:?}"),
        "{what}: the debug form"
    );
    want
}

#[test]
fn the_best_state_reads_its_tips_missed_tickets_after_connects_and_disconnects() {
    let params = regnet_params();
    let (now, blocks) = battery();
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let mut chain = create(&opts, &params);
    assert!(
        chain.best_snapshot().missed_tickets.is_empty(),
        "nothing is missed at the genesis block"
    );

    // Every state the battery reaches by connecting a block, the last
    // connect of each of its reorganizations among them.
    let mut connects_that_changed_the_set = 0;
    let mut first_missed_height = None;
    let mut previous: Vec<Hash> = Vec::new();
    // The handle of every state, with the list it read as then.
    let mut held = Vec::new();
    for (label, block) in &blocks {
        process(&mut chain, label, block, now, &params);
        let list = check_snapshot(&mut chain, &params, label);
        connects_that_changed_the_set += usize::from(list != previous);
        if !list.is_empty() && first_missed_height.is_none() {
            first_missed_height = Some(chain.best_snapshot().height);
        }
        held.push((chain.best_snapshot().missed_tickets.clone(), list.clone()));
        previous = list;
    }
    assert_eq!(held.len(), 205, "every accepted block of the battery");
    // One block misses a vote and a later one revokes the ticket.
    assert_eq!(
        connects_that_changed_the_set, 2,
        "the connects that change the missed set"
    );
    let first_missed_height = first_missed_height.expect("the battery misses a ticket");

    // Invalidating the tip takes that block off, and where its parent
    // becomes the tip nothing is connected afterwards, so the best
    // state is the one the disconnect built.  Walk back below the
    // first miss, which crosses both changes of the set in reverse.
    let mut disconnects_that_changed_the_set = 0;
    loop {
        let tip = chain.best_chain.tip().expect("tip");
        let (tip_hash, tip_height, parent) = {
            let n = chain.store.node(tip);
            (n.hash, n.height, n.parent)
        };
        if tip_height < first_missed_height {
            break;
        }
        let what = format!("after invalidating {tip_hash} at height {tip_height}");
        let before = check_snapshot(&mut chain, &params, "before the next invalidation");
        let errs = chain.invalidate_block(&tip_hash, now, &params);
        assert!(errs.is_empty(), "{what}: {errs:?}");
        let after = check_snapshot(&mut chain, &params, &what);
        if chain.best_chain.tip() == parent {
            disconnects_that_changed_the_set += usize::from(after != before);
        }
    }
    assert_eq!(
        disconnects_that_changed_the_set, 2,
        "the disconnects that change the missed set"
    );

    // A handle names the set of the block it was taken at, whatever
    // the chain did afterwards.
    for (i, (handle, list)) in held.iter().enumerate() {
        assert_eq!(&handle.to_vec(), list, "the handle of state {i} changed");
    }
}

#[test]
fn the_best_state_reads_its_tips_missed_tickets_after_a_restart() {
    let params = regnet_params();
    let (now, blocks) = battery();
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let mut chain = create(&opts, &params);

    // Stop at the first state with a missed ticket, so the load has a
    // set to rebuild.
    let mut want = Vec::new();
    for (label, block) in &blocks {
        process(&mut chain, label, block, now, &params);
        want = check_snapshot(&mut chain, &params, label);
        if !want.is_empty() {
            break;
        }
    }
    assert!(!want.is_empty(), "the battery misses a ticket");
    let tip = chain.best_snapshot().hash;
    chain.flush(&params).expect("clean shutdown flush");
    chain.db.as_ref().expect("db").close().expect("close");
    drop(chain);

    let db = Database::open(&opts).expect("open database");
    let mut chain = Chain::open(db, &params, Hash::ZERO, false, 0).expect("reopen chain");
    assert_eq!(chain.best_snapshot().hash, tip, "the restart kept the tip");
    let got = check_snapshot(&mut chain, &params, "after the restart");
    assert_eq!(got, want, "the restart kept the missed set");
}
