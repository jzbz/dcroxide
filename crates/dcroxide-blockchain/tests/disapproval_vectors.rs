// SPDX-License-Identifier: ISC
//! Replay of dcrd's `TestDisapprovalScenarios`
//! (`internal/blockchain/utxoviewpoint_test.go:259-755` at `382ff4dd`,
//! added by `2b896ffb` and `016d46af` over `81a671bd`'s harness helpers)
//! from `data/disapproval_vectors.txt`.
//!
//! The scenarios play blocks that disapprove the regular tree of their
//! parent on regnet from stake validation height, with real votes, and
//! check which outputs the UTXO set holds spendable after each step:
//!
//! - s1: a disapproval, then a different regular transaction spends the
//!   output the disapproved transaction had spent;
//! - s2: the same, spent by a ticket;
//! - s3: a disapproved in-block spend chain whose creating transaction
//!   alone is reincluded;
//! - s4: a reincluded transaction whose output is spent later in the
//!   reincluding block;
//! - s5: an in-block spend replaced by another in the disapproving
//!   block;
//! - s6: a reorganization to a branch that approves the parent, which
//!   restores the parent's in-block spend;
//! - s7: a reorganization away from and back to a branch that reincludes
//!   a transaction, with a forced flush first when flushes are off;
//! - s8: longer in-block spend chains across competing disapproving
//!   branches.
//!
//! dcrd runs them twice, with the UTXO cache flushing as on a node that is
//! current (after every block) and with flushing turned off as during the
//! initial sync, so that both the backend and the cache hold the outputs.
//!
//! The port has no `chaingen`, so the generator in
//! `tools/disapprovalgen` runs the scenarios inside dcrd's own package
//! at `382ff4dd` and writes down every block the chain processed and
//! what dcrd's chain did, as the move to `6f6cf21b` did for
//! `ticketspend_vectors`.  Its clock and the generator's random values
//! are fixed, so a run at an unchanged pin writes the same file.  The
//! replay drives a database-backed chain through `Chain::process_block`
//! with the cache size of dcrd's test chain, checks what dcrd checked,
//! and also that the cache flushed at the same blocks, in the same order,
//! as dcrd's did, and that the backend records the same utxo set state.
//! Every block it attaches runs the view assertions of `22fd2431`.
//!
//! Rows, in each run's section after the blocks:
//!
//! - `block <name> <hex>`: a block either run processes, first;
//! - `test <flush-enabled|flush-disabled>`, `params regnet`, `now <unix>`:
//!   a run on a fresh chain, with the adjusted time every block is
//!   processed at and block one's timestamp;
//! - `process <name> <fork length>`: dcrd accepted the block with this
//!   fork length, zero for the main chain;
//! - `flushed <hash> <height>`: dcrd's cache flushed through this block
//!   during the step above (every connect flushes while the chain is
//!   current, every disconnect is forced, a forced flush flushes);
//! - `state <hash> <height>`: the utxo set state dcrd's backend records
//!   after the step;
//! - `tip <name>`, `disapproves <name>`: dcrd's `ExpectTip` and
//!   `AssertTipDisapprovesPrevious`;
//! - `spendable` and `unspendable <hash> <index> <tree>`: dcrd's
//!   `ExpectUtxoSpendable` and `ExpectUtxoUnspendable`, through the cache;
//! - `forceflush`: dcrd's `ForceUtxoCacheFlush`, a flush through the tip
//!   with flushing turned on for its duration;
//! - `disableflushes`: dcrd's `DisableUtxoCacheFlushes`.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::{BTreeMap, VecDeque};

use dcroxide_blockchain::chaindb::db_fetch_utxo_set_state;
use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::regnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_testutil::unhex;
use dcroxide_wire::{MsgBlock, OutPoint};
use tempfile::TempDir;

/// The maximum size of the UTXO cache of dcrd's test chain
/// (`common_test.go:154`).
const TEST_CACHE_MAX_BYTES: u64 = 100 * 1024;

fn vector_rows() -> impl Iterator<Item = Vec<&'static str>> {
    include_str!("data/disapproval_vectors.txt")
        .lines()
        .map(|line| line.split(' ').collect())
}

/// Every block of the file, by name.
fn blocks() -> BTreeMap<&'static str, MsgBlock> {
    vector_rows()
        .filter(|f| f[0] == "block")
        .map(|f| {
            let (block, _) = MsgBlock::from_bytes(&unhex(f[2])).expect("block");
            (f[1], block)
        })
        .collect()
}

/// The rows of one run's section.
fn section(mode: &str) -> Vec<Vec<&'static str>> {
    let mut rows = Vec::new();
    let mut inside = false;
    for f in vector_rows() {
        if f[0] == "test" {
            inside = f[1] == mode;
            continue;
        }
        if inside {
            rows.push(f);
        }
    }
    assert!(!rows.is_empty(), "no {mode} section in the vector file");
    rows
}

fn outpoint(f: &[&str]) -> OutPoint {
    OutPoint {
        hash: f[1].parse().expect("hash"),
        index: f[2].parse().expect("index"),
        tree: f[3].parse().expect("tree"),
    }
}

/// What a run checked, by row kind.
#[derive(Debug, Default, PartialEq)]
struct Tally {
    processed: usize,
    side_chain: usize,
    flushes: usize,
    states: usize,
    spendable: usize,
    unspendable: usize,
    forced: usize,
}

fn replay(mode: &str) -> Tally {
    let params = regnet_params();
    let blocks = blocks();
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let mut chain = Chain::open(
        Database::create(&opts).expect("create database"),
        &params,
        Hash::ZERO,
        false,
        0,
    )
    .expect("open chain");
    chain.set_utxo_cache_max_bytes(TEST_CACHE_MAX_BYTES);
    chain.utxo_flush_test_hooks.log = Some(Vec::new());

    let mut now = None;
    let mut tally = Tally::default();
    // The flushes the port made in the current step that the file has
    // not named yet.
    let mut flushes: VecDeque<(Hash, u32)> = VecDeque::new();
    let take_flushes = |chain: &mut Chain, flushes: &mut VecDeque<(Hash, u32)>| {
        let log = chain.utxo_flush_test_hooks.log.as_mut().expect("flush log");
        flushes.extend(log.drain(..));
    };

    for f in section(mode) {
        let line = f.join(" ");
        match f[0] {
            "params" => assert_eq!(f[1], "regnet"),
            "now" => now = Some(f[1].parse::<i64>().expect("now")),
            "process" => {
                assert!(
                    flushes.is_empty(),
                    "{line}: flushes dcrd did not make: {flushes:?}"
                );
                let block = &blocks[f[1]];
                let (fork_len, errs) = chain.process_block(block, now.expect("now row"), &params);
                assert!(errs.is_empty(), "{line}: {errs:?}");
                assert_eq!(fork_len.to_string(), f[2], "{line}: fork length");
                take_flushes(&mut chain, &mut flushes);
                tally.processed += 1;
                if fork_len != 0 {
                    tally.side_chain += 1;
                }
            }
            "flushed" => {
                let want = (
                    f[1].parse::<Hash>().expect("hash"),
                    f[2].parse().expect("height"),
                );
                assert_eq!(flushes.pop_front(), Some(want), "{line}: the next flush");
                tally.flushes += 1;
            }
            "state" => {
                assert!(
                    flushes.is_empty(),
                    "{line}: flushes dcrd did not make: {flushes:?}"
                );
                let db = chain.db.as_ref().expect("database-backed chain");
                let mut state = None;
                db.view(|tx| {
                    state = db_fetch_utxo_set_state(tx).expect("utxo set state");
                    Ok(())
                })
                .expect("read the utxo set state");
                let state = state.expect("a recorded utxo set state");
                assert_eq!(
                    (
                        state.last_flush_hash.to_string(),
                        state.last_flush_height.to_string()
                    ),
                    (f[1].to_string(), f[2].to_string()),
                    "{line}: the backend's utxo set state"
                );
                tally.states += 1;
            }
            "tip" => {
                let tip = chain.best_chain.tip().expect("tip");
                assert_eq!(
                    chain.store.node(tip).hash,
                    blocks[f[1]].header.block_hash(),
                    "{line}"
                );
            }
            "disapproves" => {
                assert_eq!(blocks[f[1]].header.vote_bits & 1, 0, "{line}");
            }
            "spendable" => {
                let entry = chain.fetch_utxo_entry(&outpoint(&f));
                assert!(
                    entry.as_ref().is_some_and(|entry| !entry.is_spent()),
                    "{line}: not spendable: {entry:?}"
                );
                tally.spendable += 1;
            }
            "unspendable" => {
                let entry = chain.fetch_utxo_entry(&outpoint(&f));
                assert!(
                    entry.as_ref().is_none_or(|entry| entry.is_spent()),
                    "{line}: spendable: {entry:?}"
                );
                tally.unspendable += 1;
            }
            "forceflush" => {
                assert!(
                    flushes.is_empty(),
                    "{line}: flushes dcrd did not make: {flushes:?}"
                );
                // Flushing is turned on for the duration of the forced
                // flush (`common_test.go:1057-1079`).
                let disabled = chain.utxo_flush_test_hooks.disabled;
                chain.utxo_flush_test_hooks.disabled = false;
                chain.flush_utxo_cache_for_stats().expect("forced flush");
                chain.utxo_flush_test_hooks.disabled = disabled;
                take_flushes(&mut chain, &mut flushes);
                tally.forced += 1;
            }
            "disableflushes" => chain.utxo_flush_test_hooks.disabled = true,
            other => panic!("unknown row kind {other}: {line}"),
        }
    }
    assert!(flushes.is_empty(), "flushes dcrd did not make: {flushes:?}");
    tally
}

/// The scenarios with the cache flushing as on a current node.
#[test]
fn disapproval_scenarios_with_flushes() {
    let tally = replay("flush-enabled");
    assert_eq!(
        tally,
        Tally {
            processed: 170,
            side_chain: 5,
            flushes: 180,
            states: 28,
            spendable: 21,
            unspendable: 57,
            forced: 1,
        }
    );
}

/// The scenarios with the cache flushing turned off, as during the
/// initial sync, except where dcrd forces it.
#[test]
fn disapproval_scenarios_without_flushes() {
    let tally = replay("flush-disabled");
    assert_eq!(
        tally,
        Tally {
            processed: 170,
            side_chain: 5,
            flushes: 146,
            states: 29,
            spendable: 21,
            unspendable: 57,
            forced: 2,
        }
    );
}
