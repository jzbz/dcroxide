// SPDX-License-Identifier: ISC
//! Replay of chains that cross the treasury agenda's activation boundary
//! with a block that disapproves its parent, from
//! `data/trsyboundary_vectors.txt`, the boundary dcrd's `37fd3a3e`
//! corrects.
//!
//! `is_treasury_agenda_active` at a block gives the agenda state of the
//! block after it, so a disapproved parent P is undone, and redone when
//! its child is detached, with the state at P's own parent.  That flag
//! differs from the child's at one block only: H_act, the first block
//! under the agenda, whose parent H_act-1 is still before it.  Read with
//! H_act's flag, H_act-1's spend journal comes up one spent output
//! short, as if its first stake transaction were a treasurybase, and its
//! version 1 coinbase is judged under the treasury rules.
//!
//! dcrd added no tests with the fix, and the port has no `chaingen`, so
//! `tools/trsyboundarygen` plays the chains inside dcrd's own
//! `internal/blockchain` package at the parity pin and writes down every
//! block and what dcrd's chain did with it.  Each case votes the agenda
//! in on a fresh chain under `quickVoteActivationParams`
//! (`validate_test.go:239-263`): bva19, at height 69, is H_act-1, and h70
//! is an H_act that disapproves it.
//!
//! - extend: h70 on the tip, and an approving child;
//! - reorg: a reorganization from h70 to a branch whose own H_act, p70,
//!   disapproves a sibling H_act-1 and is attached unvalidated, and back,
//!   which detaches p70 and attaches h70 again, validated before;
//! - restart: with flushes off, a restart catches the cache up across h70
//!   from H_act-1; then, after an unclean reorganization away from h70, a
//!   restart detaches h70 again, redoing H_act-1's regular tree, whose
//!   entries the `entry` rows check;
//! - templates: h70 checked as a template on H_act-1, templates beside a
//!   tip h70 that disapprove and approve H_act-1, and the view of their
//!   parent, whose entries the `viewentry` rows check;
//! - beyond: d71 disapproves h70 on the tip, where h70's own flag is
//!   active as well as d71's, and a reorganization detaches d71 again,
//!   redoing h70's regular tree, whose entries the `entry` rows check.
//!
//! The file's sixth case, fetchview, is dcrd's `FetchUtxoView` on the
//! tips H_act-1 and h70, which the port has in the node's mempool
//! adapter; `dcroxide-node`'s `tests/trsyboundary_fetch_view.rs` replays
//! it, and nothing here reads its section.
//!
//! Each place the port takes the parent's flag fails a case when it
//! takes the child's instead.  Every one fails by a panic: where the
//! parent is undone, its journal comes up one spent output short of
//! what its transactions spend; where it is redone, the version 1
//! coinbase is not a coinbase under the treasury rules and its null
//! input is spent.
//!
//! | site | cases | the panic |
//! | --- | --- | --- |
//! | `check_connect_block` | all five replayed here, at h70 | journal short |
//! | reorganization, attach of a validated block | reorg, h70 again | journal short |
//! | reorganization, detach | reorg, restart | coinbase input |
//! | startup catch-up, attach | restart, first restart | journal short |
//! | startup catch-up, detach | restart, second restart | coinbase input |
//! | template beside the tip, detach of the tip | templates | coinbase input |
//! | parent template view, detach of the tip | templates | coinbase input |
//! | parent template view, attach of the template | templates, s70d | journal short |
//! | `UtxoView::connect_block`, undo of the parent | reorg, restart, templates | journal short |
//! | `UtxoView::disconnect_block`, redo of the parent | reorg, restart, templates | coinbase input |
//!
//! `check_connect_block` is also where a reorganization attaches p70
//! unvalidated and where a template beside the tip is checked; h70
//! reaches it first in every case.  The two `UtxoView` rows are the
//! undo and the redo every caller above goes through.
//!
//! Two of the redo sites have rows behind the panic, which a redo that
//! got past the coinbase but left the wrong entries would still fail:
//! the startup catch-up's detach (the restart case's `entry` rows) and
//! the parent template view's (the `viewentry` rows).  The
//! reorganization's detach and the detach of the tip beside a template
//! fail only by the panic, as dcrd's do: bva19 is detached again right
//! after its redo, and the template's view is thrown away.
//!
//! The beyond case is the one where the parent's flag is active.  When
//! `is_parent_treasury_agenda_active` looks one block too far back, or
//! never answers true, d71 is rejected there, h70's journal failing to
//! decode, while every case at the boundary still passes.  Its `entry`
//! rows check a reorganization's redo under that flag.
//!
//! The replay drives a database-backed chain through
//! `Chain::process_block` with the cache size of dcrd's test chain and
//! checks what dcrd checked.  The periodic flush is timed on a clock
//! that does not move, as every cache the generator makes is, so a slow
//! run flushes at no other step.  A restart closes the database and
//! opens the chain again over it, which loses the cache, as dcrd's test
//! replaces its cache with a new one on the same backend.
//!
//! Rows, after a `block <name> <hex>` row for every block:
//!
//! - `test <case>`, `params quickvote`, `now <unix>`: a case on a fresh
//!   chain, with the adjusted time every block is processed at;
//! - `process <name> <fork length>`: dcrd accepted the block;
//! - `state <hash> <height>`: the utxo set state dcrd's backend recorded
//!   after the step;
//! - `treasury <name> <bool>`: whether the agenda is active for the block
//!   after the named one;
//! - `tip <name>`, `disapproves <name>`: dcrd's `ExpectTip` and
//!   `AssertTipDisapprovesPrevious`, which looks at the generator's tip,
//!   the named block, not the chain's;
//! - `spendable` and `unspendable <hash> <index> <tree>`: dcrd's
//!   `ExpectUtxoSpendable` and `ExpectUtxoUnspendable`;
//! - `entry <hash> <index> <tree> <entry>`: the unspent entry dcrd's
//!   `FetchUtxoEntry` returned;
//! - `forceflush`, `disableflushes`: dcrd's `ForceUtxoCacheFlush` and
//!   `DisableUtxoCacheFlushes`;
//! - `restorejournal <name> <hex>`: the block's spend journal entry, which
//!   the reorganization removed though the cache was not flushed, put back
//!   as an unclean shutdown before that flush would have left it;
//! - `restart`: the cache lost and caught up again from the backend;
//! - `template <name>`: `CheckConnectBlockTemplate` accepted the block;
//! - `parenttemplate <name>`: `FetchUtxoViewParentTemplate` returned a
//!   view, followed by its `viewentry <hash> <index> <tree> <entry>` rows.
//!
//! An entry is `missing`, `spent`, or the amount, height, block index,
//! transaction type, coinbase and expiry flags, script version and
//! script of an unspent entry.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

use dcroxide_blockchain::UtxoEntry;
use dcroxide_blockchain::chaindb::{
    db_fetch_spend_journal_entry, db_fetch_utxo_set_state, db_put_spend_journal_entry,
};
use dcroxide_blockchain::process::{Chain, OpenConfig};
use dcroxide_chaincfg::{Params, regnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_testutil::{hex, unhex};
use dcroxide_wire::{MsgBlock, OutPoint};
use tempfile::TempDir;

/// The maximum size of the UTXO cache of dcrd's test chain
/// (`common_test.go:154`), which a restart keeps.
const TEST_CACHE_MAX_BYTES: u64 = 100 * 1024;

/// dcrd's `quickVoteActivationParams` (`validate_test.go:239-263`).  The
/// treasury deployment is open for voting on regnet already.
fn quick_vote_activation_params() -> Params {
    let mut p = regnet_params();
    p.work_diff_window_size = 200_000;
    p.work_diff_windows = 1;
    p.target_timespan_secs = p.target_time_per_block_secs * p.work_diff_window_size;
    p.coinbase_maturity = 2;
    p.block_enforce_num_required = 5;
    p.block_reject_num_required = 7;
    p.block_upgrade_num_to_check = 10;
    p.ticket_maturity = 2;
    p.ticket_pool_size = 4;
    p.ticket_expiry = 6 * u32::from(p.ticket_pool_size);
    p.stake_enabled_height = i64::from(p.coinbase_maturity) + i64::from(p.ticket_maturity);
    p.stake_validation_height = i64::from(p.coinbase_maturity) + i64::from(p.ticket_pool_size) * 2;
    p.stake_version_interval = 10;
    p.rule_change_activation_interval =
        u32::from(p.ticket_pool_size) * u32::from(p.tickets_per_block);
    p.rule_change_activation_quorum =
        p.rule_change_activation_interval * u32::from(p.tickets_per_block * 100) / 1000;
    p
}

fn vector_rows() -> impl Iterator<Item = Vec<&'static str>> {
    include_str!("data/trsyboundary_vectors.txt")
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

/// The rows of one case's section.
fn section(case: &str) -> Vec<Vec<&'static str>> {
    let mut rows = Vec::new();
    let mut inside = false;
    for f in vector_rows() {
        if f[0] == "test" {
            inside = f[1] == case;
            continue;
        }
        if inside {
            rows.push(f);
        }
    }
    assert!(!rows.is_empty(), "no {case} section in the vector file");
    rows
}

fn outpoint(f: &[&str]) -> OutPoint {
    OutPoint {
        hash: f[1].parse().expect("hash"),
        index: f[2].parse().expect("index"),
        tree: f[3].parse().expect("tree"),
    }
}

/// An entry as the generator writes it (its `exportEntry`).
fn entry_text(entry: Option<&UtxoEntry>) -> String {
    match entry {
        None => "missing".to_string(),
        Some(entry) if entry.is_spent() => "spent".to_string(),
        Some(entry) => format!(
            "{} {} {} {} {} {} {} {}",
            entry.amount(),
            entry.block_height(),
            entry.block_index(),
            entry.transaction_type(),
            entry.is_coin_base(),
            entry.has_expiry(),
            entry.script_version(),
            hex(entry.pk_script()),
        ),
    }
}

/// A chain on its own database, which a restart opens again.
struct Node {
    // Held so the database directory outlives the chain.
    _dir: TempDir,
    opts: Options,
    params: Params,
    chain: Chain,
}

impl Node {
    fn new(params: Params) -> Node {
        let dir = TempDir::new().expect("tempdir");
        let opts = Options::new(dir.path().join("chain"), params.net.0);
        let chain = Self::open(Database::create(&opts).expect("create database"), &params);
        Node {
            _dir: dir,
            opts,
            params,
            chain,
        }
    }

    /// Open the chain, with its periodic jobs timed on [`fixed_clock`] from
    /// then on, as the generator sets `exportClock` on every cache.
    fn open(db: Database, params: &Params) -> Chain {
        let mut config = OpenConfig::new(Hash::ZERO, false, 0);
        config.utxo_cache_max_bytes = TEST_CACHE_MAX_BYTES;
        let mut chain = Chain::open_with_config(db, params, config).expect("open chain");
        chain.set_periodic_clock(fixed_clock);
        chain
    }

    /// Lose the cache and catch it up from the backend: the database's
    /// writes are made durable and the chain is opened again over it.
    /// The flush switch is put back as it was once the open, and with it
    /// the catch-up, is done; dcrd sets it on the new cache before the
    /// catch-up, which flushes nothing in these chains either way.
    fn restart(&mut self) {
        let disabled = self.chain.utxo_flush_test_hooks.disabled;
        let db = self.chain.db.clone().expect("database-backed chain");
        db.flush().expect("database flush");
        let old = std::mem::replace(&mut self.chain, Chain::new(&self.params, Hash::ZERO, false));
        drop(old);
        db.close().expect("close database");
        drop(db);
        let db = Database::open(&self.opts).expect("reopen database");
        self.chain = Self::open(db, &self.params);
        self.chain.utxo_flush_test_hooks.disabled = disabled;
    }

    fn state(&self) -> (String, String) {
        let db = self.chain.db.as_ref().expect("database-backed chain");
        let mut state = None;
        db.view(|tx| {
            state = db_fetch_utxo_set_state(tx).expect("utxo set state");
            Ok(())
        })
        .expect("read the utxo set state");
        let state = state.expect("a recorded utxo set state");
        (
            state.last_flush_hash.to_string(),
            state.last_flush_height.to_string(),
        )
    }

    /// Put back a block's spend journal entry, which must be gone.
    fn restore_journal(&self, block: &MsgBlock, serialized: &[u8]) {
        let db = self.chain.db.as_ref().expect("database-backed chain");
        let hash = block.header.block_hash();
        let height = block.header.height;
        db.view(|tx| {
            assert_eq!(
                db_fetch_spend_journal_entry(tx, &hash, height),
                None,
                "the spend journal entry of {hash} was not removed"
            );
            Ok(())
        })
        .expect("read the spend journal");
        db.update(|tx| {
            db_put_spend_journal_entry(tx, &hash, height, serialized)
                .unwrap_or_else(|e| panic!("spend journal entry: {e:?}"));
            Ok(())
        })
        .expect("write the spend journal entry");
    }
}

/// A clock that does not move, for [`Chain::set_periodic_clock`]: the
/// periodic flush never comes due.
fn fixed_clock() -> Option<i64> {
    Some(0)
}

/// What a case checked or did, by row kind.
#[derive(Debug, Default, PartialEq)]
struct Tally {
    processed: usize,
    side_chain: usize,
    states: usize,
    treasury: usize,
    tips: usize,
    disapprovals: usize,
    spendable: usize,
    unspendable: usize,
    entries: usize,
    flushes: usize,
    flush_disables: usize,
    journals_restored: usize,
    restarts: usize,
    templates: usize,
    parent_templates: usize,
    view_entries: usize,
}

fn replay(case: &str) -> Tally {
    let blocks = blocks();
    let mut node: Option<Node> = None;
    let mut now = None;
    let mut tally = Tally::default();
    // The view of the last `parenttemplate` row, which its `viewentry`
    // rows read.
    let mut template_view = None;

    for f in section(case) {
        let line = f.join(" ");
        if f[0] == "params" {
            assert_eq!(f[1], "quickvote", "{line}");
            node = Some(Node::new(quick_vote_activation_params()));
            continue;
        }
        let node = node.as_mut().expect("a params row first");
        let params = node.params.clone();
        if f[0] != "viewentry" {
            template_view = None;
        }
        match f[0] {
            "now" => now = Some(f[1].parse::<i64>().expect("now")),
            "process" => {
                let block = &blocks[f[1]];
                let (fork_len, errs) =
                    node.chain
                        .process_block(block, now.expect("now row"), &params);
                assert!(errs.is_empty(), "{line}: {errs:?}");
                assert_eq!(fork_len.to_string(), f[2], "{line}: fork length");
                tally.processed += 1;
                if fork_len != 0 {
                    tally.side_chain += 1;
                }
            }
            "state" => {
                assert_eq!(
                    node.state(),
                    (f[1].to_string(), f[2].to_string()),
                    "{line}: the backend's utxo set state"
                );
                tally.states += 1;
            }
            "treasury" => {
                let hash = blocks[f[1]].header.block_hash();
                let active = node
                    .chain
                    .is_treasury_agenda_active(&hash, &params)
                    .unwrap_or_else(|e| panic!("{line}: {e:?}"));
                assert_eq!(active.to_string(), f[2], "{line}");
                tally.treasury += 1;
            }
            "tip" => {
                let tip = node.chain.best_chain.tip().expect("tip");
                assert_eq!(
                    node.chain.store.node(tip).hash,
                    blocks[f[1]].header.block_hash(),
                    "{line}"
                );
                tally.tips += 1;
            }
            "disapproves" => {
                // dcrd asserts this of the generator's tip, the named
                // block, which a side chain block can be.
                assert_eq!(blocks[f[1]].header.vote_bits & 1, 0, "{line}");
                tally.disapprovals += 1;
            }
            "spendable" => {
                let entry = node.chain.fetch_utxo_entry(&outpoint(&f));
                assert!(
                    entry.as_ref().is_some_and(|entry| !entry.is_spent()),
                    "{line}: not spendable: {entry:?}"
                );
                tally.spendable += 1;
            }
            "unspendable" => {
                let entry = node.chain.fetch_utxo_entry(&outpoint(&f));
                assert!(
                    entry.as_ref().is_none_or(|entry| entry.is_spent()),
                    "{line}: spendable: {entry:?}"
                );
                tally.unspendable += 1;
            }
            "entry" => {
                let entry = node.chain.fetch_utxo_entry(&outpoint(&f));
                assert_eq!(entry_text(entry.as_ref()), f[4..].join(" "), "{line}");
                tally.entries += 1;
            }
            "forceflush" => {
                // Flushing is turned on for the duration of the forced
                // flush (`common_test.go:1057-1079`).
                let disabled = node.chain.utxo_flush_test_hooks.disabled;
                node.chain.utxo_flush_test_hooks.disabled = false;
                node.chain
                    .flush_utxo_cache_for_stats()
                    .expect("forced flush");
                node.chain.utxo_flush_test_hooks.disabled = disabled;
                tally.flushes += 1;
            }
            "disableflushes" => {
                node.chain.utxo_flush_test_hooks.disabled = true;
                tally.flush_disables += 1;
            }
            "restorejournal" => {
                node.restore_journal(&blocks[f[1]], &unhex(f[2]));
                tally.journals_restored += 1;
            }
            "restart" => {
                node.restart();
                tally.restarts += 1;
            }
            "template" => {
                node.chain
                    .check_connect_block_template(&blocks[f[1]], now.expect("now row"), &params)
                    .unwrap_or_else(|e| panic!("{line}: {e:?}"));
                tally.templates += 1;
            }
            "parenttemplate" => {
                let view = node
                    .chain
                    .fetch_utxo_view_parent_template(&blocks[f[1]], &params)
                    .unwrap_or_else(|e| panic!("{line}: {e}"));
                template_view = Some(view);
                tally.parent_templates += 1;
            }
            "viewentry" => {
                let view = template_view.as_ref().expect("a parenttemplate row first");
                assert_eq!(
                    entry_text(view.lookup_entry(&outpoint(&f))),
                    f[4..].join(" "),
                    "{line}"
                );
                tally.view_entries += 1;
            }
            other => panic!("unknown row kind {other}: {line}"),
        }
    }
    tally
}

/// The disapproving H_act on the tip, and an approving child.
#[test]
fn a_disapproving_activation_block_extends_the_tip() {
    assert_eq!(
        replay("extend"),
        Tally {
            processed: 71,
            states: 3,
            treasury: 2,
            tips: 3,
            disapprovals: 1,
            spendable: 7,
            unspendable: 15,
            ..Tally::default()
        }
    );
}

/// A reorganization away from a disapproving H_act to a branch whose own
/// H_act is attached unvalidated, and back.
#[test]
fn a_reorganization_crosses_the_activation_boundary_both_ways() {
    assert_eq!(
        replay("reorg"),
        Tally {
            processed: 75,
            side_chain: 3,
            states: 7,
            treasury: 2,
            tips: 7,
            disapprovals: 2,
            spendable: 3,
            unspendable: 40,
            ..Tally::default()
        }
    );
}

/// Restarts that catch the cache up across a disapproving H_act, forward
/// and then back.
#[test]
fn a_restart_catches_up_across_the_activation_boundary() {
    assert_eq!(
        replay("restart"),
        Tally {
            processed: 74,
            side_chain: 2,
            states: 11,
            treasury: 2,
            tips: 7,
            disapprovals: 1,
            spendable: 9,
            unspendable: 8,
            entries: 7,
            flushes: 3,
            flush_disables: 1,
            journals_restored: 2,
            restarts: 2,
            ..Tally::default()
        }
    );
}

/// Templates on H_act-1 and beside a disapproving tip H_act, and the view
/// of their parent.
#[test]
fn templates_cross_the_activation_boundary() {
    assert_eq!(
        replay("templates"),
        Tally {
            processed: 70,
            states: 2,
            treasury: 2,
            tips: 3,
            disapprovals: 1,
            templates: 3,
            parent_templates: 2,
            view_entries: 99,
            ..Tally::default()
        }
    );
}

/// The block after a disapproving H_act disapproves it in turn, where
/// the parent's flag is active too, and is detached by a reorganization.
#[test]
fn a_block_past_the_activation_boundary_disapproves_its_parent() {
    assert_eq!(
        replay("beyond"),
        Tally {
            processed: 73,
            side_chain: 1,
            states: 5,
            treasury: 3,
            tips: 5,
            disapprovals: 2,
            spendable: 2,
            unspendable: 23,
            entries: 7,
            ..Tally::default()
        }
    );
}
