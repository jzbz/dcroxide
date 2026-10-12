// SPDX-License-Identifier: ISC
//! Every durable state of a chain reopens to the right UTXO set.
//!
//! A UTXO cache flush that only its size limit tripped does not end in a
//! durable database flush, so an unclean stop during a catch-up usually
//! finds the utxo set state behind the best state, and the open replays
//! the blocks between them (dcrd `UtxoCache.Initialize`).  dcrd makes its
//! block database durable before every flush of its cache
//! (`flushBlockDB`, `utxocache.go:713`) because its UTXO set is a
//! separate database that must never run ahead of the block index.  Here
//! both are rows of one store: a durable state holds whole transactions
//! in the order they committed, and a flush writes its rows and the set
//! state in one transaction.
//!
//! The sweep holds that to the commit boundaries of a whole run.  The
//! database's write cache is given no room, so each commit first makes
//! every commit before it durable, and the flush observer copies the
//! database directory as each of those durable states lands: one copy
//! for each whole-transaction prefix of the commit order.  The run is
//! dcrd's full-block battery, reorganizations included, under a clock
//! that never lets the chain latch to current.  Every copy is opened as
//! an unclean stop would leave it and must fold to the UTXO statistics,
//! serialized hash included, of an uninterrupted chain at the same tip.
//! Some then take the rest of the battery and must end at a correct set
//! too.
//!
//! Three kinds of durable state are met, and the sweep fails if it stops
//! meeting any of them: the set state at the best state, the set state
//! behind it (the replay), and the set state naming a block that is no
//! longer on the best chain, which an interrupted disconnect leaves
//! because the best state moves to the parent one transaction before the
//! flush does.
//!
//! The tests sample the prefixes: every commit of a battery row that
//! disconnects a block, and every `stride`th of the rest.
//! `DCROXIDE_CRASH_SWEEP_EVERY=1` takes every prefix, which is a few
//! minutes in a debug build.

// Test-harness arithmetic over small counts.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use dcroxide_blockchain::RuleErrorKind;
use dcroxide_blockchain::chaindb::{db_fetch_best_state, db_fetch_utxo_set_state};
use dcroxide_blockchain::notifications::Notification;
use dcroxide_blockchain::process::{Chain, OpenConfig, UtxoStats};
use dcroxide_chaincfg::{Params, regnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, FlushObservation, Options};
use dcroxide_testutil::unhex;
use dcroxide_wire::MsgBlock;
use tempfile::TempDir;

/// Two days: every block of the battery looks old under a clock this far
/// ahead, so the chain never latches to current and no connect forces a
/// durable flush.
const CLOCK_OFFSET: i64 = 48 * 60 * 60;

/// The battery's accepted blocks in order, each with the adjusted time it
/// is processed at.
fn battery() -> Vec<(i64, MsgBlock)> {
    let mut now: i64 = 0;
    let mut rows = Vec::new();
    for line in include_str!("data/fullblock_vectors.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "now" => now = f[1].parse::<i64>().expect("now") + CLOCK_OFFSET,
            "accept" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                rows.push((now, block));
            }
            _ => {}
        }
    }
    rows
}

fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).expect("create the copy's directory");
    for entry in std::fs::read_dir(src).expect("read the directory") {
        let entry = entry.expect("directory entry");
        let to = dst.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_dir(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), &to).expect("copy a file");
        }
    }
}

/// Open a chain over `db` with the UTXO cache limited to `cache` bytes,
/// or at its default size.
fn open_chain(
    db: Database,
    params: &Params,
    cache: Option<u64>,
) -> Result<Chain, dcroxide_blockchain::chaindb::ChainDbError> {
    let mut cfg = OpenConfig::new(Hash::ZERO, false, 0);
    if let Some(bytes) = cache {
        cfg.utxo_cache_max_bytes = bytes;
    }
    Chain::open_with_config(db, params, cfg)
}

/// Process one battery row on a chain nothing has interrupted: the
/// block is accepted, or is one of the battery's orphans.
fn process(chain: &mut Chain, now: i64, block: &MsgBlock, params: &Params, what: &str) {
    let (_, errs) = chain.process_block(block, now, params);
    let is_orphan = errs.len() == 1 && errs[0].kind == RuleErrorKind::MissingParent;
    assert!(errs.is_empty() || is_orphan, "{what}: {errs:?}");
}

/// Process one battery row on a chain reopened part way through the
/// battery.  It may hold the row's block already, and it may reject a
/// block the uninterrupted run accepted: a chain reopened inside a
/// reorganization stands on a lower tip, so a side-chain block the
/// uninterrupted run never had to connect, such as the battery's
/// double-spending `bf7`, can be the better chain here and fail as it
/// connects.  What must not happen is a storage failure, which the chain
/// returns as `ErrUnknownBlock` (`persist_rule_error`).
fn process_reopened(chain: &mut Chain, now: i64, block: &MsgBlock, params: &Params, what: &str) {
    let (_, errs) = chain.process_block(block, now, params);
    for err in &errs {
        assert_ne!(err.kind, RuleErrorKind::UnknownBlock, "{what}: {err:?}");
    }
}

/// The UTXO statistics of an uninterrupted chain at any tip the battery
/// can reach.
struct Reference<'a> {
    params: &'a Params,
    /// Every accepted block of the battery, by hash, with its clock.
    blocks: HashMap<Hash, (i64, MsgBlock)>,
    /// The statistics already known, by tip.
    stats: HashMap<Hash, UtxoStats>,
}

impl Reference<'_> {
    /// How many blocks `ancestor` is below `of`; `None` when it is not
    /// one of its ancestors.
    fn depth_below(&self, ancestor: Hash, mut of: Hash) -> Option<usize> {
        let mut steps = 0;
        loop {
            if of == ancestor {
                return Some(steps);
            }
            let (_, block) = self.blocks.get(&of)?;
            of = block.header.prev_block;
            steps += 1;
        }
    }

    /// The statistics at `tip`.  A tip no row of the battery ends at,
    /// which only an interrupted reorganization leaves, is built from
    /// genesis on a chain of its own.
    fn at(&mut self, tip: Hash) -> UtxoStats {
        if let Some(stats) = self.stats.get(&tip) {
            return stats.clone();
        }
        let mut path = Vec::new();
        let mut hash = tip;
        while hash != self.params.genesis_hash {
            let (now, block) = self.blocks.get(&hash).expect("a battery block");
            path.push((*now, block));
            hash = block.header.prev_block;
        }
        let dir = TempDir::new().expect("tempdir");
        let opts = Options::new(dir.path().join("chain"), self.params.net.0);
        let db = Database::create(&opts).expect("create database");
        let mut chain = open_chain(db, self.params, None).expect("open the reference");
        for (now, block) in path.into_iter().rev() {
            let (_, errs) = chain.process_block(block, now, self.params);
            assert!(errs.is_empty(), "the reference's path: {errs:?}");
        }
        assert_eq!(chain.best_snapshot().hash, tip, "the reference's tip");
        let stats = chain.fetch_utxo_stats().expect("reference stats");
        self.stats.insert(tip, stats.clone());
        stats
    }
}

/// Which durable states a sweep opened.
#[derive(Default, Debug)]
struct Tally {
    /// Copies opened.
    opened: usize,
    /// The set state named the best block.
    at_the_tip: usize,
    /// The set state named an ancestor of the best block.
    behind: usize,
    /// The most blocks one open had to replay.
    most_behind: usize,
    /// The set state named a block off the best chain.
    off_the_best_chain: usize,
    /// Copies that went on to take the rest of the battery.
    continued: usize,
}

/// Which prefixes a sweep opens: every `every`th durable commit, every
/// `in_a_disconnecting_row`th of a battery row that disconnects a block,
/// and of those opened every `continued`th goes on through the rest of
/// the battery.
#[derive(Clone, Copy)]
struct Sampling {
    every: u64,
    in_a_disconnecting_row: u64,
    continued: usize,
}

impl Sampling {
    /// The sampling a test asks for, or every prefix when
    /// `DCROXIDE_CRASH_SWEEP_EVERY` is set to 1 (any other stride it
    /// names replaces `every`).
    fn or_from_env(self) -> Sampling {
        match std::env::var("DCROXIDE_CRASH_SWEEP_EVERY") {
            Ok(v) => {
                let every = v.parse().expect("DCROXIDE_CRASH_SWEEP_EVERY is a count");
                assert!(every > 0, "DCROXIDE_CRASH_SWEEP_EVERY is at least 1");
                Sampling {
                    every,
                    in_a_disconnecting_row: self.in_a_disconnecting_row.min(every),
                    ..self
                }
            }
            Err(_) => self,
        }
    }
}

/// Run the battery on a chain whose UTXO cache holds `cache` bytes (the
/// default size for `None`), and open the sampled durable states.
fn sweep(cache: Option<u64>, sampling: Sampling) -> Tally {
    let params = regnet_params();
    let rows = battery();
    let dir = TempDir::new().expect("tempdir");
    let db_path = dir.path().join("chain");
    let copies = dir.path().join("copies");

    // The observer runs inside each durable flush, with the commits
    // before it on disk and the committing transaction's own rows not
    // yet published.
    let commits = Arc::new(AtomicU64::new(0));
    let disconnecting = Arc::new(AtomicBool::new(false));
    let pending: Arc<Mutex<Vec<(u64, PathBuf)>>> = Arc::default();
    let mut opts = Options::new(&db_path, params.net.0);
    opts.cache_max_size = 0;
    opts.flush_observer = Some({
        let (commits, disconnecting, pending) = (
            Arc::clone(&commits),
            Arc::clone(&disconnecting),
            Arc::clone(&pending),
        );
        let (db_path, copies) = (db_path.clone(), copies.clone());
        Arc::new(move |_: &FlushObservation| {
            let n = commits.fetch_add(1, Ordering::SeqCst) + 1;
            let stride = if disconnecting.load(Ordering::SeqCst) {
                sampling.in_a_disconnecting_row
            } else {
                sampling.every
            };
            if !n.is_multiple_of(stride) {
                return;
            }
            let copy = copies.join(n.to_string());
            copy_dir(&db_path, &copy);
            pending.lock().expect("pending").push((n, copy));
        })
    });
    let db = Database::create(&opts).expect("create database");
    let mut chain = open_chain(db, &params, cache).expect("open chain");

    // The same rows on a chain nothing interrupts, one row ahead: it
    // says which rows disconnect a block, and what the set is at each
    // tip a row ends at.
    let lockstep_dir = TempDir::new().expect("tempdir");
    let lockstep_opts = Options::new(lockstep_dir.path().join("chain"), params.net.0);
    let lockstep_db = Database::create(&lockstep_opts).expect("create database");
    let mut lockstep = open_chain(lockstep_db, &params, None).expect("open chain");
    let disconnected = Arc::new(AtomicBool::new(false));
    lockstep.set_notification_callback({
        let disconnected = Arc::clone(&disconnected);
        Box::new(move |ntfn| {
            if let Notification::BlockDisconnected(_) = ntfn {
                disconnected.store(true, Ordering::SeqCst);
            }
        })
    });
    let mut reference = Reference {
        params: &params,
        blocks: rows
            .iter()
            .map(|(now, block)| (block.header.block_hash(), (*now, block.clone())))
            .collect(),
        stats: HashMap::new(),
    };
    let genesis_stats = lockstep.fetch_utxo_stats().expect("genesis stats");
    reference.stats.insert(params.genesis_hash, genesis_stats);

    let mut tally = Tally::default();
    for (row, (now, block)) in rows.iter().enumerate() {
        disconnected.store(false, Ordering::SeqCst);
        process(&mut lockstep, *now, block, &params, "the uninterrupted run");
        let tip = lockstep.best_snapshot().hash;
        reference
            .stats
            .entry(tip)
            .or_insert_with(|| lockstep.fetch_utxo_stats().expect("uninterrupted stats"));

        disconnecting.store(disconnected.load(Ordering::SeqCst), Ordering::SeqCst);
        process(&mut chain, *now, block, &params, "the swept run");
        assert_eq!(chain.best_snapshot().hash, tip, "row {row}: the tips agree");

        let landed: Vec<(u64, PathBuf)> = std::mem::take(&mut *pending.lock().expect("pending"));
        for (n, copy) in landed {
            let at = format!("row {row}, durable commit {n}");
            tally.opened += 1;

            // What the durable state records, before anything repairs
            // it.
            let db = Database::open(&Options::new(&copy, params.net.0))
                .unwrap_or_else(|e| panic!("{at}: open the database: {e:?}"));
            let mut recorded = None;
            db.view(|tx| {
                let best = db_fetch_best_state(tx).expect("best state").hash;
                let set = db_fetch_utxo_set_state(tx).expect("utxo set state");
                recorded = Some((best, set.map(|state| state.last_flush_hash)));
                Ok(())
            })
            .unwrap_or_else(|e| panic!("{at}: read the states: {e:?}"));
            let (best, set_state) = recorded.expect("the states");
            match set_state.map(|hash| reference.depth_below(hash, best)) {
                // A store with no set state yet is at genesis.
                None | Some(Some(0)) => tally.at_the_tip += 1,
                Some(Some(depth)) => {
                    tally.behind += 1;
                    tally.most_behind = tally.most_behind.max(depth);
                }
                Some(None) => tally.off_the_best_chain += 1,
            }

            // The open an unclean stop is followed by.
            let mut reopened = open_chain(db, &params, cache)
                .unwrap_or_else(|e| panic!("{at}: open the chain: {e:?}"));
            assert_eq!(
                reopened.best_snapshot().hash,
                best,
                "{at}: the chain opened away from its durable best state"
            );
            let stats = reopened
                .fetch_utxo_stats()
                .unwrap_or_else(|e| panic!("{at}: stats: {e:?}"));
            assert_eq!(stats, reference.at(best), "{at}: the utxo set at {best}");

            // And the rest of the battery from the interrupted row.  A
            // restart does not resume a reorganization or remember which
            // of two equal branches it saw first, so the end may be
            // another tip than the uninterrupted run's; the set must be
            // the one a chain built from genesis has at the tip reached.
            if tally.opened.is_multiple_of(sampling.continued) {
                tally.continued += 1;
                for (now, block) in &rows[row..] {
                    process_reopened(&mut reopened, *now, block, &params, &at);
                }
                let end = reopened.best_snapshot().hash;
                let stats = reopened
                    .fetch_utxo_stats()
                    .unwrap_or_else(|e| panic!("{at}: stats after the battery: {e:?}"));
                assert_eq!(
                    stats,
                    reference.at(end),
                    "{at}: the utxo set at {end}, after the rest of the battery"
                );
            }
            drop(reopened);
            std::fs::remove_dir_all(&copy).expect("remove the copy");
        }
    }
    assert!(tally.opened > 0, "no durable state was opened");
    assert!(tally.continued > 0, "no reopened chain took more blocks");
    tally
}

/// The UTXO cache at its size limit after every connect, as late in an
/// initial sync: each connect is followed by a flush transaction that is
/// not durable, so the durable states between them have the set state a
/// block behind, and the ones inside a disconnect have it on the block
/// being disconnected.
#[test]
fn every_durable_state_reopens_to_the_right_set_with_the_cache_at_its_limit() {
    let tally = sweep(
        Some(1),
        Sampling {
            every: 29,
            in_a_disconnecting_row: 3,
            continued: 16,
        }
        .or_from_env(),
    );
    assert!(tally.at_the_tip > 0, "{tally:?}");
    assert!(tally.behind > 0, "{tally:?}");
    assert!(tally.off_the_best_chain > 0, "{tally:?}");
}

/// The default cache, which the battery never fills: only the flushes a
/// disconnect forces write the set, so the set state trails the best
/// state by as many blocks as the battery connects between two of them
/// and the open replays them all.
#[test]
fn every_durable_state_reopens_to_the_right_set_with_a_large_cache() {
    let tally = sweep(
        None,
        Sampling {
            every: 43,
            in_a_disconnecting_row: 43,
            continued: 7,
        }
        .or_from_env(),
    );
    assert!(tally.behind > 0, "{tally:?}");
    assert!(
        tally.most_behind >= 50,
        "no open replayed a long run of blocks: {tally:?}"
    );
}
