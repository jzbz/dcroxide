// SPDX-License-Identifier: ISC
//! Every durable state of a chain reopens to the right UTXO set.
//!
//! A UTXO cache flush that only its size limit tripped does not end in a
//! durable database flush, so an unclean stop during a catch-up usually
//! finds the utxo set state behind the best state, and the open replays
//! the blocks between them (dcrd `UtxoCache.Initialize`).  dcrd makes its
//! block database durable before every flush of its cache
//! (`flushBlockDB`, `utxocache.go:722`) because its UTXO set is a
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
//! The same is held with each of those flushes committed on a thread of
//! its own (`Options::background_commit`), as the daemon commits them.
//! The copy is then taken by that thread, when its commit has landed,
//! while the chain goes on: the commit that tripped the flush publishes
//! its rows, and the next transaction may be appending its block to the
//! block files, which the copy then holds a part of, as a crash at that
//! moment would leave them.  Each battery row waits for the commit under
//! way before its copies are opened.
//!
//! A third pair of sweeps gives the write cache its default room and
//! steps the clock the chain's periodic jobs are timed on by 30 s a
//! battery row, so the durable states are the commits the periodic UTXO
//! cache flush asks for (`Database::flush_in_background`), which the
//! daemon makes on the commit thread while the chain goes on, and the
//! flushes a disconnect forces.
//!
//! The tests sample the prefixes: every commit of a battery row that
//! disconnects a block, and every `stride`th of the rest.
//! `DCROXIDE_CRASH_SWEEP_EVERY=1` takes every prefix, which is a few
//! minutes in a debug build.
//!
//! The sweep copies the files of a store that is still open, which
//! Windows refuses: redb holds a byte-range lock on its file while the
//! database is open.  So it does not run there.

#![cfg(not(windows))]
// Test-harness arithmetic over small counts.
#![allow(clippy::arithmetic_side_effects)]

use std::cell::Cell;
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

/// How far the periodic sweeps step the chain's periodic clock a battery
/// row: four rows to the 120 s of the periodic UTXO cache flush.
const PERIODIC_STEP_SECS: i64 = 30;

thread_local! {
    /// The periodic clock a sweep steps, in nanoseconds.  The chain reads
    /// it on the thread that processes blocks, which is the test's.
    static PERIODIC_CLOCK: Cell<i64> = const { Cell::new(0) };
}

/// The clock [`PERIODIC_CLOCK`] holds, for `Chain::set_periodic_clock`.
fn periodic_clock() -> Option<i64> {
    Some(PERIODIC_CLOCK.with(Cell::get))
}

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
    /// Copies of a durable state that a flush no caller waited for made:
    /// one a commit tripped, or one `Database::flush_in_background` asked
    /// for, which is what the periodic sweeps' are.
    opened_unwaited: usize,
    /// Flushes observed that no caller waited for (`explicit` unset).
    unwaited: u64,
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
/// default size for `None`), and open the sampled durable states.  With
/// `background`, each flush a commit trips, or the chain asks for without
/// waiting, makes its redb commit on a thread of its own.  With
/// `periodic`, the database's write cache has its default room instead
/// of none, and the chain's periodic clock steps [`PERIODIC_STEP_SECS`] a
/// row.
fn sweep(cache: Option<u64>, sampling: Sampling, background: bool, periodic: bool) -> Tally {
    let params = regnet_params();
    let rows = battery();
    let dir = TempDir::new().expect("tempdir");
    let db_path = dir.path().join("chain");
    let copies = dir.path().join("copies");

    // The observer runs inside each durable flush, with the commits
    // before it on disk and the committing transaction's own rows not
    // yet published; or, for a commit on a thread of its own, once that
    // commit has landed, with whatever the chain has committed since
    // still in the write cache.
    let commits = Arc::new(AtomicU64::new(0));
    let disconnecting = Arc::new(AtomicBool::new(false));
    let pending: Arc<Mutex<Vec<(u64, PathBuf, bool)>>> = Arc::default();
    let background_flushes = Arc::new(AtomicU64::new(0));
    let unwaited = Arc::new(AtomicU64::new(0));
    let mut opts = Options::new(&db_path, params.net.0);
    if !periodic {
        opts.cache_max_size = 0;
    }
    opts.background_commit = background;
    opts.flush_observer = Some({
        let (commits, disconnecting, pending) = (
            Arc::clone(&commits),
            Arc::clone(&disconnecting),
            Arc::clone(&pending),
        );
        let (db_path, copies) = (db_path.clone(), copies.clone());
        let background_flushes = Arc::clone(&background_flushes);
        let unwaited = Arc::clone(&unwaited);
        Arc::new(move |obs: &FlushObservation| {
            if obs.background {
                background_flushes.fetch_add(1, Ordering::SeqCst);
            }
            if !obs.explicit {
                unwaited.fetch_add(1, Ordering::SeqCst);
            }
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
            pending
                .lock()
                .expect("pending")
                .push((n, copy, !obs.explicit));
        })
    });
    let db = Database::create(&opts).expect("create database");
    let settle = db.clone();
    let mut chain = open_chain(db, &params, cache).expect("open chain");
    if periodic {
        PERIODIC_CLOCK.with(|clock| clock.set(0));
        chain.set_periodic_clock(periodic_clock);
    }

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
        if periodic {
            let secs = (row as i64 + 1) * PERIODIC_STEP_SECS;
            PERIODIC_CLOCK.with(|clock| clock.set(secs * 1_000_000_000));
        }
        process(&mut chain, *now, block, &params, "the swept run");
        assert_eq!(chain.best_snapshot().hash, tip, "row {row}: the tips agree");
        // A commit still under way on its own thread has yet to take its
        // copy.
        settle
            .wait_background_commit()
            .unwrap_or_else(|e| panic!("row {row}: the commit under way failed: {e:?}"));

        let landed: Vec<(u64, PathBuf, bool)> =
            std::mem::take(&mut *pending.lock().expect("pending"));
        for (n, copy, not_waited_for) in landed {
            let at = format!("row {row}, durable commit {n}");
            tally.opened += 1;
            if not_waited_for {
                tally.opened_unwaited += 1;
            }

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
            let depth = set_state.map(|hash| reference.depth_below(hash, best));
            match depth {
                // A store with no set state yet is at genesis.
                None | Some(Some(0)) => tally.at_the_tip += 1,
                Some(Some(depth)) => {
                    tally.behind += 1;
                    tally.most_behind = tally.most_behind.max(depth);
                }
                Some(None) => tally.off_the_best_chain += 1,
            }
            // The periodic flush asks for its commit once its rows and
            // the set state are written, so what that commit makes
            // durable has the set state at the best state.
            if periodic && not_waited_for {
                assert!(
                    matches!(depth, None | Some(Some(0))),
                    "{at}: a periodic flush's commit left the set state at {set_state:?}, \
                     not at the best state {best}"
                );
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
    let on_their_own_thread = background_flushes.load(Ordering::SeqCst);
    let flushes = commits.load(Ordering::SeqCst);
    tally.unwaited = unwaited.load(Ordering::SeqCst);
    if periodic {
        // The flushes the periodic one asked for, and those a disconnect
        // forced, which commit on the thread that asked.
        let expected = if background { tally.unwaited } else { 0 };
        assert_eq!(
            on_their_own_thread, expected,
            "{on_their_own_thread} of {flushes} flushes committed on a thread of their own, {} \
             not waited for",
            tally.unwaited
        );
    } else if background {
        // All but the few the chain asks for outright, which commit on
        // the thread that asked.
        assert!(
            on_their_own_thread * 10 >= flushes * 9,
            "{on_their_own_thread} of {flushes} flushes committed on a thread of their own"
        );
    } else {
        assert_eq!(on_their_own_thread, 0);
    }
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
        false,
        false,
    );
    assert!(tally.at_the_tip > 0, "{tally:?}");
    assert!(tally.behind > 0, "{tally:?}");
    assert!(tally.off_the_best_chain > 0, "{tally:?}");
}

/// The same sweep with every flush a commit trips committed on a thread
/// of its own: each durable state is still a whole-transaction prefix of
/// the commit order, and all three kinds are still met.
#[test]
fn every_durable_state_reopens_to_the_right_set_with_commits_on_their_own_thread() {
    let tally = sweep(
        Some(1),
        Sampling {
            every: 29,
            in_a_disconnecting_row: 3,
            continued: 16,
        }
        .or_from_env(),
        true,
        false,
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
        false,
        false,
    );
    assert!(tally.behind > 0, "{tally:?}");
    assert!(
        tally.most_behind >= 50,
        "no open replayed a long run of blocks: {tally:?}"
    );
}

/// The large cache with commits on a thread of their own: the long
/// replays start from states those commits made durable.
#[test]
fn every_durable_state_reopens_to_the_right_set_with_a_large_cache_and_commits_on_their_own_thread()
{
    let tally = sweep(
        None,
        Sampling {
            every: 43,
            in_a_disconnecting_row: 43,
            continued: 7,
        }
        .or_from_env(),
        true,
        false,
    );
    assert!(tally.behind > 0, "{tally:?}");
    assert!(
        tally.most_behind >= 50,
        "no open replayed a long run of blocks: {tally:?}"
    );
}

/// The write cache with its default room, which the battery never fills,
/// and the periodic clock stepped 30 s a row: the durable states are the
/// periodic UTXO cache flush's, every 120 s of that clock unless a forced
/// flush came between, and those a disconnect forces.  They are few, so
/// every one is opened.  Every one the periodic flush made has the set
/// state at the best state it captured, and each reopens to the right
/// set.
#[test]
fn every_durable_state_reopens_to_the_right_set_with_periodic_flushes() {
    let tally = sweep(
        None,
        Sampling {
            every: 1,
            in_a_disconnecting_row: 1,
            continued: 9,
        }
        .or_from_env(),
        false,
        true,
    );
    assert!(tally.unwaited >= 20, "too few periodic flushes: {tally:?}");
    assert!(tally.opened_unwaited > 0, "{tally:?}");
    assert!(tally.at_the_tip > 0, "{tally:?}");
}

/// The periodic sweep with each periodic flush's commit made on a thread
/// of its own, as the daemon makes it: the copy is taken on that thread
/// when the commit lands, and each state still reopens to the right set.
#[test]
fn every_durable_state_reopens_to_the_right_set_with_periodic_flushes_on_their_own_thread() {
    let tally = sweep(
        None,
        Sampling {
            every: 1,
            in_a_disconnecting_row: 1,
            continued: 9,
        }
        .or_from_env(),
        true,
        true,
    );
    assert!(tally.unwaited >= 20, "too few periodic flushes: {tally:?}");
    assert!(tally.opened_unwaited > 0, "{tally:?}");
    assert!(tally.at_the_tip > 0, "{tally:?}");
}
