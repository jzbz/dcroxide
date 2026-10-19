// SPDX-License-Identifier: ISC
//! The two database hooks ADR-0011 adds: a flush participant, whose rows
//! ride inside the metadata flush's own redb transaction, and
//! `Transaction::on_commit`, whose closures run after a commit's own
//! flush and before its rows are published.
//!
//! The participant here is shaped like the exists-address index that
//! uses them.  Each "connect" commits a generation's chain rows and a tip
//! row in one transaction, and its `on_commit` hook hands the
//! generation's keys to the participant's memory.  A flush journals what
//! is in memory under the participant's prefix, with a meta row naming
//! the newest generation journaled.
//!
//! The property the power-cut tests hold the store to is the index's
//! invariant: **in every durable state, the participant's rows are
//! exactly the keys of the generations whose tip row is durable**.  None
//! is missing, which would be an index losing keys of blocks it claims to
//! have indexed.  None is extra, which would be an index answering for a
//! block it never recorded.  It holds only if three things are true at
//! once: the participant's rows land in the chain's commit, the hook runs
//! after the commit's own flush, and a failed commit runs no hook.  The
//! controls at the end break each in turn, and the checker has to catch
//! every one of them.
//!
//! **These tests were checked against a broken store**, each mutation made
//! in `dcroxide-database` itself rather than in the test double, and each
//! reverted after:
//!
//! - contributing in a second durable commit after the flush's own fails
//!   `power_cut_at_every_storage_operation_keeps_participant_and_chain_rows_together`
//!   at a cut between the two ("generation 1 is durable at tip Some(2) but
//!   the participant holds none of its rows"), and both failure tests;
//! - running the hooks after `commit_pending` fails
//!   `hooks_run_in_order_after_the_commits_own_flush_and_before_its_rows_are_visible`,
//!   whose hook then sees its own transaction's row.  Nothing else
//!   notices: a flush cannot run between the two under the writer
//!   semaphore, so the order shows only to a reader;
//! - running them before the commit's own flush fails seven tests, both
//!   power-cut sweeps among them;
//! - counting only flushes with overlay rows in `DbCache::retire` (then
//!   `finish_flush`) fails
//!   `the_flush_log_counts_a_flush_only_the_participant_wrote`;
//! - releasing the participant before the close's flush, which is what a
//!   `Weak` registration amounts to once its owner has dropped it, fails
//!   `close_runs_a_participant_whose_owner_has_dropped_it`.
//!
//! **The same sweeps run with the flush's rows and commit on a thread of
//! its own** (`Options::background_commit`, [`Mode::Background`]).  There
//! the participant allows its `contribute` and `finished` to be deferred:
//! it is sealed at the capture, under the writer, and contributes on the
//! thread the flush is handed to.  The hooks of the commit that tripped a
//! flush, and of up to two more connects, run while that flush is held:
//! one with its `contribute` held at its start, between the seal and the
//! `contribute`, and one with its commit held at its first write, between
//! the `contribute` and its `finished`, where no hook could run before.
//! The invariant is the same, and two more controls break it: a
//! participant that takes `finished(true)` to cover everything it holds,
//! rather than what it sealed, forgets the keys handed in meanwhile, and
//! one whose `contribute` writes everything it holds, rather than what it
//! sealed, writes keys of connects whose tip rows the flush does not
//! persist.

// Test-harness arithmetic over bounded counts.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use dcroxide_database::{
    COMMIT_THREAD_NAME, Database, Error, ErrorKind, FlushObservation, FlushParticipant,
    FlushWriter, Options, ParticipantStats, SharedBackend,
};
use dcroxide_testutil::SplitMix64;
use dcroxide_testutil::gate::GateBackend;
use dcroxide_testutil::powerloss::PowerLossBackend;
use tempfile::TempDir;

const NET: u32 = 0x12141c16; // simnet magic

/// The bucket a connect writes one row per generation into.
const CHAIN: &[u8] = b"chain";
/// The tip row, in the metadata bucket, written by every connect.
const TIP: &[u8] = b"tip";
/// The bucket whose id is the participant's prefix.  Nothing writes to
/// it through a transaction; the participant writes under its id.
const JOURNAL: &[u8] = b"journal";

// ---------------------------------------------------------------------
// The participant
// ---------------------------------------------------------------------

/// One call a participant received, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Call {
    Seal,
    Contribute,
    Finished(bool),
}

/// Which pending generations a [`Journal`] writes in a flush.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Placement {
    /// Every generation pending when the flush runs: the design under
    /// test.
    Current,
    /// All but the newest: a participant one flush behind the chain,
    /// which the checker must catch.
    Lagging,
    /// Every generation pending at the seal, as [`Self::Current`], but a
    /// committed flush is taken to have written everything pending by the
    /// time `finished` is called: right while nothing can be handed in
    /// between the two, and a loss of keys once a flush on its own thread
    /// lets hooks run there, which the checker must catch.
    Forgetful,
    /// Every generation pending when `contribute` runs, whatever the
    /// seal set apart: right while nothing can be handed in between the
    /// two, and rows of connects whose tip rows the flush does not
    /// persist once a `contribute` on its own thread lets hooks run
    /// before it, which the checker must catch.
    Unsealed,
}

/// Where the rows and the redb commit of a flush that a commit trips are
/// written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// On the thread that tripped it, under the writer semaphore.
    Inline,
    /// On a thread of its own (`Options::background_commit`), with the
    /// participant allowing its `contribute` and `finished` to be
    /// deferred.
    Background,
}

/// A point the thread a flush is handed to can be held at.  It holds that
/// thread and no other, so a flush that runs on the thread that asked for
/// it passes an armed hold untouched.
#[derive(Default)]
struct Hold {
    /// Whether to hold, and whether a thread is held now.
    state: Mutex<(bool, bool)>,
    changed: Condvar,
}

impl Hold {
    fn arm(&self) {
        self.state.lock().unwrap().0 = true;
    }

    fn release(&self) {
        self.state.lock().unwrap().0 = false;
        self.changed.notify_all();
    }

    fn is_held(&self) -> bool {
        self.state.lock().unwrap().1
    }

    /// Called by the thread to hold.
    fn pass(&self) {
        if std::thread::current().name() != Some(COMMIT_THREAD_NAME) {
            return;
        }
        let mut state = self.state.lock().unwrap();
        if !state.0 {
            return;
        }
        state.1 = true;
        self.changed.notify_all();
        while state.0 {
            state = self.changed.wait(state).unwrap();
        }
        state.1 = false;
    }
}

/// Wait for `done` to hold, for at most [`STUCK`]; whether it did.
fn wait_for(done: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + STUCK;
    while !done() {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    true
}

/// A participant shaped like the exists-address index.
struct Journal {
    prefix: Vec<u8>,
    placement: Placement,
    /// Generations handed in by hooks and not yet journaled durably.
    pending: Mutex<Vec<(u32, Vec<u32>)>>,
    /// How many of `pending` the flush in progress sealed, and writes.
    in_flight: Mutex<usize>,
    /// `wants_flush` once this many keys are pending; 0 for never.
    want_at: AtomicUsize,
    /// `has_work` even with nothing pending.
    always_work: AtomicBool,
    /// Fail `contribute` after writing its rows.
    fail: AtomicBool,
    /// Every generation a hook handed in.
    handed_in: Mutex<BTreeSet<u32>>,
    calls: Arc<Mutex<Vec<Call>>>,
    /// Run at the end of `contribute`, before it returns.
    during: Mutex<Option<Box<dyn Fn() + Send>>>,
    /// Holds `contribute` at its start on the committer thread while
    /// armed.
    hold: Hold,
    /// Whether `contribute` and `finished` may be called after the commit
    /// that tripped the flush has returned, with later hooks run beside
    /// and between them.
    deferred: bool,
}

impl Journal {
    fn new(prefix: &[u8], placement: Placement) -> Arc<Journal> {
        Journal::for_mode(prefix, placement, Mode::Inline)
    }

    fn for_mode(prefix: &[u8], placement: Placement, mode: Mode) -> Arc<Journal> {
        Arc::new(Journal {
            prefix: prefix.to_vec(),
            placement,
            pending: Mutex::new(Vec::new()),
            in_flight: Mutex::new(0),
            want_at: AtomicUsize::new(0),
            always_work: AtomicBool::new(false),
            fail: AtomicBool::new(false),
            handed_in: Mutex::new(BTreeSet::new()),
            calls: Arc::new(Mutex::new(Vec::new())),
            during: Mutex::new(None),
            hold: Hold::default(),
            deferred: mode == Mode::Background,
        })
    }

    /// What an `on_commit` hook does: hand a generation's keys in.
    fn hand_in(&self, generation: u32, keys: Vec<u32>) {
        self.handed_in.lock().unwrap().insert(generation);
        self.pending.lock().unwrap().push((generation, keys));
    }

    fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    fn pending_keys(&self) -> usize {
        self.pending
            .lock()
            .unwrap()
            .iter()
            .map(|(_, keys)| keys.len())
            .sum()
    }

    /// How many times `seal` has been called.
    fn seals(&self) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| **call == Call::Seal)
            .count()
    }

    /// The keys handed in that no flush has sealed: what is pending
    /// beyond the generations a flush in progress writes.  Outside a
    /// flush that is everything pending.
    fn unwritten_keys(&self) -> usize {
        let written = *self.in_flight.lock().unwrap();
        self.pending
            .lock()
            .unwrap()
            .iter()
            .skip(written)
            .map(|(_, keys)| keys.len())
            .sum()
    }
}

fn row_key(prefix: &[u8], generation: u32, key: u32) -> Vec<u8> {
    let mut k = prefix.to_vec();
    k.push(b'K');
    k.extend_from_slice(&generation.to_be_bytes());
    k.extend_from_slice(&key.to_be_bytes());
    k
}

fn meta_key(prefix: &[u8]) -> Vec<u8> {
    let mut k = prefix.to_vec();
    k.push(b'M');
    k
}

impl FlushParticipant for Journal {
    /// Only keys no flush has written count: with a flush's commit still
    /// under way, the ones it wrote are no reason for another.
    fn wants_flush(&self) -> bool {
        let at = self.want_at.load(Ordering::SeqCst);
        at > 0 && self.unwritten_keys() >= at
    }

    fn has_work(&self) -> bool {
        self.always_work.load(Ordering::SeqCst) || !self.pending.lock().unwrap().is_empty()
    }

    fn allows_deferred_contribute(&self) -> bool {
        self.deferred
    }

    fn seal(&self) {
        self.calls.lock().unwrap().push(Call::Seal);
        let pending = self.pending.lock().unwrap().len();
        *self.in_flight.lock().unwrap() = match self.placement {
            Placement::Current | Placement::Forgetful | Placement::Unsealed => pending,
            Placement::Lagging => pending.saturating_sub(1),
        };
    }

    fn contribute(&self, w: &mut FlushWriter<'_, '_>) -> Result<ParticipantStats, Error> {
        self.calls.lock().unwrap().push(Call::Contribute);
        self.hold.pass();
        let pending = self.pending.lock().unwrap();
        let n = match self.placement {
            Placement::Unsealed => {
                *self.in_flight.lock().unwrap() = pending.len();
                pending.len()
            }
            Placement::Current | Placement::Forgetful | Placement::Lagging => {
                *self.in_flight.lock().unwrap()
            }
        };
        let mut journaled = 0u64;
        let mut newest = None;
        for (generation, keys) in &pending[..n] {
            for key in keys {
                w.insert(
                    &row_key(&self.prefix, *generation, *key),
                    &generation.to_be_bytes(),
                )?;
                journaled += 1;
            }
            newest = Some(*generation);
        }
        if let Some(generation) = newest {
            w.insert(&meta_key(&self.prefix), &generation.to_be_bytes())?;
        }
        drop(pending);
        if let Some(during) = &*self.during.lock().unwrap() {
            during();
        }
        if self.fail.load(Ordering::SeqCst) {
            return Err(Error {
                kind: ErrorKind::DriverSpecific,
                description: "injected contribute failure".to_string(),
            });
        }
        let mut stats = ParticipantStats::default();
        stats.keys_journaled = journaled;
        // The database counts rows itself; this must be overwritten.
        stats.rows_put = 999_999;
        Ok(stats)
    }

    fn finished(&self, committed: bool) {
        self.calls.lock().unwrap().push(Call::Finished(committed));
        let n = std::mem::take(&mut *self.in_flight.lock().unwrap());
        if committed {
            let mut pending = self.pending.lock().unwrap();
            match self.placement {
                Placement::Forgetful => pending.clear(),
                Placement::Current | Placement::Lagging | Placement::Unsealed => {
                    drop(pending.drain(..n));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------
// The chain side
// ---------------------------------------------------------------------

/// Commit a generation's chain row and tip row in one transaction, and
/// hand its keys to the journal from an `on_commit` hook.
fn connect(
    db: &Database,
    journal: &Arc<Journal>,
    generation: u32,
    keys: &[u32],
) -> Result<(), Error> {
    let journal = Arc::clone(journal);
    let keys = keys.to_vec();
    db.update(move |tx| {
        let meta = tx.metadata();
        let chain = meta.create_bucket_if_not_exists(CHAIN)?;
        chain.put(
            &generation.to_be_bytes(),
            &(keys.len() as u32).to_be_bytes(),
        )?;
        meta.put(TIP, &generation.to_be_bytes())?;
        tx.on_commit(move || journal.hand_in(generation, keys))
    })
}

/// Create the chain and journal buckets and make them durable; returns
/// the journal bucket's id, the participant's prefix.
fn setup(db: &Database) -> Vec<u8> {
    let mut prefix = Vec::new();
    db.update(|tx| {
        let meta = tx.metadata();
        meta.create_bucket(CHAIN)?;
        prefix = meta.create_bucket(JOURNAL)?.raw_id().to_vec();
        Ok(())
    })
    .expect("create buckets");
    db.flush().expect("flush the buckets");
    prefix
}

fn power_loss_opts(dir: &Path, honest_sync: bool) -> (Options, Arc<PowerLossBackend>) {
    std::fs::create_dir_all(dir).expect("mkdir");
    let backend = PowerLossBackend::create(&dir.join("metadata.redb"), honest_sync);
    let mut opts = Options::new(dir, NET);
    opts.backend = Some(Arc::clone(&backend) as SharedBackend);
    (opts, backend)
}

/// [`power_loss_opts`] with a gate over the storage that holds the
/// committer thread while it is armed, and background commits on.
fn held_commit_opts(dir: &Path) -> (Options, Arc<PowerLossBackend>, Arc<GateBackend>) {
    std::fs::create_dir_all(dir).expect("mkdir");
    let backend = PowerLossBackend::create(&dir.join("metadata.redb"), true);
    let gate = GateBackend::new(Arc::clone(&backend) as SharedBackend);
    let mut opts = Options::new(dir, NET);
    opts.backend = Some(Arc::clone(&gate) as SharedBackend);
    opts.background_commit = true;
    (opts, backend, gate)
}

/// Reopen a store and hold it to the invariant: the participant's rows
/// are exactly the keys of the generations whose tip row survived, the
/// meta row names the newest of them, and the chain's own rows agree
/// with the tip.  `committed` is every generation whose commit returned
/// `Ok`; generations commit in order and a run stops at its first
/// failure, so the durable ones are those at or below the tip.
///
/// Returns the surviving tip, or what is wrong.
fn check_store(
    db_dir: &Path,
    prefix: &[u8],
    committed: &BTreeMap<u32, Vec<u32>>,
) -> Result<Option<u32>, String> {
    let db = Database::open(&Options::new(db_dir, NET)).map_err(|e| format!("reopen: {e}"))?;
    let mut verdict = Ok(None);
    db.view(|tx| {
        let meta = tx.metadata();
        let tip = meta
            .get(TIP)
            .map(|v| u32::from_be_bytes(v.as_slice().try_into().expect("tip")));
        let durable: BTreeSet<u32> = committed
            .keys()
            .copied()
            .filter(|g| tip.is_some_and(|t| *g <= t))
            .collect();

        let mut chain_rows = BTreeSet::new();
        if let Some(chain) = meta.bucket(CHAIN) {
            chain.for_each(|k, _| {
                chain_rows.insert(u32::from_be_bytes(k.try_into().expect("generation")));
                Ok(())
            })?;
        }

        let mut journaled: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
        let mut meta_row = None;
        let mut strays = Vec::new();
        for (key, value) in tx.try_scan_after(prefix, None, usize::MAX)? {
            let rest = &key[prefix.len()..];
            match rest.first() {
                Some(b'K') if rest.len() == 9 => {
                    let g = u32::from_be_bytes(rest[1..5].try_into().expect("generation"));
                    let k = u32::from_be_bytes(rest[5..9].try_into().expect("key"));
                    journaled.entry(g).or_default().insert(k);
                }
                Some(b'M') if rest.len() == 1 => {
                    meta_row = Some(u32::from_be_bytes(
                        value.as_slice().try_into().expect("meta"),
                    ));
                }
                _ => strays.push(key),
            }
        }

        verdict = (|| {
            if chain_rows != durable {
                return Err(format!(
                    "the chain rows {chain_rows:?} disagree with the tip {tip:?}, which names {durable:?}"
                ));
            }
            let journaled_gens: BTreeSet<u32> = journaled.keys().copied().collect();
            if let Some(extra) = journaled_gens.difference(&durable).next() {
                return Err(format!(
                    "the participant holds rows of generation {extra}, past the durable tip {tip:?}: \
                     an index answering for a block it never recorded"
                ));
            }
            if let Some(missing) = durable.difference(&journaled_gens).next() {
                return Err(format!(
                    "generation {missing} is durable at tip {tip:?} but the participant holds none \
                     of its rows: an index that lost keys of a block it claims"
                ));
            }
            for (g, keys) in &journaled {
                let want: BTreeSet<u32> = committed[g].iter().copied().collect();
                if *keys != want {
                    return Err(format!(
                        "generation {g}: the participant holds {keys:?}, the connect handed in {want:?}"
                    ));
                }
            }
            if meta_row != durable.last().copied() {
                return Err(format!(
                    "the meta row names {meta_row:?}, the newest durable generation is {:?}",
                    durable.last()
                ));
            }
            if !strays.is_empty() {
                return Err(format!("rows under the prefix nobody wrote: {strays:02x?}"));
            }
            Ok(tip)
        })();
        Ok(())
    })
    .map_err(|e| format!("read the reopened store: {e}"))?;
    db.close()
        .map_err(|e| format!("close the reopened store: {e}"))?;
    verdict
}

// ---------------------------------------------------------------------
// Scripted runs under power loss
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Step {
    Connect(u32, Vec<u32>),
    Flush,
}

/// A scripted run: connects, explicit flushes, and the two thresholds
/// that make commits flush on their own.
#[derive(Debug, Clone)]
struct Script {
    steps: Vec<Step>,
    /// The overlay's size ceiling, small enough that commits trip it.
    cache_max_size: u64,
    /// The journal's `wants_flush` threshold, in pending keys.
    want_at: usize,
}

impl Script {
    fn random(rng: &mut SplitMix64, connects: u32) -> Script {
        let mut steps = Vec::new();
        for generation in 1..=connects {
            let n = rng.below(6) + 1;
            let keys = (0..n)
                .map(|_| rng.next_u64() as u32)
                .collect::<BTreeSet<_>>();
            steps.push(Step::Connect(generation, keys.into_iter().collect()));
            if rng.below(4) == 0 {
                steps.push(Step::Flush);
            }
        }
        steps.push(Step::Flush);
        Script {
            steps,
            cache_max_size: 1500 + rng.below(3000),
            want_at: 8 + rng.below(16) as usize,
        }
    }
}

/// What one run of a script did, and what survived it.
struct Run {
    survived: Result<Option<u32>, String>,
    /// Storage operations the run made after setup.
    ops: u64,
    power_failed: bool,
    latched: bool,
    calls: Vec<Call>,
    handed_in: BTreeSet<u32>,
    committed: BTreeMap<u32, Vec<u32>>,
    /// Connects made while a flush was held on its own thread, before its
    /// `contribute` or after it.
    beside: usize,
    /// Of those, the ones made before its `contribute`.
    before_contribute: usize,
}

impl Run {
    /// The protocol the database promises the participant, whatever the
    /// cut did: each flush it has work in calls `seal`, then at most one
    /// `contribute`, then `finished` exactly once; `contribute` is left
    /// out only by a flush that failed before it, `finished(false)` comes
    /// only as the last call and only on a latched store, and there is a
    /// hook for every commit that returned `Ok` and for no other.
    fn assert_protocol(&self, context: &str) {
        let mut calls = self.calls.iter().peekable();
        while let Some(call) = calls.next() {
            assert_eq!(
                *call,
                Call::Seal,
                "{context}: each flush's calls begin with a seal: {:?}",
                self.calls
            );
            let contributed = calls.next_if_eq(&&Call::Contribute).is_some();
            match calls.next() {
                Some(Call::Finished(true)) => assert!(
                    contributed,
                    "{context}: finished(true) for a flush that never contributed: {:?}",
                    self.calls
                ),
                Some(Call::Finished(false)) => assert!(
                    calls.peek().is_none() && self.latched,
                    "{context}: finished(false) must end the calls on a latched store: {:?}",
                    self.calls
                ),
                _ => panic!(
                    "{context}: a seal must be followed by at most one contribute and one \
                     finished: {:?}",
                    self.calls
                ),
            }
        }
        let committed: BTreeSet<u32> = self.committed.keys().copied().collect();
        assert_eq!(
            self.handed_in, committed,
            "{context}: hooks ran for {:?}, commits succeeded for {committed:?}",
            self.handed_in
        );
        if self.power_failed {
            assert!(
                self.latched,
                "{context}: a refused write must latch the store"
            );
        }
    }
}

/// Run `script` over a power-loss backend, with the power failing after
/// `cut_after` storage operations when given, then cut the power and
/// check what survived.
fn run(script: &Script, placement: Placement, cut_after: Option<u64>) -> Run {
    run_in(Mode::Inline, script, placement, cut_after)
}

/// How long a step that cannot block is given before the run is called
/// stuck.
const STUCK: Duration = Duration::from_secs(60);

/// [`run`] in either mode.
///
/// In [`Mode::Background`] every connect is made with the gate shut and
/// the participant's `contribute` held.  A connect whose flush the
/// participant has work in leaves that flush on the committer thread,
/// with its own hook already run after the seal: held at the start of
/// its `contribute`, or at the gate, should writing the overlay's rows
/// reach storage first.  One of the connects that follow it in the script
/// is made there, so its hook comes between the seal and the
/// `contribute`.  Then the `contribute` is let go, and when it was what
/// held the flush, the flush runs on to its commit's first write, held
/// at the gate, where one more connect is made for an odd generation, so
/// its hook comes between the `contribute` and its `finished`.  A connect
/// that would trip a flush of its own has to wait for the held one first,
/// so one that finds the participant asking for a flush is left for
/// after the gate opens.  So is any when the flush was stopped growing
/// the file, where redb lets no transaction begin
/// (`GateBackend::holds_a_length_change`).  Then the gate opens and the
/// flush is waited for, before the next step.  A flush under way makes
/// no storage operation while it is held, and has made all of its own
/// before the step after it begins, so the operations come in one order
/// however the threads are scheduled, and a cut after the `n`th lands in
/// the same place every time.
fn run_in(mode: Mode, script: &Script, placement: Placement, cut_after: Option<u64>) -> Run {
    let dir = TempDir::new().expect("tempdir");
    let db_dir = dir.path().join("db");
    let (mut opts, backend, gate) = match mode {
        Mode::Inline => {
            let (opts, backend) = power_loss_opts(&db_dir, true);
            (opts, backend, None)
        }
        Mode::Background => {
            let (opts, backend, gate) = held_commit_opts(&db_dir);
            (opts, backend, Some(gate))
        }
    };
    opts.cache_max_size = script.cache_max_size;
    let db = Database::create(&opts).expect("create");
    let prefix = setup(&db);
    let journal = Journal::for_mode(&prefix, placement, mode);
    journal.want_at.store(script.want_at, Ordering::SeqCst);
    db.set_flush_participant(&prefix, Arc::clone(&journal) as Arc<dyn FlushParticipant>)
        .expect("register the participant");

    let start = backend.ops();
    if let Some(n) = cut_after {
        backend.power_fails_after(n);
    }
    let mut committed = BTreeMap::new();
    let (mut beside, mut before_contribute) = (0usize, 0usize);
    let mut steps = script.steps.iter().peekable();
    'steps: while let Some(step) = steps.next() {
        match step {
            Step::Flush => {
                if db.flush().is_err() {
                    break;
                }
            }
            Step::Connect(generation, keys) => {
                if let Some(gate) = &gate {
                    gate.arm();
                    journal.hold.arm();
                }
                let seals = journal.seals();
                if connect(&db, &journal, *generation, keys).is_err() {
                    break;
                }
                committed.insert(*generation, keys.clone());
                let Some(gate) = &gate else {
                    continue;
                };
                // A seal during the connect means a flush the participant
                // has work in was handed over: it is on its way to the
                // participant's `contribute`, or to the gate, should
                // writing the overlay's rows reach storage first.
                let mut refused = false;
                if journal.seals() > seals {
                    assert!(
                        wait_for(|| journal.hold.is_held() || gate.is_held()),
                        "generation {generation}: the handed-over flush reached neither its \
                         contribute nor storage"
                    );
                    let at_contribute = !gate.is_held();
                    // A flush stopped while redb grows the file lets no
                    // transaction begin: nothing is connected beside that
                    // one.
                    let before = u32::from(!gate.holds_a_length_change());
                    let made = beside;
                    refused = connect_beside(
                        &db,
                        &journal,
                        &mut steps,
                        before,
                        &mut committed,
                        &mut beside,
                    );
                    before_contribute += beside - made;
                    journal.hold.release();
                    if at_contribute && !refused {
                        assert!(
                            gate.wait_held(STUCK),
                            "generation {generation}: the handed-over commit never reached \
                             storage"
                        );
                        let after = if gate.holds_a_length_change() {
                            0
                        } else {
                            generation % 2
                        };
                        refused = connect_beside(
                            &db,
                            &journal,
                            &mut steps,
                            after,
                            &mut committed,
                            &mut beside,
                        );
                    }
                }
                journal.hold.release();
                gate.open();
                // The flush under way ends before the next step: its
                // failure, if the power went under it, is the next
                // step's refusal.
                let _ = db.wait_background_commit();
                if refused {
                    break 'steps;
                }
            }
        }
    }
    let ops = backend.ops() - start;
    let latched = db.is_fatal();
    // Read before the drop: redb's own drop writes, and a cut placed at
    // the run's last operation refuses those rather than the run's.
    let power_failed = backend.power_failed();
    drop(db);
    backend.cut_power();

    let survived = check_store(&db_dir, &prefix, &committed);
    let handed_in = journal.handed_in.lock().unwrap().clone();
    Run {
        survived,
        ops,
        power_failed,
        latched,
        calls: journal.calls(),
        handed_in,
        committed,
        beside,
        before_contribute,
    }
}

/// Make up to `count` of the connects that come next in `steps`, each
/// while a flush is held on its own thread, stopping before one that
/// would trip a flush of its own; whether one was refused.
fn connect_beside(
    db: &Database,
    journal: &Arc<Journal>,
    steps: &mut std::iter::Peekable<std::slice::Iter<'_, Step>>,
    count: u32,
    committed: &mut BTreeMap<u32, Vec<u32>>,
    beside: &mut usize,
) -> bool {
    for _ in 0..count {
        if journal.wants_flush() {
            break;
        }
        let Some(Step::Connect(generation, keys)) =
            steps.next_if(|next| matches!(next, Step::Connect(..)))
        else {
            break;
        };
        match connect_while_held(db, journal, *generation, keys) {
            Ok(()) => {
                committed.insert(*generation, keys.clone());
                *beside += 1;
            }
            Err(_) => return true,
        }
    }
    false
}

/// [`connect`] while a flush is held on its own thread.  A connect that
/// had to wait for that flush, at a flush of its own or at the overlay's
/// ceiling, would wait for ever, so it is made on a thread and a run in
/// which it does not return is failed: its script let too much be
/// committed above the captured layers ([`background_script`]).
fn connect_while_held(
    db: &Database,
    journal: &Arc<Journal>,
    generation: u32,
    keys: &[u32],
) -> Result<(), Error> {
    let (done, result) = mpsc::channel();
    let (db, journal, keys) = (db.clone(), Arc::clone(journal), keys.to_vec());
    std::thread::spawn(move || {
        let outcome = connect(&db, &journal, generation, &keys);
        drop(db);
        let _ = done.send(outcome);
    });
    result.recv_timeout(STUCK).unwrap_or_else(|_| {
        panic!("generation {generation}: a connect made beside a held commit waited for it")
    })
}

/// Cut the power at every storage operation a scripted run makes, and
/// after it, and require every surviving store to hold the participant's
/// rows and the chain's together.
///
/// The backend discards whatever was not synced when the power goes, so a
/// cut inside a flush's commit lands on the previous flush, and one after
/// its sync keeps it.  A participant that wrote in a commit of its own
/// would fail at every cut between the two syncs.
#[test]
fn power_cut_at_every_storage_operation_keeps_participant_and_chain_rows_together() {
    let mut rng = SplitMix64::from_entropy("participant-power-cut-sweep");
    let script = Script::random(&mut rng, 20);

    let whole = run(&script, Placement::Current, None);
    let tip = whole
        .survived
        .clone()
        .unwrap_or_else(|e| panic!("the uncut run: {e}"));
    whole.assert_protocol("the uncut run");
    assert_eq!(
        tip,
        Some(20),
        "the script ends in a flush, so the whole run is durable"
    );
    assert!(
        whole.calls.len() >= 6,
        "the script must make the participant contribute to several flushes: {:?}",
        whole.calls
    );
    assert_eq!(whole.beside, 0, "no commit leaves the committing thread");

    let total = whole.ops;
    let mut felt = 0u64;
    let mut tips = BTreeSet::new();
    for n in 0..=total {
        let cut = run(&script, Placement::Current, Some(n));
        let context = format!("power cut after {n} of {total} storage operations");
        let tip = cut
            .survived
            .clone()
            .unwrap_or_else(|e| panic!("{context}: {e}"));
        cut.assert_protocol(&context);
        felt += u64::from(cut.power_failed);
        tips.insert(tip);
    }
    assert!(
        felt >= total,
        "every cut short of the end must be felt: {felt} of {total}"
    );
    assert!(
        tips.len() >= 3,
        "the cuts must land on several different durable states, got {tips:?}"
    );
}

/// The same invariant over many scripts, each cut once at its end: the
/// store keeps the last flush and loses the window after it.
#[test]
fn power_cut_after_random_runs_keeps_participant_and_chain_rows_together() {
    let mut rng = SplitMix64::from_entropy("participant-power-cut-scripts");
    for round in 0..12 {
        let connects = 6 + rng.below(20) as u32;
        let mut script = Script::random(&mut rng, connects);
        // Lose a window: drop the final flush and add connects after it.
        script.steps.pop();
        let next = script.steps.len() as u32 + 100;
        for g in next..next + rng.below(4) as u32 {
            script.steps.push(Step::Connect(g, vec![g]));
        }
        let r = run(&script, Placement::Current, None);
        let context = format!("round {round}");
        r.assert_protocol(&context);
        r.survived.unwrap_or_else(|e| panic!("{context}: {e}"));
    }
}

/// A script for [`Mode::Background`]: [`Script::random`] with an overlay
/// ceiling roomy enough that the three small commits made above a held
/// flush's layers -- the connect that tripped it and two more -- stay
/// under it, so none of them waits for the commit they are there to
/// overlap.
///
/// The participant asks for a flush at four to seven pending keys, so
/// most flushes are tripped by a commit, and the keys handed in behind
/// one, at most six a connect, often leave room for another connect
/// before it asks again.
fn background_script(rng: &mut SplitMix64, connects: u32) -> Script {
    let mut script = Script::random(rng, connects);
    script.cache_max_size = 3000 + rng.below(3000);
    script.want_at = 4 + rng.below(4) as usize;
    script
}

/// The sweep above with every flush a commit trips committed on a thread
/// of its own, and connects made while that commit is held: the power
/// goes at every storage operation, and every surviving store holds the
/// participant's rows and the chain's together.
///
/// A flush captures the tip rows published before it and the keys of
/// exactly those connects.  The keys of the connect that tripped it, and
/// of the connects made while its commit was held, are handed in after
/// the participant's `contribute` and before its `finished`; they belong
/// to the next flush, whose commit lands after this one's.
#[test]
fn power_cut_at_every_storage_operation_with_commits_on_their_own_thread() {
    // A fixed script: how many connects land beside a held commit depends
    // on it, and the sweep is only worth its name if several do.
    let mut rng = SplitMix64(0x6261_636b_6772_6f75);
    let script = background_script(&mut rng, 20);

    let whole = run_in(Mode::Background, &script, Placement::Current, None);
    let tip = whole
        .survived
        .clone()
        .unwrap_or_else(|e| panic!("the uncut run: {e}"));
    whole.assert_protocol("the uncut run");
    assert_eq!(
        tip,
        Some(20),
        "the script ends in a flush, so the whole run is durable"
    );
    assert!(
        whole.calls.len() >= 6,
        "the script must make the participant contribute to several flushes: {:?}",
        whole.calls
    );
    assert!(
        whole.beside >= 2 && whole.before_contribute >= 1 && whole.before_contribute < whole.beside,
        "{} connects were made while a flush was held, {} of them before its contribute",
        whole.beside,
        whole.before_contribute
    );

    let total = whole.ops;
    let mut felt = 0u64;
    let mut tips = BTreeSet::new();
    for n in 0..=total {
        let cut = run_in(Mode::Background, &script, Placement::Current, Some(n));
        let context = format!("power cut after {n} of {total} storage operations");
        let tip = cut
            .survived
            .clone()
            .unwrap_or_else(|e| panic!("{context}: {e}"));
        cut.assert_protocol(&context);
        felt += u64::from(cut.power_failed);
        tips.insert(tip);
    }
    assert!(
        felt >= total,
        "every cut short of the end must be felt: {felt} of {total}"
    );
    assert!(
        tips.len() >= 3,
        "the cuts must land on several different durable states, got {tips:?}"
    );
}

/// Many scripts with commits on a thread of their own, each cut once at
/// its end, after a window of connects no flush was asked for.
#[test]
fn power_cut_after_random_runs_with_commits_on_their_own_thread() {
    let mut rng = SplitMix64::from_entropy("participant-power-cut-scripts-background");
    for round in 0..12 {
        let connects = 6 + rng.below(20) as u32;
        let mut script = background_script(&mut rng, connects);
        script.steps.pop();
        let next = script.steps.len() as u32 + 100;
        for g in next..next + rng.below(4) as u32 {
            script.steps.push(Step::Connect(g, vec![g]));
        }
        let r = run_in(Mode::Background, &script, Placement::Current, None);
        let context = format!("round {round}");
        r.assert_protocol(&context);
        r.survived.unwrap_or_else(|e| panic!("{context}: {e}"));
    }
}

// ---------------------------------------------------------------------
// Controls: each breaks one of the three conditions, and the checker
// has to notice.  If one of these starts passing, the tests above have
// stopped testing the property.
// ---------------------------------------------------------------------

/// A participant one flush behind the chain leaves a durable tip whose
/// keys are not durable.
#[test]
fn the_checker_catches_a_participant_one_flush_behind() {
    let mut rng = SplitMix64::from_entropy("participant-control-lagging");
    let script = Script::random(&mut rng, 8);
    let r = run(&script, Placement::Lagging, None);
    let err = r
        .survived
        .expect_err("a lagging participant must be caught");
    assert!(err.contains("holds none of its rows"), "{err}");
}

/// The same participant with commits on a thread of their own is caught
/// the same way.
#[test]
fn the_checker_catches_a_lagging_participant_with_commits_on_their_own_thread() {
    let mut rng = SplitMix64::from_entropy("participant-control-lagging-background");
    let script = background_script(&mut rng, 8);
    let r = run_in(Mode::Background, &script, Placement::Lagging, None);
    let err = r
        .survived
        .expect_err("a lagging participant must be caught");
    assert!(err.contains("holds none of its rows"), "{err}");
}

/// A participant that takes a committed flush to have written everything
/// it holds is right while its `finished` is called under the writer
/// semaphore, before any hook can run: nothing is handed in between a
/// `contribute` and its `finished`.  With the commit on a thread of its
/// own the hook of the very commit that tripped the flush runs there,
/// and its keys are forgotten: a later flush makes that generation's tip
/// durable with none of its keys.  This is what a participant must not
/// do once it allows its `finished` to be deferred, and what the
/// exists-address index's seal is for.
#[test]
fn the_checker_catches_a_participant_that_forgets_keys_handed_in_during_a_commit() {
    // Three keys a connect and a flush wanted at six: every third
    // connect trips a flush of the two before it, and hands its own keys
    // in while that flush's commit is held.
    let script = Script {
        steps: (1..=12u32)
            .map(|g| Step::Connect(g, vec![g * 10, g * 10 + 1, g * 10 + 2]))
            .chain([Step::Flush])
            .collect(),
        cache_max_size: 6000,
        want_at: 6,
    };

    let inline = run_in(Mode::Inline, &script, Placement::Forgetful, None);
    inline.assert_protocol("the same participant with the commit on the committing thread");
    assert_eq!(
        inline.survived,
        Ok(Some(12)),
        "under the writer semaphore nothing is handed in before `finished`"
    );

    let r = run_in(Mode::Background, &script, Placement::Forgetful, None);
    let err = r
        .survived
        .expect_err("keys handed in during a commit and then forgotten must be caught");
    assert!(
        err.contains("generation 3 is durable") && err.contains("holds none of its rows"),
        "{err}"
    );

    // The participant that keeps them apart loses nothing over the same
    // script.
    let kept = run_in(Mode::Background, &script, Placement::Current, None);
    kept.assert_protocol("the same script with what was handed in kept apart");
    assert_eq!(kept.survived, Ok(Some(12)));
    assert!(
        kept.calls.len() >= 8 && kept.beside >= 2 && kept.before_contribute >= 1,
        "the script made too few flushes to show anything: {:?}, {} connects beside a held \
         flush, {} of them before its contribute",
        kept.calls,
        kept.beside,
        kept.before_contribute
    );
}

/// What [`held_contribute_run`] left: what survived the power cut, the
/// participant's calls, and every generation whose commit returned `Ok`.
struct HeldContribute {
    survived: Result<Option<u32>, String>,
    calls: Vec<Call>,
    pending_after: Vec<u32>,
}

/// Generations 1 and 2 are connected, then 3, whose own check trips a
/// flush the participant asks for, which is handed over and held at the
/// start of its `contribute`.  Generations 4 and 5 are connected beside
/// it, so their hooks, like 3's, run between the seal and the
/// `contribute`.  The flush is let go and lands; then, with `flush_again`,
/// one more flush is asked for, and the power is cut.
fn held_contribute_run(placement: Placement, flush_again: bool) -> HeldContribute {
    let dir = TempDir::new().expect("tempdir");
    let db_dir = dir.path().join("db");
    let (opts, backend, _gate) = held_commit_opts(&db_dir);
    let db = Database::create(&opts).expect("create");
    let prefix = setup(&db);
    let journal = Journal::for_mode(&prefix, placement, Mode::Background);
    journal.want_at.store(4, Ordering::SeqCst);
    db.set_flush_participant(&prefix, Arc::clone(&journal) as Arc<dyn FlushParticipant>)
        .expect("register");
    let mut committed = BTreeMap::new();
    let mut connect_one = |generation: u32| {
        let keys = vec![generation * 10, generation * 10 + 1];
        connect_while_held(&db, &journal, generation, &keys).expect("connect");
        committed.insert(generation, keys);
    };
    connect_one(1);
    connect_one(2);
    journal.hold.arm();
    // Four keys pending: generation 3's own check trips a flush of 1 and
    // 2, and 3's hook runs once that flush is sealed.
    connect_one(3);
    assert!(
        wait_for(|| journal.hold.is_held()),
        "the flush's contribute runs on the thread it was handed to"
    );
    assert_eq!(journal.calls(), vec![Call::Seal, Call::Contribute]);
    // No further flush is asked for while this one is held.
    journal.want_at.store(0, Ordering::SeqCst);
    connect_one(4);
    connect_one(5);
    journal.hold.release();
    db.wait_background_commit().expect("the flush landed");
    if flush_again {
        db.flush().expect("the next flush");
    }
    let pending_after = journal
        .pending
        .lock()
        .unwrap()
        .iter()
        .map(|(generation, _)| *generation)
        .collect();
    let calls = journal.calls();
    drop(db);
    backend.cut_power();
    HeldContribute {
        survived: check_store(&db_dir, &prefix, &committed),
        calls,
        pending_after,
    }
}

/// Keys handed in between a flush's seal and its `contribute`, which runs
/// on the thread the flush is handed to, belong to the next flush: the
/// flush writes only the generations it sealed, whose tip rows it
/// persists, so a cut after it lands finds generation 2 durable with
/// exactly its keys; the next flush writes the rest.
#[test]
fn keys_handed_in_between_the_seal_and_the_contribute_wait_for_the_next_flush() {
    let first = held_contribute_run(Placement::Current, false);
    assert_eq!(
        first.calls,
        vec![Call::Seal, Call::Contribute, Call::Finished(true)]
    );
    assert_eq!(
        first.pending_after,
        vec![3, 4, 5],
        "the generations handed in after the seal wait for the next flush"
    );
    assert_eq!(
        first.survived,
        Ok(Some(2)),
        "the flush persists generations 1 and 2, tip rows and keys together"
    );

    let second = held_contribute_run(Placement::Current, true);
    assert!(
        second.pending_after.is_empty(),
        "{:?}",
        second.pending_after
    );
    assert_eq!(
        second.survived,
        Ok(Some(5)),
        "the next flush writes the rest"
    );
}

/// A participant whose `contribute` writes everything it holds, rather
/// than what it sealed, is right while nothing can be handed in between
/// the two: on the thread that tripped the flush, under the writer, its
/// rows are the sealed ones.  Once its `contribute` runs on a thread of
/// its own, beside later hooks, it writes keys of connects whose tip
/// rows its flush does not persist, and a cut after that flush lands
/// keeps an index answering for blocks it never recorded.  The next
/// flush hides the fault, which is why the cut must come between.
#[test]
fn the_checker_catches_a_participant_that_writes_what_was_handed_in_after_its_seal() {
    let mut rng = SplitMix64::from_entropy("participant-control-unsealed");
    let script = Script::random(&mut rng, 10);
    let full = run(&script, Placement::Unsealed, None);
    full.assert_protocol("the uncut inline run");
    full.survived
        .clone()
        .unwrap_or_else(|e| panic!("the uncut inline run: {e}"));
    for n in (0..=full.ops).step_by(5) {
        let cut = run(&script, Placement::Unsealed, Some(n));
        let context = format!("inline, power cut after {n} of {} operations", full.ops);
        cut.assert_protocol(&context);
        cut.survived
            .unwrap_or_else(|e| panic!("{context}: harmless inline, yet {e}"));
    }

    let caught = held_contribute_run(Placement::Unsealed, false);
    let err = caught
        .survived
        .expect_err("rows written past the durable tip must be caught");
    assert!(err.contains("past the durable tip"), "{err}");
    let hidden = held_contribute_run(Placement::Unsealed, true);
    assert_eq!(hidden.survived, Ok(Some(5)));
}

/// Keys handed in before the commit instead of from its hook: the
/// commit's own flush journals them while their tip row is still waiting
/// to be published, and a power cut then keeps rows for a block the
/// index never recorded.  This is the placement ADR-0011 rejects.
#[test]
fn the_checker_catches_keys_handed_in_before_the_commit() {
    let dir = TempDir::new().expect("tempdir");
    let db_dir = dir.path().join("db");
    let (mut opts, backend) = power_loss_opts(&db_dir, true);
    // Every commit flushes first.
    opts.cache_flush_interval_secs = 0;
    let db = Database::create(&opts).expect("create");
    let prefix = setup(&db);
    let journal = Journal::new(&prefix, Placement::Current);
    db.set_flush_participant(&prefix, Arc::clone(&journal) as Arc<dyn FlushParticipant>)
        .expect("register");

    let keys = vec![7u32, 8, 9];
    db.update(|tx| {
        let meta = tx.metadata();
        meta.bucket(CHAIN)
            .expect("chain")
            .put(&1u32.to_be_bytes(), &3u32.to_be_bytes())?;
        meta.put(TIP, &1u32.to_be_bytes())?;
        // The mistake: into memory before the commit, not from a hook.
        journal.hand_in(1, keys.clone());
        Ok(())
    })
    .expect("connect");
    drop(db);
    backend.cut_power();

    let committed = BTreeMap::from([(1u32, keys)]);
    let err = check_store(&db_dir, &prefix, &committed)
        .expect_err("rows journaled ahead of their tip must be caught");
    assert!(err.contains("past the durable tip"), "{err}");
}

/// With the hook, the same sequence leaves nothing of generation 1 and a
/// consistent store: the commit's own flush runs before the hook hands
/// the keys in.
#[test]
fn keys_handed_in_by_the_hook_wait_for_the_flush_that_carries_their_tip() {
    let dir = TempDir::new().expect("tempdir");
    let db_dir = dir.path().join("db");
    let (mut opts, backend) = power_loss_opts(&db_dir, true);
    opts.cache_flush_interval_secs = 0;
    let db = Database::create(&opts).expect("create");
    let prefix = setup(&db);
    let journal = Journal::new(&prefix, Placement::Current);
    db.set_flush_participant(&prefix, Arc::clone(&journal) as Arc<dyn FlushParticipant>)
        .expect("register");

    connect(&db, &journal, 1, &[7, 8, 9]).expect("connect 1");
    assert!(
        journal.calls().is_empty(),
        "the commit's own flush ran before the hook, so it had nothing to journal"
    );
    // The next commit's own flush carries generation 1's tip and keys.
    connect(&db, &journal, 2, &[10]).expect("connect 2");
    assert_eq!(
        journal.calls(),
        vec![Call::Seal, Call::Contribute, Call::Finished(true)]
    );
    drop(db);
    backend.cut_power();

    let committed = BTreeMap::from([(1u32, vec![7, 8, 9]), (2, vec![10])]);
    let tip = check_store(&db_dir, &prefix, &committed).expect("consistent");
    assert_eq!(tip, Some(1), "generation 1 rode generation 2's flush");
}

// ---------------------------------------------------------------------
// Failed flushes and commits
// ---------------------------------------------------------------------

/// A participant whose `contribute` fails fails the flush, and with it
/// the commit that triggered it: the hook does not run, `finished(false)`
/// is called once, the store latches, and nothing later commits or
/// contributes.  A power cut afterwards finds the previous durable state.
#[test]
fn a_failed_contribute_fails_the_commit_runs_no_hook_and_latches() {
    let dir = TempDir::new().expect("tempdir");
    let db_dir = dir.path().join("db");
    let (mut opts, backend) = power_loss_opts(&db_dir, true);
    opts.cache_flush_interval_secs = 0;
    let db = Database::create(&opts).expect("create");
    let prefix = setup(&db);
    let journal = Journal::new(&prefix, Placement::Current);
    db.set_flush_participant(&prefix, Arc::clone(&journal) as Arc<dyn FlushParticipant>)
        .expect("register");

    connect(&db, &journal, 1, &[1, 2]).expect("connect 1");
    db.flush().expect("flush generation 1");
    connect(&db, &journal, 2, &[3]).expect("connect 2");

    journal.fail.store(true, Ordering::SeqCst);
    let err = connect(&db, &journal, 3, &[4]).expect_err("the flush fails");
    assert_eq!(err.kind, ErrorKind::DriverSpecific, "{err}");
    assert!(db.is_fatal(), "a failed contribute latches the store");
    assert!(
        !journal.handed_in.lock().unwrap().contains(&3),
        "the failed commit's hook ran"
    );
    assert_eq!(
        journal.calls(),
        vec![
            Call::Seal,
            Call::Contribute,
            Call::Finished(true),
            Call::Seal,
            Call::Contribute,
            Call::Finished(false)
        ]
    );
    assert_eq!(
        journal.pending.lock().unwrap().len(),
        1,
        "finished(false) leaves generation 2 in memory"
    );

    journal.fail.store(false, Ordering::SeqCst);
    let err = connect(&db, &journal, 4, &[5]).expect_err("latched");
    assert_eq!(err.kind, ErrorKind::Fatal);
    assert!(!journal.handed_in.lock().unwrap().contains(&4));
    assert_eq!(journal.calls().len(), 6, "no flush runs on a latched store");
    drop(db);
    backend.cut_power();

    let committed = BTreeMap::from([(1u32, vec![1, 2]), (2, vec![3])]);
    let tip = check_store(&db_dir, &prefix, &committed).expect("consistent");
    assert_eq!(tip, Some(1));
}

/// The redb commit itself failing after the participant has written: the
/// participant is told `finished(false)` and the hook does not run.
#[test]
fn a_failed_redb_commit_after_contribute_reports_finished_false() {
    let dir = TempDir::new().expect("tempdir");
    let db_dir = dir.path().join("db");
    let (mut opts, backend) = power_loss_opts(&db_dir, true);
    opts.cache_flush_interval_secs = 0;
    let db = Database::create(&opts).expect("create");
    let prefix = setup(&db);
    let journal = Journal::new(&prefix, Placement::Current);
    db.set_flush_participant(&prefix, Arc::clone(&journal) as Arc<dyn FlushParticipant>)
        .expect("register");

    connect(&db, &journal, 1, &[1]).expect("connect 1");
    db.flush().expect("flush generation 1");
    connect(&db, &journal, 2, &[2]).expect("connect 2");
    // The power goes once the participant has written, before the commit.
    let cut = Arc::clone(&backend);
    *journal.during.lock().unwrap() = Some(Box::new(move || cut.power_fails_after(0)));

    connect(&db, &journal, 3, &[3]).expect_err("the commit fails");
    assert!(backend.power_failed());
    assert!(db.is_fatal());
    assert!(!journal.handed_in.lock().unwrap().contains(&3));
    assert_eq!(
        journal.calls().last(),
        Some(&Call::Finished(false)),
        "{:?}",
        journal.calls()
    );
    drop(db);
    backend.cut_power();

    let committed = BTreeMap::from([(1u32, vec![1]), (2, vec![2])]);
    let tip = check_store(&db_dir, &prefix, &committed).expect("consistent");
    assert_eq!(tip, Some(1));
}

/// A `contribute` that fails on the thread the flush was handed to
/// cannot fail the commit that tripped the flush, which has returned `Ok`
/// with its hook run.  It latches the store, and the participant is told
/// `finished(false)` with what it holds left as it was; the next connect
/// is refused with the failure as its cause and runs no hook, and a power
/// cut afterwards finds the previous durable state.
#[test]
fn a_contribute_that_fails_on_the_commit_thread_latches_and_keeps_the_previous_state() {
    let dir = TempDir::new().expect("tempdir");
    let db_dir = dir.path().join("db");
    let (opts, backend, _gate) = held_commit_opts(&db_dir);
    let db = Database::create(&opts).expect("create");
    let prefix = setup(&db);
    let journal = Journal::for_mode(&prefix, Placement::Current, Mode::Background);
    db.set_flush_participant(&prefix, Arc::clone(&journal) as Arc<dyn FlushParticipant>)
        .expect("register");

    connect(&db, &journal, 1, &[1, 2]).expect("connect 1");
    db.flush().expect("flush generation 1");
    connect(&db, &journal, 2, &[3]).expect("connect 2");

    journal.fail.store(true, Ordering::SeqCst);
    journal.want_at.store(1, Ordering::SeqCst);
    connect(&db, &journal, 3, &[4])
        .expect("the commit that trips the flush returns before its contribute");
    assert!(
        journal.handed_in.lock().unwrap().contains(&3),
        "the tripping commit's hook ran"
    );
    let err = db
        .wait_background_commit()
        .expect_err("the contribute failed on the commit thread");
    assert_eq!(err.kind, ErrorKind::Fatal, "{err}");
    assert!(
        err.description.contains("injected contribute failure"),
        "{err}"
    );
    assert!(db.is_fatal());
    assert_eq!(
        journal.calls(),
        vec![
            Call::Seal,
            Call::Contribute,
            Call::Finished(true),
            Call::Seal,
            Call::Contribute,
            Call::Finished(false)
        ]
    );
    assert_eq!(
        journal
            .pending
            .lock()
            .unwrap()
            .iter()
            .map(|(generation, _)| *generation)
            .collect::<Vec<_>>(),
        vec![2, 3],
        "finished(false) leaves generation 2, and 3 handed in after the seal, in memory"
    );

    journal.fail.store(false, Ordering::SeqCst);
    let err = connect(&db, &journal, 4, &[5]).expect_err("latched");
    assert_eq!(err.kind, ErrorKind::Fatal);
    assert!(
        err.description.contains("injected contribute failure"),
        "the refusal names the failed contribute: {err}"
    );
    assert!(!journal.handed_in.lock().unwrap().contains(&4));
    assert_eq!(journal.calls().len(), 6, "no flush runs on a latched store");
    drop(db);
    backend.cut_power();

    let committed = BTreeMap::from([(1u32, vec![1, 2]), (2, vec![3]), (3, vec![4])]);
    let tip = check_store(&db_dir, &prefix, &committed).expect("consistent");
    assert_eq!(tip, Some(1));
}

// ---------------------------------------------------------------------
// `on_commit`
// ---------------------------------------------------------------------

/// Hooks run in registration order, after the commit's own flush has
/// finished (the participant has been told), and before the commit's rows
/// are visible to anyone else.
#[test]
fn hooks_run_in_order_after_the_commits_own_flush_and_before_its_rows_are_visible() {
    let dir = TempDir::new().expect("tempdir");
    let db = Database::create(&Options::new(dir.path().join("db"), NET)).expect("create");
    let prefix = setup(&db);
    let journal = Journal::new(&prefix, Placement::Current);
    journal.always_work.store(true, Ordering::SeqCst);
    journal.want_at.store(0, Ordering::SeqCst);
    db.set_flush_participant(&prefix, Arc::clone(&journal) as Arc<dyn FlushParticipant>)
        .expect("register");
    connect(&db, &journal, 1, &[1]).expect("connect 1");
    // Make this commit flush first, through the participant.
    journal.want_at.store(1, Ordering::SeqCst);

    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let (first, second) = (Arc::clone(&seen), Arc::clone(&seen));
    let reader = db.clone();
    let told = Arc::clone(&journal);
    db.update(move |tx| {
        tx.metadata()
            .bucket(CHAIN)
            .expect("chain")
            .put(b"row", b"v")?;
        tx.on_commit(move || {
            let mut visible = None;
            reader
                .view(|rtx| {
                    visible = Some(rtx.metadata().bucket(CHAIN).expect("chain").get(b"row"));
                    Ok(())
                })
                .expect("a read-only transaction inside a hook");
            let flushed = told.calls().contains(&Call::Finished(true));
            first.lock().unwrap().push(format!(
                "first visible={:?} flushed={flushed}",
                visible.flatten()
            ));
        })?;
        tx.on_commit(move || second.lock().unwrap().push("second".to_string()))
    })
    .expect("commit");

    assert_eq!(
        *seen.lock().unwrap(),
        vec![
            "first visible=None flushed=true".to_string(),
            "second".to_string()
        ],
        "hooks run in order, after the commit's own flush, before its rows are published"
    );
    db.view(|tx| {
        assert_eq!(
            tx.metadata().bucket(CHAIN).expect("chain").get(b"row"),
            Some(b"v".to_vec()),
            "published once the commit returns"
        );
        Ok(())
    })
    .expect("view");
}

/// A hook never runs for a transaction that does not commit: rolled
/// back, dropped, an `update` whose closure fails, or a commit refused.
/// Registering one on a read-only or closed transaction is an error.
#[test]
fn hooks_never_run_when_the_transaction_does_not_commit() {
    let dir = TempDir::new().expect("tempdir");
    let db = Database::create(&Options::new(dir.path().join("db"), NET)).expect("create");
    let ran = Arc::new(AtomicUsize::new(0));
    let hook = || {
        let ran = Arc::clone(&ran);
        move || {
            ran.fetch_add(1, Ordering::SeqCst);
        }
    };

    let tx = db.begin(true).expect("begin");
    tx.on_commit(hook()).expect("register");
    tx.rollback().expect("rollback");
    assert_eq!(
        tx.on_commit(hook()).expect_err("closed").kind,
        ErrorKind::TxClosed
    );

    let tx = db.begin(true).expect("begin");
    tx.on_commit(hook()).expect("register");
    drop(tx);

    let err = db
        .update(|tx| {
            tx.on_commit(hook())?;
            Err(Error {
                kind: ErrorKind::DriverSpecific,
                description: "the closure fails".to_string(),
            })
        })
        .expect_err("rolled back");
    assert_eq!(err.kind, ErrorKind::DriverSpecific);

    let tx = db.begin(false).expect("begin read");
    assert_eq!(
        tx.on_commit(hook()).expect_err("read-only").kind,
        ErrorKind::TxNotWritable
    );
    tx.rollback().expect("rollback");

    assert_eq!(ran.load(Ordering::SeqCst), 0, "a hook ran without a commit");

    // And one that commits does run it, once.
    db.update(|tx| tx.on_commit(hook())).expect("commit");
    assert_eq!(ran.load(Ordering::SeqCst), 1);
}

// ---------------------------------------------------------------------
// The flush log, `wants_flush`, close
// ---------------------------------------------------------------------

/// Options whose observer records every flush.
fn observed(path: &Path) -> (Options, Arc<Mutex<Vec<FlushObservation>>>) {
    let mut opts = Options::new(path, NET);
    let seen: Arc<Mutex<Vec<FlushObservation>>> = Arc::default();
    let sink = Arc::clone(&seen);
    opts.flush_observer = Some(Arc::new(move |obs: &FlushObservation| {
        sink.lock().unwrap().push(*obs);
    }));
    (opts, seen)
}

/// A flush in which only the participant wrote commits, takes the next
/// sequence number and reaches the observer, with the row counts the
/// database kept rather than any the participant claimed.  A flush with
/// neither overlay rows nor participant work still commits nothing and is
/// not observed.
#[test]
fn the_flush_log_counts_a_flush_only_the_participant_wrote() {
    let dir = TempDir::new().expect("tempdir");
    let (opts, seen) = observed(&dir.path().join("db"));
    let db = Database::create(&opts).expect("create");
    let prefix = setup(&db);
    let journal = Journal::new(&prefix, Placement::Current);
    db.set_flush_participant(&prefix, Arc::clone(&journal) as Arc<dyn FlushParticipant>)
        .expect("register");
    let before = seen.lock().unwrap().len();
    let last_seq = seen.lock().unwrap().last().map_or(0, |o| o.sequence);

    // Nothing anywhere: no commit, no observation.
    db.flush().expect("empty flush");
    assert_eq!(seen.lock().unwrap().len(), before);
    assert!(journal.calls().is_empty(), "no work, no contribute");

    // Keys in memory, an empty overlay: the participant alone writes.
    journal.hand_in(1, vec![10, 11, 12]);
    db.flush().expect("participant-only flush");
    let obs = *seen.lock().unwrap().last().expect("observed");
    assert_eq!(obs.sequence, last_seq + 1, "it takes the next number");
    assert_eq!(obs.dirty_entries, 0, "the overlay was empty");
    let stats = obs.participant.expect("the participant's part");
    assert_eq!(
        stats.rows_put, 4,
        "three keys and the meta row, counted by the database"
    );
    assert_eq!(stats.keys_journaled, 3, "the participant's own figure kept");
    assert!(stats.bytes_put > 0);
    assert!(stats.contribute.elapsed <= obs.elapsed);
    // Its phase has what every phase of an observed flush has: the
    // flushing thread's counters, each where the kernel has the file it
    // is read from and nowhere else.
    let has = |file: &str| {
        cfg!(target_os = "linux") && Path::new("/proc/thread-self").join(file).exists()
    };
    let phase = stats.contribute;
    assert_eq!(
        (phase.read_bytes.is_some(), phase.write_bytes.is_some()),
        (has("io"), has("io")),
        "{phase:?}"
    );
    assert_eq!(
        (phase.utime_ms.is_some(), phase.stime_ms.is_some()),
        (has("stat"), has("stat")),
        "{phase:?}"
    );
    assert_eq!(
        (phase.on_cpu_ns.is_some(), phase.runq_wait_ns.is_some()),
        (has("schedstat"), has("schedstat")),
        "{phase:?}"
    );
    assert!(stats.to_json().starts_with("{\"rows_put\":4,"));

    // The commit path: `wants_flush` makes the first commit after a flush
    // flush an empty overlay for the participant alone.
    journal.hand_in(2, vec![20]);
    journal.want_at.store(1, Ordering::SeqCst);
    db.update(|tx| tx.metadata().put(b"k", b"v"))
        .expect("commit");
    let obs = *seen.lock().unwrap().last().expect("observed");
    assert_eq!(obs.sequence, last_seq + 2);
    assert_eq!(obs.dirty_entries, 0);
    assert_eq!(obs.participant.expect("participant").rows_put, 2);

    // An ordinary flush with overlay rows and no participant work.
    journal.want_at.store(0, Ordering::SeqCst);
    db.flush().expect("overlay flush");
    let obs = *seen.lock().unwrap().last().expect("observed");
    assert_eq!(obs.sequence, last_seq + 3);
    assert!(obs.dirty_entries > 0);
    assert_eq!(obs.participant, None, "no work, so not called");
}

/// With the overlay's thresholds far off, a commit flushes only when the
/// participant asks.
#[test]
fn wants_flush_makes_the_next_commit_flush() {
    let dir = TempDir::new().expect("tempdir");
    let (opts, seen) = observed(&dir.path().join("db"));
    let db = Database::create(&opts).expect("create");
    let prefix = setup(&db);
    let journal = Journal::new(&prefix, Placement::Current);
    journal.want_at.store(3, Ordering::SeqCst);
    db.set_flush_participant(&prefix, Arc::clone(&journal) as Arc<dyn FlushParticipant>)
        .expect("register");
    let flushes = || seen.lock().unwrap().len();
    let base = flushes();

    connect(&db, &journal, 1, &[1]).expect("connect 1");
    connect(&db, &journal, 2, &[2]).expect("connect 2");
    connect(&db, &journal, 3, &[3]).expect("connect 3");
    assert_eq!(flushes(), base, "two keys pending, under the threshold");
    assert_eq!(journal.pending_keys(), 3);

    // Three pending: this commit's own flush runs first and journals them.
    connect(&db, &journal, 4, &[4]).expect("connect 4");
    assert_eq!(flushes(), base + 1);
    assert_eq!(
        journal.pending.lock().unwrap().clone(),
        vec![(4, vec![4])],
        "generations 1-3 journaled; 4 handed in after the flush"
    );
}

/// The database holds its participant strongly: `close` journals what the
/// participant holds even after every other owner has dropped it, then
/// releases it.
#[test]
fn close_runs_a_participant_whose_owner_has_dropped_it() {
    let dir = TempDir::new().expect("tempdir");
    let db_dir = dir.path().join("db");
    let (opts, backend) = power_loss_opts(&db_dir, true);
    let db = Database::create(&opts).expect("create");
    let prefix = setup(&db);
    let journal = Journal::new(&prefix, Placement::Current);
    db.set_flush_participant(&prefix, Arc::clone(&journal) as Arc<dyn FlushParticipant>)
        .expect("register");
    connect(&db, &journal, 1, &[1, 2, 3]).expect("connect 1");
    connect(&db, &journal, 2, &[4]).expect("connect 2");

    let calls = Arc::clone(&journal.calls);
    let weak = Arc::downgrade(&journal);
    drop(journal);
    assert!(weak.upgrade().is_some(), "the database still holds it");

    db.close().expect("close");
    assert_eq!(
        *calls.lock().unwrap(),
        vec![Call::Seal, Call::Contribute, Call::Finished(true)],
        "the close's flush reached the participant"
    );
    assert!(
        weak.upgrade().is_none(),
        "close releases the participant once its flush is done"
    );
    drop(db);
    backend.cut_power();

    let committed = BTreeMap::from([(1u32, vec![1, 2, 3]), (2, vec![4])]);
    let tip = check_store(&db_dir, &prefix, &committed).expect("consistent");
    assert_eq!(tip, Some(2), "a clean close keeps everything");
}

// ---------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------

/// `set_flush_participant` and `clear_flush_participant` wait out a flush
/// in progress, so the flush finishes with the participant it began with,
/// `finished` included.
#[test]
fn set_and_clear_wait_out_a_running_flush() {
    let dir = TempDir::new().expect("tempdir");
    let db = Database::create(&Options::new(dir.path().join("db"), NET)).expect("create");
    let prefix = setup(&db);
    let journal = Journal::new(&prefix, Placement::Current);
    db.set_flush_participant(&prefix, Arc::clone(&journal) as Arc<dyn FlushParticipant>)
        .expect("register");
    journal.hand_in(1, vec![1]);

    // Hold the flush inside `contribute` until released.
    let (entered_tx, entered_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let release_rx = Mutex::new(release_rx);
    *journal.during.lock().unwrap() = Some(Box::new(move || {
        entered_tx.send(()).expect("signal");
        release_rx
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(30))
            .expect("released");
    }));

    let flusher = {
        let db = db.clone();
        std::thread::spawn(move || db.flush())
    };
    entered_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("the flush reached contribute");
    let cleared = Arc::new(AtomicBool::new(false));
    let clearer = {
        let db = db.clone();
        let cleared = Arc::clone(&cleared);
        std::thread::spawn(move || {
            let gone = db.clear_flush_participant();
            cleared.store(true, Ordering::SeqCst);
            gone.is_some()
        })
    };
    std::thread::sleep(Duration::from_millis(150));
    assert!(
        !cleared.load(Ordering::SeqCst),
        "clear returned while a flush was running with the participant"
    );
    release_tx.send(()).expect("release");
    flusher.join().expect("flusher").expect("flush");
    assert!(clearer.join().expect("clearer"), "it found the participant");
    assert_eq!(
        journal.calls(),
        vec![Call::Seal, Call::Contribute, Call::Finished(true)],
        "the flush finished with the participant it began with"
    );
    *journal.during.lock().unwrap() = None;

    // Cleared: flushes run without it.
    journal.hand_in(2, vec![2]);
    db.update(|tx| tx.metadata().put(b"k", b"v"))
        .expect("commit");
    db.flush().expect("flush");
    assert_eq!(journal.calls().len(), 3, "not called once cleared");

    // Registration waits for a writable transaction too.
    let tx = db.begin(true).expect("begin");
    let set = Arc::new(AtomicBool::new(false));
    let setter = {
        let db = db.clone();
        let set = Arc::clone(&set);
        let journal = Arc::clone(&journal);
        std::thread::spawn(move || {
            let result = db.set_flush_participant(&prefix, journal as Arc<dyn FlushParticipant>);
            set.store(true, Ordering::SeqCst);
            result
        })
    };
    std::thread::sleep(Duration::from_millis(150));
    assert!(
        !set.load(Ordering::SeqCst),
        "set returned while a writable transaction was open"
    );
    tx.commit().expect("commit");
    setter.join().expect("setter").expect("registered");
}

/// Registration refuses a prefix that is not a bucket of its own, a
/// second participant, a prefix the overlay holds rows under, and a
/// closed database.  `close` leaves nothing registered.
#[test]
fn registration_refuses_what_would_break_the_overlay_rule() {
    let dir = TempDir::new().expect("tempdir");
    let db = Database::create(&Options::new(dir.path().join("db"), NET)).expect("create");
    let prefix = setup(&db);
    let journal = || Journal::new(&prefix, Placement::Current) as Arc<dyn FlushParticipant>;

    for bad in [
        &[0u8, 0, 9][..],
        &[0, 0, 0, 0, 1][..],
        &[0, 0, 0, 1][..],
        &b"bidx"[..],
        &b"bidx-cbid"[..],
    ] {
        let err = db
            .set_flush_participant(bad, journal())
            .expect_err("reserved or short prefix");
        assert_eq!(err.kind, ErrorKind::IncompatibleValue, "{bad:02x?}: {err}");
    }

    // A row under the prefix waiting in the overlay would shadow the
    // participant's: refused until it is flushed.
    db.update(|tx| {
        tx.metadata()
            .bucket(JOURNAL)
            .expect("journal")
            .put(b"r", b"v")
    })
    .expect("commit");
    let err = db
        .set_flush_participant(&prefix, journal())
        .expect_err("the overlay holds a row under the prefix");
    assert_eq!(err.kind, ErrorKind::IncompatibleValue, "{err}");
    db.flush().expect("flush");
    db.set_flush_participant(&prefix, journal())
        .expect("rows in the store are no obstacle");

    let err = db
        .set_flush_participant(&prefix, journal())
        .expect_err("one at a time");
    assert_eq!(err.kind, ErrorKind::DriverSpecific, "{err}");
    assert!(db.clear_flush_participant().is_some());
    assert!(db.clear_flush_participant().is_none());
    db.set_flush_participant(&prefix, journal())
        .expect("again once cleared");

    db.close().expect("close");
    assert!(
        db.clear_flush_participant().is_none(),
        "close released the participant"
    );
    let err = db
        .set_flush_participant(&prefix, journal())
        .expect_err("closed");
    assert_eq!(err.kind, ErrorKind::DbNotOpen);
}

/// A commit that stages a row under the participant's prefix, put or
/// delete, is refused before anything is written: no hook runs, the store
/// does not latch, and the next commit succeeds.
#[test]
fn a_commit_staging_a_row_under_the_prefix_is_refused_without_latching() {
    let dir = TempDir::new().expect("tempdir");
    let db = Database::create(&Options::new(dir.path().join("db"), NET)).expect("create");
    let prefix = setup(&db);
    let journal = Journal::new(&prefix, Placement::Current);
    db.set_flush_participant(&prefix, Arc::clone(&journal) as Arc<dyn FlushParticipant>)
        .expect("register");
    let ran = Arc::new(AtomicBool::new(false));

    for delete in [false, true] {
        let flag = Arc::clone(&ran);
        let err = db
            .update(move |tx| {
                let meta = tx.metadata();
                meta.put(b"beside", b"it")?;
                let bucket = meta.bucket(JOURNAL).expect("journal");
                if delete {
                    bucket.delete(b"r")?;
                } else {
                    bucket.put(b"r", b"v")?;
                }
                tx.on_commit(move || flag.store(true, Ordering::SeqCst))
            })
            .expect_err("refused");
        assert_eq!(err.kind, ErrorKind::IncompatibleValue, "{err}");
    }
    assert!(!ran.load(Ordering::SeqCst), "a refused commit ran its hook");
    assert!(!db.is_fatal(), "a refusal is not a storage failure");
    db.view(|tx| {
        assert_eq!(tx.metadata().get(b"beside"), None, "nothing was applied");
        Ok(())
    })
    .expect("view");
    db.update(|tx| tx.metadata().put(b"beside", b"it"))
        .expect("an ordinary commit goes on");
}

// ---------------------------------------------------------------------
// The writer
// ---------------------------------------------------------------------

/// A participant that tries every way out of its prefix.
struct Trespasser {
    prefix: Vec<u8>,
    other: Vec<u8>,
    propagate: bool,
    refusals: Mutex<Vec<ErrorKind>>,
    finished: Mutex<Vec<bool>>,
}

impl FlushParticipant for Trespasser {
    fn wants_flush(&self) -> bool {
        false
    }

    fn has_work(&self) -> bool {
        true
    }

    fn contribute(&self, w: &mut FlushWriter<'_, '_>) -> Result<ParticipantStats, Error> {
        assert_eq!(w.prefix(), self.prefix.as_slice());
        let mut inside = self.prefix.clone();
        inside.extend_from_slice(b"in");
        w.insert(&inside, b"ok")?;
        assert_eq!(w.get(&inside)?, Some(b"ok".to_vec()));

        let mut outside = self.other.clone();
        outside.extend_from_slice(b"out");
        let mut below = self.prefix.clone();
        *below.last_mut().expect("prefix") -= 1;
        let mut past = self.prefix.clone();
        *past.last_mut().expect("prefix") += 1;
        past.push(0);
        let attempts: Vec<Result<(), Error>> = vec![
            w.insert(&outside, b"no"),
            w.insert(&self.prefix, b"the prefix itself is not a row"),
            w.remove(&outside).map(|_| ()),
            w.get(&outside).map(|_| ()),
            w.range(&below, &inside).map(|_| ()),
            w.range(&inside, &past).map(|_| ()),
            w.range_prefix(&outside).map(|_| ()),
        ];
        let mut refusals = Vec::new();
        for attempt in attempts {
            match attempt {
                Ok(()) => panic!("an access outside the prefix was allowed"),
                Err(e) if self.propagate => return Err(e),
                Err(e) => refusals.push(e.kind),
            }
        }
        *self.refusals.lock().unwrap() = refusals;
        Ok(ParticipantStats::default())
    }

    fn finished(&self, committed: bool) {
        self.finished.lock().unwrap().push(committed);
    }
}

/// [`FlushWriter`] refuses every key and range outside the prefix, and
/// nothing outside it is written.  A participant that propagates the
/// refusal fails the flush, latches the store, and leaves nothing of the
/// flush durable.
#[test]
fn the_writer_refuses_keys_outside_the_prefix_and_writes_nothing_there() {
    for propagate in [false, true] {
        let dir = TempDir::new().expect("tempdir");
        let db_dir = dir.path().join("db");
        let (opts, backend) = power_loss_opts(&db_dir, true);
        let db = Database::create(&opts).expect("create");
        let prefix = setup(&db);
        let mut other = Vec::new();
        db.update(|tx| {
            other = tx.metadata().create_bucket(b"other")?.raw_id().to_vec();
            Ok(())
        })
        .expect("other bucket");
        db.flush().expect("flush");
        let trespasser = Arc::new(Trespasser {
            prefix: prefix.clone(),
            other: other.clone(),
            propagate,
            refusals: Mutex::new(Vec::new()),
            finished: Mutex::new(Vec::new()),
        });
        db.set_flush_participant(
            &prefix,
            Arc::clone(&trespasser) as Arc<dyn FlushParticipant>,
        )
        .expect("register");

        let flushed = db.flush();
        let mut inside = prefix.clone();
        inside.extend_from_slice(b"in");
        if propagate {
            let err = flushed.expect_err("the refusal fails the flush");
            assert_eq!(err.kind, ErrorKind::IncompatibleValue, "{err}");
            assert!(db.is_fatal());
            assert_eq!(*trespasser.finished.lock().unwrap(), vec![false]);
        } else {
            flushed.expect("flush");
            assert_eq!(
                *trespasser.refusals.lock().unwrap(),
                vec![ErrorKind::IncompatibleValue; 7]
            );
            assert_eq!(*trespasser.finished.lock().unwrap(), vec![true]);
        }
        drop(db);
        backend.cut_power();

        let db = Database::open(&Options::new(&db_dir, NET)).expect("reopen");
        db.view(|tx| {
            assert_eq!(
                tx.try_scan_after(&other, None, usize::MAX)?,
                Vec::<(Vec<u8>, Vec<u8>)>::new(),
                "nothing reached the other bucket"
            );
            let row = tx.try_first_after(&prefix, &prefix)?;
            if propagate {
                assert_eq!(row, None, "the failed flush left nothing durable");
            } else {
                assert_eq!(row, Some((inside.clone(), b"ok".to_vec())));
            }
            Ok(())
        })
        .expect("view");
        db.close().expect("close");
    }
}

// ---------------------------------------------------------------------
// Reading the participant's rows
// ---------------------------------------------------------------------

/// A participant that writes a fixed set of rows once.
struct Rows {
    rows: Vec<(Vec<u8>, Vec<u8>)>,
    written: AtomicBool,
}

impl FlushParticipant for Rows {
    fn wants_flush(&self) -> bool {
        false
    }

    fn has_work(&self) -> bool {
        !self.written.load(Ordering::SeqCst)
    }

    fn contribute(&self, w: &mut FlushWriter<'_, '_>) -> Result<ParticipantStats, Error> {
        for (k, v) in &self.rows {
            w.insert(k, v)?;
        }
        Ok(ParticipantStats::default())
    }

    fn finished(&self, committed: bool) {
        self.written.store(committed, Ordering::SeqCst);
    }
}

fn with(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut k = prefix.to_vec();
    k.extend_from_slice(suffix);
    k
}

/// `try_first_after` finds the first row strictly after a key, the way an
/// index finds the chunk keyed by its last entry that may hold a key:
/// equal to a row's key it moves on, below the first it finds the first,
/// past the last it finds nothing, and it never crosses into the next
/// prefix.  Participant rows become visible to transactions that begin
/// after their flush commits, and not to one that began before.
#[test]
fn try_first_after_finds_the_first_row_past_a_key_and_stays_in_its_prefix() {
    let dir = TempDir::new().expect("tempdir");
    let db = Database::create(&Options::new(dir.path().join("db"), NET)).expect("create");
    let prefix = setup(&db);
    let mut next = Vec::new();
    db.update(|tx| {
        let bucket = tx.metadata().create_bucket(b"next")?;
        next = bucket.raw_id().to_vec();
        bucket.put(&[0x00], b"next bucket")
    })
    .expect("next bucket");
    db.flush().expect("flush");

    let chunk = |last: u8| with(&prefix, &[b'R', last, 0xff]);
    let rows = Arc::new(Rows {
        rows: [10u8, 20, 30]
            .iter()
            .map(|&last| (chunk(last), vec![last]))
            .collect(),
        written: AtomicBool::new(false),
    });
    db.set_flush_participant(&prefix, Arc::clone(&rows) as Arc<dyn FlushParticipant>)
        .expect("register");

    let early = db.begin(false).expect("a reader from before the flush");
    db.flush().expect("participant flush");
    assert!(rows.written.load(Ordering::SeqCst));
    let level = with(&prefix, b"R");
    assert_eq!(
        early.try_first_after(&level, &level).expect("read"),
        None,
        "a snapshot from before the flush does not see its rows"
    );
    early.rollback().expect("rollback");

    db.view(|tx| {
        let probe = |k: u8| tx.try_first_after(&level, &with(&level, &[k]));
        assert_eq!(
            probe(20)?,
            Some((chunk(20), vec![20])),
            "equal to a chunk's last key"
        );
        assert_eq!(probe(19)?, Some((chunk(20), vec![20])));
        assert_eq!(probe(21)?, Some((chunk(30), vec![30])));
        assert_eq!(probe(5)?, Some((chunk(10), vec![10])), "below the first");
        assert_eq!(
            probe(31)?,
            None,
            "past the last, the next prefix is not read"
        );
        assert_eq!(
            tx.try_first_after(&level, &[0])?,
            Some((chunk(10), vec![10])),
            "a key below the prefix starts at its first row"
        );
        assert_eq!(
            tx.try_first_after(&with(&prefix, b"J"), &with(&prefix, b"J"))?,
            None,
            "an empty level"
        );
        // The bucket's id prefixes its rows, overlay or store.
        assert_eq!(
            tx.try_first_after(&next, &next)?,
            Some((with(&next, &[0x00]), b"next bucket".to_vec()))
        );

        let two = tx.try_scan_after(&level, None, 2)?;
        assert_eq!(two, vec![(chunk(10), vec![10]), (chunk(20), vec![20])]);
        let rest = tx.try_scan_after(&level, Some(&two[1].0), 10)?;
        assert_eq!(
            rest,
            vec![(chunk(30), vec![30])],
            "resumes after the last key"
        );
        Ok(())
    })
    .expect("view");

    // A writable transaction's pending rows are part of what it reads.
    let tx = db.begin(true).expect("begin");
    tx.metadata()
        .bucket(b"next")
        .expect("next")
        .put(&[0x01], b"pending")
        .expect("put");
    assert_eq!(
        tx.try_first_after(&next, &with(&next, &[0x00]))
            .expect("read"),
        Some((with(&next, &[0x01]), b"pending".to_vec()))
    );
    tx.rollback().expect("rollback");
    assert_eq!(
        tx.try_first_after(&next, &next).expect_err("closed").kind,
        ErrorKind::TxClosed
    );
}

/// redb storage over memory that fails reads on request.
#[derive(Debug)]
struct FailingReads {
    inner: redb::backends::InMemoryBackend,
    fail: AtomicBool,
}

impl Default for FailingReads {
    fn default() -> FailingReads {
        FailingReads {
            inner: redb::backends::InMemoryBackend::new(),
            fail: AtomicBool::new(false),
        }
    }
}

impl redb::StorageBackend for FailingReads {
    fn len(&self) -> Result<u64, std::io::Error> {
        self.inner.len()
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> Result<(), std::io::Error> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("injected read failure"));
        }
        self.inner.read(offset, out)
    }

    fn set_len(&self, len: u64) -> Result<(), std::io::Error> {
        self.inner.set_len(len)
    }

    fn sync_data(&self) -> Result<(), std::io::Error> {
        self.inner.sync_data()
    }

    fn write(&self, offset: u64, data: &[u8]) -> Result<(), std::io::Error> {
        self.inner.write(offset, data)
    }
}

/// A store read error comes back as an error, never as "no row": an index
/// that read a failing disk as absence would answer `false` for an
/// address it has.
#[test]
fn try_first_after_returns_a_store_read_error() {
    let dir = TempDir::new().expect("tempdir");
    let backend = Arc::new(FailingReads::default());
    let mut opts = Options::new(dir.path().join("db"), NET);
    // No page cache, so a read reaches the backend; enough rows that the
    // tree has leaves below the root redb holds for a transaction's life.
    opts.db_cache_bytes = 0;
    opts.backend = Some(Arc::clone(&backend) as SharedBackend);
    let db = Database::create(&opts).expect("create");
    let mut id = Vec::new();
    db.update(|tx| {
        let bucket = tx.metadata().create_bucket(b"rows")?;
        id = bucket.raw_id().to_vec();
        for i in 0..2000u32 {
            bucket.put(&i.to_be_bytes(), &[0x5a; 64])?;
        }
        Ok(())
    })
    .expect("fill");
    db.flush().expect("flush");

    let tx = db.begin(false).expect("begin");
    let probe = with(&id, &1000u32.to_be_bytes());
    assert!(tx.try_first_after(&id, &probe).expect("healthy").is_some());
    backend.fail.store(true, Ordering::SeqCst);
    let err = tx
        .try_first_after(&id, &probe)
        .expect_err("a failed read is an error, not absence");
    assert_ne!(err.kind, ErrorKind::TxClosed, "{err}");
    let err = tx
        .try_scan_after(&id, None, 10)
        .expect_err("and so is a failed scan");
    assert_ne!(err.kind, ErrorKind::TxClosed, "{err}");
    backend.fail.store(false, Ordering::SeqCst);
    tx.rollback().expect("rollback");
}
