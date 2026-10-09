// SPDX-License-Identifier: ISC
//! Layout 3 under power loss, under concurrent lookups, and under
//! injected faults, with the controls that prove each test can fail; and
//! the merge, probe and leaf-size unit tests that need the crate's
//! internals.
//!
//! **Power loss.**  A scripted run of connects, mempool transactions and
//! flushes is cut at every storage operation it makes, under the shared
//! `PowerLossBackend`.  After each cut the store is reopened, the index
//! recovered, and held to the plan's four properties: (a) every key of
//! every connect whose tip row survived is present; (b) the index holds
//! exactly those keys, mempool keys drained at those connects included,
//! and none of a connect whose tip row was lost; (c) every row checks
//! against layout 3's invariants; (d) the memtable rebuilt from the
//! journal is exactly the journal's pending keys.
//!
//! The same checks hold at every cut point of a run that ends in the
//! daemon's clean shutdown (handles dropped, then `Database::close`), and
//! a drop cut at any point leaves a store that finishes the drop and
//! rebuilds.
//!
//! **Controls that must fail**, each a broken index the checks have to
//! catch: a backend whose sync does nothing, a participant that skips its
//! journal rows, a participant released before the close's flush (what a
//! weak registration amounts to), lookups that read the mempool overlay
//! last, and a hand-over that runs after the tip row is published.
//!
//! **Keys an adversary grinds** to share a first hash160 byte must still
//! spread over the partitions, keeping each flush near its page budget
//! and the journal collectable.

#![allow(clippy::arithmetic_side_effects)]

#[macro_use]
#[path = "../../tests/support/chain.rs"]
mod chain;

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use chain::{Key, TestChain, address_of, block_on, script_of, tx_paying};
use dcroxide_chaincfg::{Params, simnet_params};
use dcroxide_database::{Database, FlushParticipant, Options, SharedBackend};
use dcroxide_testutil::SplitMix64;
use dcroxide_testutil::powerloss::PowerLossBackend;
use dcroxide_wire::MsgBlock;
use tempfile::TempDir;

use super::policy::{CHUNK, PARTITIONS, Partitioner, Policy};
use super::runs::{self, BASE, DELTA};
use super::store::{AddrStore, LayoutCheck, check_layout};
use crate::ChainQueryer;
use crate::existsaddrindex::{EXISTS_ADDR_INDEX_KEY, ExistsAddrIndex};
use crate::subscriber::{CONNECT_NTFN, IndexNtfn, IndexSubscriber, NO_PREREQS};

impl_chain_queryer!(crate::ChainQueryer, chain::TestChain);

const NET: u32 = 0x1214_1c16;

fn params() -> &'static Params {
    static PARAMS: std::sync::OnceLock<Params> = std::sync::OnceLock::new();
    PARAMS.get_or_init(simnet_params)
}

fn random_key(rng: &mut SplitMix64) -> Key {
    let mut key = [0u8; 21];
    key[0] = rng.below(4) as u8;
    for chunk in key[1..].chunks_mut(8) {
        let r = rng.next_u64().to_le_bytes();
        chunk.copy_from_slice(&r[..chunk.len()]);
    }
    key
}

/// The partition key of the tests that need keys in chosen partitions or
/// layouts that repeat.
const PKEY: [u8; 16] = *b"layout-3 tests!!";

/// `policy` with the tests' partition key.
fn fixed(policy: Policy) -> Policy {
    Policy {
        partition_key: Some(PKEY),
        ..policy
    }
}

/// The partition hash under [`PKEY`].
fn part() -> Partitioner {
    Partitioner::new(&PKEY)
}

/// A random key that [`PKEY`] files in partition `p`.
fn random_key_in(rng: &mut SplitMix64, p: u8) -> Key {
    loop {
        let key = random_key(rng);
        if part().of(&key) == p {
            return key;
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn new_subber() -> IndexSubscriber {
    IndexSubscriber::new(Arc::new(AtomicBool::new(false)), None)
}

fn open_index(
    subber: &mut IndexSubscriber,
    db: &Arc<Database>,
    chain: &Arc<TestChain>,
    policy: Policy,
) -> Arc<Mutex<ExistsAddrIndex>> {
    ExistsAddrIndex::new_with_policy(
        subber,
        Arc::clone(db),
        Arc::clone(chain) as Arc<dyn ChainQueryer>,
        NO_PREREQS,
        policy,
    )
    .expect("index")
}

/// Connect a block paying `keys` on the chain's tip through `subber`.
fn connect(
    chain: &TestChain,
    subber: &mut IndexSubscriber,
    salt: u32,
    keys: &[Key],
) -> Result<(), crate::IdxError> {
    let scripts: Vec<Vec<u8>> = keys.iter().map(|k| script_of(k, params())).collect();
    let parent = chain.at(chain.tip().0);
    let block = block_on(&parent, salt, vec![tx_paying(&scripts)]);
    chain.add(&block);
    subber.notify(&IndexNtfn {
        ntfn_type: CONNECT_NTFN,
        block,
        parent,
        is_treasury_enabled: false,
    })
}

fn mempool_tx(keys: &[Key]) -> dcroxide_wire::MsgTx {
    let scripts: Vec<Vec<u8>> = keys.iter().map(|k| script_of(k, params())).collect();
    tx_paying(&scripts)
}

// ---------------------------------------------------------------------
// Power loss
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Step {
    Connect(Vec<Key>),
    Mempool(Vec<Key>),
    Flush,
}

#[derive(Debug, Clone)]
struct Script {
    steps: Vec<Step>,
    cache_max_size: u64,
}

impl Script {
    /// Connects of 1-12 keys, half of them crowding four partitions so
    /// bases grow and delta rewrites run; mempool transactions; flushes.
    /// The partitions are [`PKEY`]'s, which the runs use.
    fn random(rng: &mut SplitMix64, connects: usize) -> Script {
        let mut steps = Vec::new();
        for _ in 0..connects {
            let mut keys: Vec<Key> = (0..rng.below(12) + 1)
                .map(|_| {
                    if rng.below(2) == 0 {
                        let p = (rng.below(4) as u8) * 64;
                        random_key_in(rng, p)
                    } else {
                        random_key(rng)
                    }
                })
                .collect();
            keys.sort_unstable();
            keys.dedup();
            steps.push(Step::Connect(keys));
            if rng.below(4) == 0 {
                steps.push(Step::Mempool(vec![random_key(rng), random_key(rng)]));
            }
            if rng.below(5) == 0 {
                steps.push(Step::Flush);
            }
        }
        Script {
            steps,
            cache_max_size: 2000 + rng.below(4000),
        }
    }
}

/// How a run should break the index, for the controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Break {
    None,
    /// The participant writes no journal rows.
    SkipJournal,
    /// The participant is released before a clean close.
    WeakClose,
}

/// What one run of a script did and what survived it.
struct Run {
    survived: Result<(), String>,
    ops: u64,
    /// Summed over the run's flushes: keys journaled, merges, base
    /// rewrites, rows removed.
    work: [u64; 4],
}

/// The index tip's height as the store holds it.
fn tip_height(db: &Database) -> Option<i64> {
    let tx = db.begin(false).ok()?;
    let height = tx
        .metadata()
        .bucket(b"idxtips")
        .and_then(|b| b.get(EXISTS_ADDR_INDEX_KEY))
        .map(|v| i64::from(u32::from_le_bytes(v[32..36].try_into().expect("height")) as i32));
    let _ = tx.rollback();
    height
}

/// Run `script` over a power-loss backend, cutting the power after
/// `cut_after` storage operations when given, then hold what survived to
/// the four properties.
fn run(script: &Script, cut_after: Option<u64>, honest_sync: bool, brk: Break) -> Run {
    let dir = TempDir::new().expect("tempdir");
    let db_dir = dir.path().join("db");
    std::fs::create_dir_all(&db_dir).expect("mkdir");
    let backend = PowerLossBackend::create(&db_dir.join("metadata.redb"), honest_sync);
    let mut opts = Options::new(&db_dir, NET);
    opts.backend = Some(Arc::clone(&backend) as SharedBackend);
    opts.cache_max_size = script.cache_max_size;
    let work = Arc::new(Mutex::new([0u64; 4]));
    let seen = Arc::clone(&work);
    opts.flush_observer = Some(Arc::new(
        move |obs: &dcroxide_database::FlushObservation| {
            if let Some(p) = obs.participant {
                let mut w = seen.lock().expect("work");
                w[0] += p.keys_journaled;
                w[1] += p.merges;
                w[2] += p.base_rewrites;
                w[3] += p.rows_removed;
            }
        },
    ));
    let db = Arc::new(Database::create(&opts).expect("create"));
    let chain = TestChain::new(params());
    let mut subber = new_subber();
    let idx = open_index(&mut subber, &db, &chain, fixed(Policy::tiny()));
    db.flush().expect("setup flush");
    let store = Arc::clone(idx.lock().expect("index").store());
    if brk == Break::SkipJournal {
        store.faults.skip_journal.store(true, Ordering::SeqCst);
    }

    let start = backend.ops();
    if let Some(n) = cut_after {
        backend.power_fails_after(n);
    }
    // `candidates[h]` is what the connect of height h handed over: its
    // block's keys and the mempool keys it drained.
    let mut candidates: Vec<BTreeSet<Key>> = vec![BTreeSet::new()];
    let mut mempool = BTreeSet::new();
    let mut salt = 0u32;
    for step in &script.steps {
        let before = store.mem.snapshot();
        let res = match step {
            Step::Connect(keys) => {
                salt += 1;
                let res = connect(&chain, &mut subber, salt, keys);
                if res.is_ok() {
                    let mut handed: BTreeSet<Key> = keys.iter().copied().collect();
                    handed.append(&mut mempool);
                    candidates.push(handed);
                }
                // A failed connect leaves its block on the chain; the
                // restart's catch-up indexes it, without the mempool
                // keys, which a failed connect never drains.
                res.map_err(|e| e.to_string())
            }
            Step::Mempool(keys) => {
                idx.lock()
                    .expect("index")
                    .add_unconfirmed_tx(&mempool_tx(keys));
                mempool.extend(keys.iter().copied());
                Ok(())
            }
            Step::Flush => db.flush().map_err(|e| e.to_string()),
        };
        if let Err(e) = res {
            // A failed flush leaves memory as it was, and so does a
            // failed connect, whose hook never runs.
            assert_eq!(
                store.mem.snapshot(),
                before,
                "a failed {step:?} changed the memtable ({e})"
            );
            break;
        }
    }
    let ops = backend.ops() - start;
    // Read before the drop: redb's own drop writes.
    let power_failed = backend.power_failed();
    let latched = db.is_fatal();
    let finished = store.faults.finished.lock().expect("finished").clone();
    if let Some(false_at) = finished.iter().position(|&ok| !ok) {
        assert_eq!(
            false_at,
            finished.len() - 1,
            "finished(false) must be the last call: {finished:?}"
        );
        assert!(latched, "finished(false) on an unlatched store");
    }
    if power_failed {
        assert!(latched, "a refused write must latch the store");
    }
    if brk == Break::WeakClose {
        drop(db.clear_flush_participant());
        let _ = db.close();
    }
    drop(idx);
    drop(subber);
    drop(db);
    drop(store);
    backend.cut_power();

    let survived = check_store(&db_dir, &chain, &candidates);
    let work = *work.lock().expect("work");
    Run {
        survived,
        ops,
        work,
    }
}

/// Reopen and hold the store to the four properties; then catch the
/// index up and check it holds every block's keys.
fn check_store(
    db_dir: &Path,
    chain: &Arc<TestChain>,
    candidates: &[BTreeSet<Key>],
) -> Result<(), String> {
    let db =
        Arc::new(Database::open(&Options::new(db_dir, NET)).map_err(|e| format!("reopen: {e}"))?);
    let verdict = (|| {
        let tip = tip_height(&db).ok_or("the index tip did not survive")?;
        let tip_at = usize::try_from(tip).map_err(|_| format!("tip {tip}"))?;
        if tip_at >= candidates.len() {
            return Err(format!(
                "the durable tip {tip} is past the {} connects that committed",
                candidates.len() - 1
            ));
        }
        let want: BTreeSet<Key> = candidates[..=tip_at].iter().flatten().copied().collect();
        // (c)
        let check = check_layout(&db)
            .map_err(|e| format!("layout: {e}"))?
            .ok_or("the index bucket did not survive")?;
        let mut subber = new_subber();
        let idx = ExistsAddrIndex::new_with_policy(
            &mut subber,
            Arc::clone(&db),
            Arc::clone(chain) as Arc<dyn ChainQueryer>,
            NO_PREREQS,
            Policy::tiny(),
        )
        .map_err(|e| format!("reopen the index: {e}"))?;
        let (got, memtable) = {
            let idx = idx.lock().expect("index");
            (
                idx.logical_keys().map_err(|e| format!("keys: {e}"))?,
                idx.memtable_keys(),
            )
        };
        // (d)
        if memtable != check.pending {
            return Err(format!(
                "the rebuilt memtable holds {} keys, the journal's pending {}",
                memtable.len(),
                check.pending.len()
            ));
        }
        // (a) and (b)
        let got: BTreeSet<Key> = got.into_iter().collect();
        if let Some(missing) = want.difference(&got).next() {
            return Err(format!(
                "{} of a connect at or below the durable tip {tip} is missing",
                hex(missing)
            ));
        }
        if let Some(extra) = got.difference(&want).next() {
            return Err(format!(
                "{} is held but no connect at or below the durable tip {tip} handed it over",
                hex(extra)
            ));
        }
        // (a) through the lookup path as well: overlay, memtable, runs.
        let wanted: Vec<Key> = want.iter().copied().collect();
        let addrs: Vec<_> = wanted.iter().map(|k| address_of(k, params())).collect();
        let found = idx
            .lock()
            .expect("index")
            .query()
            .exists_addresses(&addrs)
            .map_err(|e| format!("lookup: {e}"))?;
        if let Some(i) = found.iter().position(|&f| !f) {
            return Err(format!(
                "{} of a connect at or below the durable tip {tip} looks up false",
                hex(&wanted[i])
            ));
        }
        // The catch-up indexes every block the cut lost, but not the
        // mempool keys of a lost connect: those went with the process,
        // as they go with dcrd's.
        subber
            .catch_up(&**chain)
            .map_err(|e| format!("catch up: {e}"))?;
        let after: BTreeSet<Key> = idx
            .lock()
            .expect("index")
            .logical_keys()
            .map_err(|e| format!("keys: {e}"))?
            .into_iter()
            .collect();
        let mut all = want;
        let mut blocks = BTreeSet::new();
        for height in 1..=chain.tip().0 {
            blocks.extend(block_keys(&chain.at(height)));
        }
        all.extend(blocks.iter().copied());
        for keys in &candidates[tip_at + 1..] {
            all.extend(keys.iter().copied());
        }
        if let Some(missing) = blocks.difference(&after).next() {
            return Err(format!("{} is missing after the catch-up", hex(missing)));
        }
        if let Some(extra) = after.difference(&all).next() {
            return Err(format!(
                "{} appeared from nowhere after the catch-up",
                hex(extra)
            ));
        }
        drop(idx);
        Ok(())
    })();
    let _ = db.close();
    verdict
}

/// The keys of a block built by [`connect`]: its one transaction's
/// outputs.
fn block_keys(block: &MsgBlock) -> Vec<Key> {
    block.transactions[0]
        .tx_out
        .iter()
        .filter_map(|out| {
            let (_, addrs) =
                dcroxide_txscript::stdscript::extract_addrs(out.version, &out.pk_script, params());
            addrs.first().map(|a| crate::addr_to_key(a).expect("key"))
        })
        .collect()
}

/// Every cut point of a scripted run, each one reopened and checked.
#[test]
fn a_power_cut_at_every_storage_operation_keeps_index_and_tip_together() {
    let mut rng = SplitMix64(0x7065_7263_7574_0001);
    let script = Script::random(&mut rng, 22);
    let full = run(&script, None, true, Break::None);
    full.survived.expect("the uncut run");
    assert!(full.ops > 50, "the run made only {} operations", full.ops);
    // The cuts land in flushes that journal, rewrite deltas and bases,
    // and remove rows (replaced chunks and collected journal rows).
    let [journaled, merges, bases, removed] = full.work;
    assert!(
        journaled > 0 && bases > 0 && merges > bases && removed > 0,
        "{:?}",
        full.work
    );
    for n in 0..=full.ops {
        let cut = run(&script, Some(n), true, Break::None);
        if let Err(e) = cut.survived {
            panic!("power cut after {n} of {} operations: {e}", full.ops);
        }
    }
}

/// Random scripts cut at random points, and at their end.
#[test]
fn random_runs_cut_at_random_points_keep_index_and_tip_together() {
    let mut rng = SplitMix64::from_entropy("random_runs_cut_at_random_points");
    for round in 0..12 {
        let script = Script::random(&mut rng, 30);
        let cut = if round % 3 == 0 {
            None
        } else {
            Some(rng.below(1200))
        };
        if let Err(e) = run(&script, cut, true, Break::None).survived {
            panic!("round {round}, cut {cut:?}: {e}");
        }
    }
}

/// How many cut points of a sweep the checks reject.
fn rejected(script: &Script, honest_sync: bool, brk: Break) -> usize {
    let full = run(script, None, honest_sync, Break::None);
    (0..=full.ops)
        .step_by(3)
        .map(Some)
        .chain([None])
        .filter(|&cut| run(script, cut, honest_sync, brk).survived.is_err())
        .count()
}

/// Control: a backend that acknowledges syncs without making anything
/// durable loses everything a cut discards, and the checks notice.
#[test]
fn control_a_store_that_never_syncs_is_caught() {
    let mut rng = SplitMix64(0x7065_7263_7574_0002);
    let script = Script::random(&mut rng, 12);
    assert!(rejected(&script, false, Break::None) > 0);
}

/// Control: a participant that writes no journal rows loses the keys of
/// durable tips at the next open.
#[test]
fn control_a_participant_that_skips_the_journal_is_caught() {
    let mut rng = SplitMix64(0x7065_7263_7574_0003);
    let script = Script::random(&mut rng, 12);
    assert!(rejected(&script, true, Break::SkipJournal) > 0);
}

/// Control: a participant released before the close's flush, as a weak
/// registration would be once its owner had gone, leaves tip rows whose
/// keys were never journaled.
#[test]
fn control_a_participant_released_before_the_close_is_caught() {
    let mut rng = SplitMix64(0x7065_7263_7574_0004);
    let script = Script::random(&mut rng, 12);
    let run = run(&script, None, true, Break::WeakClose);
    let err = run.survived.expect_err("the weak close must lose keys");
    assert!(err.contains("missing"), "{err}");
}

/// A run that ends as the daemon ends: every index handle dropped, then
/// `Database::close`, whose final flush reaches the participant only
/// through the database's own reference.  Power fails after `cut` storage
/// operations when given, and what survives is held to the four
/// properties.  Returns the operations the run made.
fn close_run(cut: Option<u64>) -> (u64, Result<(), String>) {
    let dir = TempDir::new().expect("tempdir");
    let db_dir = dir.path().join("db");
    std::fs::create_dir_all(&db_dir).expect("mkdir");
    let backend = PowerLossBackend::create(&db_dir.join("metadata.redb"), true);
    let mut opts = Options::new(&db_dir, NET);
    opts.backend = Some(Arc::clone(&backend) as SharedBackend);
    opts.cache_max_size = 3000;
    let db = Arc::new(Database::create(&opts).expect("create"));
    let chain = TestChain::new(params());
    let mut subber = new_subber();
    let idx = open_index(&mut subber, &db, &chain, fixed(Policy::tiny()));
    db.flush().expect("setup flush");
    let unconfirmed = idx.lock().expect("index").unconfirmed();
    let start = backend.ops();
    if let Some(n) = cut {
        backend.power_fails_after(n);
    }
    let mut rng = SplitMix64(0x636c_6f73_6501);
    let mut candidates: Vec<BTreeSet<Key>> = vec![BTreeSet::new()];
    let mut mempool = BTreeSet::new();
    for salt in 0..16u32 {
        if salt % 3 == 0 {
            let keys = [random_key(&mut rng), random_key(&mut rng)];
            unconfirmed.add_unconfirmed_tx(&mempool_tx(&keys));
            mempool.extend(keys);
        }
        let keys: Vec<Key> = (0..1 + rng.below(6))
            .map(|i| {
                if i % 2 == 0 {
                    random_key_in(&mut rng, 64)
                } else {
                    random_key(&mut rng)
                }
            })
            .collect();
        if connect(&chain, &mut subber, salt, &keys).is_err() {
            break;
        }
        let mut handed: BTreeSet<Key> = keys.into_iter().collect();
        handed.append(&mut mempool);
        candidates.push(handed);
    }
    // The daemon's order: the handles go first, so only the database's
    // reference reaches the participant in the close's flush.
    drop(unconfirmed);
    drop(idx);
    drop(subber);
    let closed = db.close();
    let ops = backend.ops() - start;
    drop(db);
    backend.cut_power();
    if cut.is_none()
        && let Err(e) = closed
    {
        return (ops, Err(format!("the uncut close failed: {e}")));
    }
    (ops, check_store(&db_dir, &chain, &candidates))
}

/// Every cut point of a run ending in the daemon's clean shutdown.
#[test]
fn a_power_cut_at_every_operation_of_a_clean_shutdown_keeps_index_and_tip_together() {
    let (ops, full) = close_run(None);
    full.expect("the uncut run");
    assert!(ops > 30, "the run made only {ops} operations");
    for n in 0..=ops {
        if let (_, Err(e)) = close_run(Some(n)) {
            panic!("power cut after {n} of {ops} operations: {e}");
        }
    }
}

/// A drop of a closed layout-3 index (`--dropexistsaddrindex`, the index
/// off), power failing after `cut` storage operations when given, then a
/// start with the index on: whatever the cut left -- the whole index, part
/// of it with the drop's marker, or none of it -- the start must finish or
/// restart the drop and catch up to exactly every block's keys.
fn drop_run(cut: Option<u64>) -> (u64, Result<(), String>) {
    let dir = TempDir::new().expect("tempdir");
    let db_dir = dir.path().join("db");
    std::fs::create_dir_all(&db_dir).expect("mkdir");
    let chain = TestChain::new(params());
    let mut rng = SplitMix64(0x6472_6f70_0001);
    {
        let mut opts = Options::new(&db_dir, NET);
        opts.cache_max_size = 3000;
        let db = Arc::new(Database::create(&opts).expect("create"));
        let mut subber = new_subber();
        let idx = open_index(&mut subber, &db, &chain, fixed(Policy::tiny()));
        for salt in 0..12u32 {
            let keys: Vec<Key> = (0..5).map(|_| random_key(&mut rng)).collect();
            connect(&chain, &mut subber, salt, &keys).expect("connect");
        }
        drop(idx);
        drop(subber);
        db.close().expect("close");
    }
    let backend = PowerLossBackend::create(&db_dir.join("metadata.redb"), true);
    let mut opts = Options::new(&db_dir, NET);
    opts.backend = Some(Arc::clone(&backend) as SharedBackend);
    // Every commit flushes, so each of the drop's transactions -- the
    // marker, the deletions, the bucket, tip and version -- is durable on
    // its own, and every partial drop is a state a cut can leave.
    opts.cache_max_size = 1;
    let db = Database::open(&opts).expect("open");
    let start = backend.ops();
    if let Some(n) = cut {
        backend.power_fails_after(n);
    }
    let dropped = crate::drop_exists_addr_index(&Arc::new(AtomicBool::new(false)), &db, None);
    let closed = db.close();
    let ops = backend.ops() - start;
    drop(db);
    backend.cut_power();
    if cut.is_none() {
        if let Err(e) = dropped {
            return (ops, Err(format!("the uncut drop failed: {e}")));
        }
        if let Err(e) = closed {
            return (ops, Err(format!("the uncut close failed: {e}")));
        }
    }
    let mut all = BTreeSet::new();
    for height in 1..=chain.tip().0 {
        all.extend(block_keys(&chain.at(height)));
    }
    let verdict = (|| {
        let db = Arc::new(
            Database::open(&Options::new(&db_dir, NET)).map_err(|e| format!("reopen: {e}"))?,
        );
        let res = (|| {
            let mut subber = new_subber();
            let idx = ExistsAddrIndex::new_with_policy(
                &mut subber,
                Arc::clone(&db),
                Arc::clone(&chain) as Arc<dyn ChainQueryer>,
                NO_PREREQS,
                Policy::tiny(),
            )
            .map_err(|e| format!("reopen the index: {e}"))?;
            subber
                .catch_up(&*chain)
                .map_err(|e| format!("catch up: {e}"))?;
            let got: BTreeSet<Key> = idx
                .lock()
                .expect("index")
                .logical_keys()
                .map_err(|e| format!("keys: {e}"))?
                .into_iter()
                .collect();
            check_layout(&db).map_err(|e| format!("layout: {e}"))?;
            if got != all {
                return Err(format!(
                    "{} keys where the blocks hold {}",
                    got.len(),
                    all.len()
                ));
            }
            Ok(())
        })();
        let _ = db.close();
        res
    })();
    (ops, verdict)
}

/// Every cut point of a drop.
#[test]
fn a_power_cut_at_every_operation_of_a_drop_leaves_a_store_that_rebuilds() {
    let (ops, full) = drop_run(None);
    full.expect("the uncut run");
    assert!(ops > 15, "the drop made only {ops} operations");
    for n in 0..=ops {
        if let (_, Err(e)) = drop_run(Some(n)) {
            panic!("power cut after {n} of {ops} operations: {e}");
        }
    }
}

// ---------------------------------------------------------------------
// Fault injection
// ---------------------------------------------------------------------

/// A `contribute` that fails latches the store and is told
/// `finished(false)`; memory is unchanged, no later commit succeeds, and
/// a power cut afterwards shows the previous durable state, consistent.
#[test]
fn a_failed_contribute_latches_and_keeps_the_previous_durable_state() {
    let dir = TempDir::new().expect("tempdir");
    let db_dir = dir.path().join("db");
    std::fs::create_dir_all(&db_dir).expect("mkdir");
    let backend = PowerLossBackend::create(&db_dir.join("metadata.redb"), true);
    let mut opts = Options::new(&db_dir, NET);
    opts.backend = Some(Arc::clone(&backend) as SharedBackend);
    let db = Arc::new(Database::create(&opts).expect("create"));
    let chain = TestChain::new(params());
    let mut subber = new_subber();
    let idx = open_index(&mut subber, &db, &chain, Policy::tiny());
    let mut rng = SplitMix64(21);
    let mut candidates = vec![BTreeSet::new()];
    for salt in 0..10 {
        let keys: Vec<Key> = (0..5).map(|_| random_key(&mut rng)).collect();
        connect(&chain, &mut subber, salt, &keys).expect("connect");
        candidates.push(keys.into_iter().collect());
    }
    db.flush().expect("flush");
    let durable_tip = chain.tip();

    let keys: Vec<Key> = (0..5).map(|_| random_key(&mut rng)).collect();
    connect(&chain, &mut subber, 99, &keys).expect("connect");
    let store = Arc::clone(idx.lock().expect("index").store());
    store.faults.fail_contribute.store(true, Ordering::SeqCst);
    let before = store.mem.snapshot();
    let meta_before = store.meta();
    let err = db.flush().expect_err("the flush must fail");
    assert!(
        err.description.contains("injected contribute failure"),
        "{err}"
    );
    assert!(db.is_fatal(), "the store latched");
    assert_eq!(
        store.faults.finished.lock().expect("log").last(),
        Some(&false)
    );
    assert_eq!(store.mem.snapshot(), before, "memory changed");
    assert_eq!(store.meta(), meta_before, "the meta changed");
    assert!(
        connect(&chain, &mut subber, 100, &[random_key(&mut rng)]).is_err(),
        "a commit succeeded on a latched store"
    );

    drop(idx);
    drop(subber);
    drop(db);
    drop(store);
    backend.cut_power();
    // Back to the durable state: the chain as it was at the flush.
    while chain.tip() != durable_tip {
        chain.remove_tip();
    }
    check_store(&db_dir, &chain, &candidates).expect("the previous durable state");
}

// ---------------------------------------------------------------------
// The hand-off race
// ---------------------------------------------------------------------

/// What the readers of a race saw.
struct Race {
    falses: usize,
    lookups: usize,
}

/// A fault a race runs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RaceFault {
    None,
    OverlayLast,
    HookAfterPublish,
}

/// A writer connects blocks while eight readers look up keys that must
/// answer true: every key already handed to the mempool, and every key
/// of a block at or below the tip each reader read first.  Half the
/// blocks pay only mempool keys, so their connects move them from the
/// overlay to the memtable; with `flush_each`, every connect is followed
/// by a flush, which under `k0` = 0 moves them on into the runs.
///
/// The writer stops after `blocks`, at `deadline`, or, under a fault,
/// once a reader has seen a `false`.
fn race(
    policy: Policy,
    flush_each: bool,
    fault: RaceFault,
    blocks: u32,
    deadline: Duration,
) -> Race {
    let dir = TempDir::new().expect("tempdir");
    let db = Arc::new(Database::create(&Options::new(dir.path().join("db"), NET)).expect("create"));
    let chain = TestChain::new(params());
    let mut subber = new_subber();
    let idx = open_index(&mut subber, &db, &chain, policy);
    let store = Arc::clone(idx.lock().expect("index").store());
    match fault {
        RaceFault::None => {}
        RaceFault::OverlayLast => store.faults.overlay_last.store(true, Ordering::SeqCst),
        RaceFault::HookAfterPublish => store
            .faults
            .hook_after_publish
            .store(true, Ordering::SeqCst),
    }
    let query = idx.lock().expect("index").query();
    let unconfirmed = idx.lock().expect("index").unconfirmed();

    // Keys that must answer true from the moment they are pushed.
    let always: Arc<RwLock<Vec<Key>>> = Arc::new(RwLock::new(Vec::new()));
    // Keys of each height, pushed before the block connects.
    let by_height: Arc<RwLock<Vec<Vec<Key>>>> = Arc::new(RwLock::new(vec![Vec::new()]));
    let stop = Arc::new(AtomicBool::new(false));
    let falses = Arc::new(AtomicUsize::new(0));
    let lookups = Arc::new(AtomicUsize::new(0));
    let readers: Vec<_> = (0..8u64)
        .map(|t| {
            let (query, always, by_height) =
                (query.clone(), Arc::clone(&always), Arc::clone(&by_height));
            let (stop, falses, lookups) =
                (Arc::clone(&stop), Arc::clone(&falses), Arc::clone(&lookups));
            std::thread::spawn(move || {
                let mut rng = SplitMix64(t);
                while !stop.load(Ordering::SeqCst) {
                    // A mempool key, mostly one of the newest.
                    let pick = {
                        let always = always.read().expect("always");
                        (!always.is_empty()).then(|| {
                            let from = always.len().saturating_sub(16);
                            let i = if rng.below(4) == 0 {
                                rng.below(always.len() as u64) as usize
                            } else {
                                from + rng.below((always.len() - from) as u64) as usize
                            };
                            always[i]
                        })
                    };
                    // The keys of the tip read first, or of a block below.
                    let tip = query.tip().expect("tip").0 as u64;
                    let height = if rng.below(2) == 0 {
                        tip
                    } else {
                        rng.below(tip + 1)
                    };
                    let mut keys: Vec<Key> = pick.into_iter().collect();
                    keys.extend(by_height.read().expect("heights")[height as usize].clone());
                    for key in &keys {
                        if !query
                            .exists_address(&address_of(key, params()))
                            .expect("lookup")
                        {
                            falses.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    let addrs: Vec<_> = keys.iter().map(|k| address_of(k, params())).collect();
                    let found = query.exists_addresses(&addrs).expect("lookups");
                    falses.fetch_add(found.iter().filter(|&&b| !b).count(), Ordering::SeqCst);
                    lookups.fetch_add(keys.len() * 2, Ordering::SeqCst);
                }
            })
        })
        .collect();

    let started = Instant::now();
    let mut rng = SplitMix64(0x7261_6365);
    for salt in 0..blocks {
        if started.elapsed() > deadline
            || (fault != RaceFault::None && falses.load(Ordering::SeqCst) > 0)
        {
            break;
        }
        let keys: Vec<Key> = (0..4).map(|_| random_key(&mut rng)).collect();
        if salt % 2 == 0 {
            unconfirmed.add_unconfirmed_tx(&mempool_tx(&keys));
            always.write().expect("always").extend(keys.iter().copied());
        }
        by_height.write().expect("heights").push(keys.clone());
        connect(&chain, &mut subber, salt, &keys).expect("connect");
        if fault == RaceFault::HookAfterPublish {
            // Widen the window between the published tip and its keys.
            std::thread::sleep(Duration::from_micros(300));
            idx.lock().expect("index").run_deferred();
        }
        if flush_each {
            db.flush().expect("flush");
        }
    }
    stop.store(true, Ordering::SeqCst);
    for reader in readers {
        reader.join().expect("reader");
    }
    Race {
        falses: falses.load(Ordering::SeqCst),
        lookups: lookups.load(Ordering::SeqCst),
    }
}

/// No reader ever sees `false` for a key it must find while keys move
/// from the overlay to the memtable.
#[test]
fn lookups_never_miss_a_key_handed_from_the_mempool() {
    let race = race(
        Policy::tiny(),
        false,
        RaceFault::None,
        1500,
        Duration::from_secs(60),
    );
    assert!(race.lookups > 1000, "{} lookups", race.lookups);
    assert_eq!(race.falses, 0, "of {} lookups", race.lookups);
}

/// The same with a merge of everything at every flush and a flush after
/// every connect, so keys also move from the memtable into the runs.
#[test]
fn lookups_never_miss_a_key_moving_into_the_runs() {
    let policy = Policy {
        k0: 0,
        k0_hard: 0,
        ..Policy::tiny()
    };
    let race = race(policy, true, RaceFault::None, 800, Duration::from_secs(60));
    assert!(race.lookups > 1000, "{} lookups", race.lookups);
    assert_eq!(race.falses, 0, "of {} lookups", race.lookups);
}

/// Control: lookups that read the overlay last, as dcrd's do, miss a key
/// that moves to the memtable between the two reads.
#[test]
fn control_reading_the_overlay_last_misses_keys_in_mid_move() {
    let race = race(
        Policy::tiny(),
        false,
        RaceFault::OverlayLast,
        u32::MAX,
        Duration::from_secs(60),
    );
    assert!(race.falses > 0, "no false in {} lookups", race.lookups);
}

/// Control: a hand-over after the tip row is published leaves a window in
/// which a reader sees the tip and misses one of its block's keys.
#[test]
fn control_handing_keys_over_after_the_tip_is_published_misses_them() {
    let race = race(
        Policy::tiny(),
        false,
        RaceFault::HookAfterPublish,
        u32::MAX,
        Duration::from_secs(60),
    );
    assert!(race.falses > 0, "no false in {} lookups", race.lookups);
}

// ---------------------------------------------------------------------
// Merges, probes and the leaf size, over a store driven directly
// ---------------------------------------------------------------------

/// What each committed flush of a [`StoreRig`] reported.
#[derive(Debug, Clone, Copy)]
struct Flushed {
    participant: Option<dcroxide_database::ParticipantStats>,
}

/// A database with the index's bucket and an [`AddrStore`] registered
/// over it, under [`PKEY`]; keys go in as a connect's hook puts them.
struct StoreRig {
    _dir: TempDir,
    db: Arc<Database>,
    store: Arc<AddrStore>,
    bucket: [u8; 4],
    flushes: Arc<Mutex<Vec<Flushed>>>,
}

impl StoreRig {
    fn new(policy: Policy) -> StoreRig {
        let dir = TempDir::new().expect("tempdir");
        let flushes = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&flushes);
        let mut opts = Options::new(dir.path().join("db"), NET);
        opts.flush_observer = Some(Arc::new(
            move |obs: &dcroxide_database::FlushObservation| {
                seen.lock().expect("flushes").push(Flushed {
                    participant: obs.participant,
                });
            },
        ));
        let db = Arc::new(Database::create(&opts).expect("db"));
        let mut bucket = [0u8; 4];
        db.update(|tx| {
            bucket = tx.metadata().create_bucket(EXISTS_ADDR_INDEX_KEY)?.raw_id();
            Ok(())
        })
        .expect("bucket");
        db.flush().expect("flush the bucket");
        let store = Arc::new(AddrStore::new(fixed(policy)));
        store.install_fresh().expect("install");
        db.set_flush_participant(&bucket, Arc::clone(&store) as Arc<dyn FlushParticipant>)
            .expect("register");
        flushes.lock().expect("flushes").clear();
        StoreRig {
            _dir: dir,
            db,
            store,
            bucket,
            flushes,
        }
    }

    fn insert(&self, keys: Vec<Key>) {
        let part = self.store.partitioner();
        let mut cands: Vec<(u8, Key)> = keys.into_iter().map(|k| (part.of(&k), k)).collect();
        cands.sort_unstable();
        self.store.mem.insert_candidates(&cands);
    }

    fn flush(&self) {
        self.db.flush().expect("flush");
    }

    fn probe(&self, key: &Key, lvl: u8) -> bool {
        let part = self.store.partitioner();
        let tx = self.db.begin(false).expect("begin");
        let found = runs::probe(&tx, &part, &self.bucket, part.of(key), key, lvl).expect("probe");
        tx.rollback().expect("rollback");
        found
    }

    /// The flushes observed since the rig was built.
    fn flushed(&self) -> Vec<Flushed> {
        self.flushes.lock().expect("flushes").clone()
    }

    fn check(&self) -> LayoutCheck {
        check_layout(&self.db).expect("layout").expect("bucket")
    }

    fn rows(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let tx = self.db.begin(false).expect("begin");
        let rows = tx
            .try_scan_after(&self.bucket, None, usize::MAX)
            .expect("rows");
        tx.rollback().expect("rollback");
        rows
    }
}

/// The `n`th key of type `t` that [`PKEY`] files in partition `p`:
/// ascending in `(t, n)`, the bytes after `n` searched until the key
/// hashes into `p`.
fn key_in(p: u8, t: u8, n: u32) -> Key {
    let part = part();
    (0u32..)
        .map(|c| {
            let mut key = [0u8; 21];
            key[0] = t;
            key[1..5].copy_from_slice(&n.to_be_bytes());
            key[5..9].copy_from_slice(&c.to_be_bytes());
            key
        })
        .find(|key| part.of(key) == p)
        .expect("some key hashes into every partition")
}

/// Random keys of type `t`, exactly `per` in every partition.
fn full_partitions(rng: &mut SplitMix64, t: u8, per: usize) -> Vec<Key> {
    let part = part();
    let mut parts: Vec<Vec<Key>> = vec![Vec::new(); PARTITIONS];
    let mut short = PARTITIONS;
    while short > 0 {
        let mut key = random_key(rng);
        key[0] = t;
        let held = &mut parts[usize::from(part.of(&key))];
        if held.len() < per {
            held.push(key);
            if held.len() == per {
                short -= 1;
            }
        }
    }
    parts.concat()
}

/// The probe finds a key equal to a chunk's last key, misses keys below
/// the first chunk, above the last, between two chunks and in an empty
/// level, and never reads into the next level or partition.
#[test]
fn probes_find_chunk_ends_and_stop_at_level_and_partition_bounds() {
    let rig = StoreRig::new(Policy {
        k0: 0,
        k0_hard: 0,
        ..Policy::tiny()
    });
    // Partition 7: even numbers 2..=800, one base of 400 keys in three
    // near-equal chunks; partition 8 beside it.
    rig.insert((1..=400).map(|n| key_in(7, 0, n * 2)).collect());
    rig.insert((1..=50).map(|n| key_in(8, 0, n)).collect());
    rig.flush();
    let meta = rig.store.meta();
    assert_eq!((meta.d_keys[7], meta.b_keys[7]), (0, 400));
    assert_eq!(rig.check().run_rows, 3 + 1);
    // Chunks of 134, 133 and 133 keys end at 268, 534 and 800.
    for last in [268, 534, 800] {
        assert!(rig.probe(&key_in(7, 0, last), BASE), "chunk end {last}");
        assert!(!rig.probe(&key_in(7, 0, last + 1), BASE), "after {last}");
    }
    assert!(
        rig.probe(&key_in(7, 0, 270), BASE),
        "the next chunk's first"
    );
    assert!(rig.probe(&key_in(7, 0, 2), BASE), "the first key");
    assert!(!rig.probe(&key_in(7, 0, 1), BASE), "below the first chunk");
    assert!(!rig.probe(&key_in(7, 0, 801), BASE), "above the last chunk");
    assert!(
        !rig.probe(&key_in(7, 3, 2), BASE),
        "type 3 sorts after every type-0 chunk"
    );
    assert!(!rig.probe(&key_in(7, 0, 2), DELTA), "the empty delta level");
    assert!(
        !rig.probe(&key_in(6, 0, 2), BASE),
        "the empty partition before"
    );
    // A probe of 7 above its last chunk must not land in 8's rows.
    assert!(!rig.probe(&key_in(7, 255, 1), BASE));
    assert!(rig.probe(&key_in(8, 0, 1), BASE));
}

/// A delta rewrite while the delta fits its cap; a base rewrite once it
/// does not, which drops the duplicates between the two levels and the
/// memtable and empties the delta.
#[test]
fn a_base_rewrite_unites_both_levels_and_drops_duplicates() {
    let rig = StoreRig::new(Policy {
        k0: 0,
        k0_hard: 0,
        ..Policy::tiny()
    });
    let p = 1u8; // phi(1) = 0.5 + 97/256
    rig.insert((0..50).map(|n| key_in(p, 0, n)).collect());
    rig.flush();
    assert_eq!(rig.store.meta().b_keys[1], 50, "the first merge: a base");
    // dcap(1, 50) = phi(1) sqrt(2 * 50 * 1) = 8.79: a key fits the delta.
    rig.insert(vec![key_in(p, 0, 100)]);
    rig.flush();
    let meta = rig.store.meta();
    assert_eq!((meta.d_keys[1], meta.b_keys[1]), (1, 50), "a delta rewrite");
    // A duplicate of the base goes into the delta as well: a delta
    // rewrite never reads the base.
    rig.insert(vec![key_in(p, 0, 3), key_in(p, 0, 101)]);
    rig.flush();
    let meta = rig.store.meta();
    assert_eq!((meta.d_keys[1], meta.b_keys[1]), (3, 50));
    // Ten more with duplicates of both levels: past the cap, so the base
    // is rewritten as the union.
    let mut more: Vec<Key> = (200..207).map(|n| key_in(p, 0, n)).collect();
    more.extend([key_in(p, 0, 4), key_in(p, 0, 100), key_in(p, 0, 101)]);
    rig.insert(more);
    rig.flush();
    let meta = rig.store.meta();
    assert_eq!((meta.d_keys[1], meta.b_keys[1]), (0, 50 + 2 + 7));
    let check = rig.check();
    assert_eq!(check.runs.len(), 59);
    assert!(check.pending.is_empty() && check.journal_rows == 0);
}

/// One merge per flush once the budget is spent, unless the memtable is
/// over its hard bound; largest partition first, ties to the lowest.
#[test]
fn the_budget_defers_merges_unless_the_memtable_is_over_its_hard_bound() {
    let rig = StoreRig::new(Policy {
        k0: 0,
        k0_hard: 1000,
        budget_pages: 1,
        u_max: 1000,
        ..Policy::tiny()
    });
    let mut keys: Vec<Key> = (0..3).map(|n| key_in(9, 0, n)).collect();
    keys.extend((0..3).map(|n| key_in(4, 0, n)));
    keys.extend((0..5).map(|n| key_in(200, 0, n)));
    rig.insert(keys);
    rig.flush();
    assert_eq!(rig.store.mem.len(), 6, "only partition 200 merged");
    assert_eq!(rig.store.meta().b_keys[200], 5);
    // The next flush with a key to journal merges once more: 4, the
    // lower of the tie.
    rig.insert(vec![key_in(100, 0, 0)]);
    rig.flush();
    assert_eq!(rig.store.mem.len(), 4, "then 4, the lower of the tie");
    assert_eq!(rig.store.meta().b_keys[4], 3);
    // Over the hard bound, the budget does not stop the merges.
    let rig = StoreRig::new(Policy {
        k0: 0,
        k0_hard: 2,
        budget_pages: 1,
        u_max: 1000,
        ..Policy::tiny()
    });
    rig.insert((0..=255u8).map(|p| key_in(p, 0, 1)).collect());
    rig.flush();
    assert_eq!(rig.store.mem.len(), 2, "merged down to the hard bound");
}

/// A flush with nothing to journal does nothing, though the memtable is
/// over its target and the budget left work behind: no merge and no
/// commit.  So `Database::close` after the node's own shutdown flush, or
/// a flush straight after another, is not a second durable commit made
/// only to merge.
#[test]
fn a_flush_with_nothing_to_journal_commits_nothing() {
    let rig = StoreRig::new(Policy {
        k0: 0,
        k0_hard: 1000,
        budget_pages: 1,
        u_max: 1000,
        ..Policy::tiny()
    });
    let mut keys: Vec<Key> = (0..4).map(|n| key_in(30, 0, n)).collect();
    keys.extend((0..3).map(|n| key_in(31, 0, n)));
    rig.insert(keys);
    rig.flush();
    let flushed = rig.flushed();
    assert_eq!(flushed.len(), 1);
    assert_eq!(flushed[0].participant.expect("participant").merges, 1);
    assert_eq!(rig.store.mem.len(), 3, "partition 31 left over k0");
    rig.flush();
    rig.db.close().expect("close");
    assert_eq!(rig.flushed().len(), 1, "{:?}", rig.flushed());
    assert_eq!(rig.store.meta().jseq, 1);
    assert_eq!(rig.store.mem.len(), 3);
}

/// The journal keeps exactly the flushes a partition still pends from,
/// a restart reads back exactly the memtable, and a partition merged in a
/// flush has none of that flush's keys journaled: they are in its runs.
#[test]
fn the_journal_is_collected_below_the_oldest_pending_flush() {
    let rig = StoreRig::new(Policy {
        k0: 3,
        k0_hard: 3,
        budget_pages: 100,
        u_max: 1000,
        ..Policy::tiny()
    });
    let sorted = |mut keys: Vec<Key>| {
        keys.sort_unstable();
        keys
    };
    // Flush 1: two keys in 10, one in 11, under k0: nothing merges.
    rig.insert(vec![key_in(10, 0, 1), key_in(10, 0, 2), key_in(11, 0, 1)]);
    rig.flush();
    let check = rig.check();
    assert_eq!(
        (check.jseq, check.journal_rows, check.pending.len()),
        (1, 1, 3)
    );
    // Flush 2: more in 10 and 12; over k0, partition 10 merges, and 11
    // and 12 still pend.  10's new key goes straight into its run, so
    // flush 2 journals 12's key alone.
    rig.insert(vec![key_in(10, 0, 3), key_in(12, 0, 1)]);
    rig.flush();
    let meta = rig.store.meta();
    assert_eq!(meta.b_keys[10], 3);
    assert_eq!(
        (meta.pend_from[10], meta.pend_from[11], meta.pend_from[12]),
        (3, 0, 2)
    );
    assert_eq!(
        meta.pend_from[0], 3,
        "an empty partition pends from the next flush"
    );
    let check = rig.check();
    assert_eq!(check.journal_rows, 2, "flush 1's row holds 11's key");
    assert_eq!(check.journal_keys, 3 + 1, "10's flush-2 key unjournaled");
    assert_eq!(
        check.pending,
        sorted(vec![key_in(11, 0, 1), key_in(12, 0, 1)])
    );
    // Flush 3: 11 and 12 tie and 11, the lower, merges; 12 still pends
    // from flush 2, so flush 1's row goes and flushes 2 and 3 stay.
    rig.insert(vec![key_in(11, 0, 2), key_in(12, 0, 2)]);
    rig.flush();
    let meta = rig.store.meta();
    assert_eq!((meta.pend_from[11], meta.pend_from[12]), (4, 2));
    let check = rig.check();
    assert_eq!(check.journal_rows, 2);
    assert_eq!(
        check.pending,
        sorted(vec![key_in(12, 0, 1), key_in(12, 0, 2)])
    );
    // Flush 4: 12 merges, and every journal row goes.
    rig.insert(vec![key_in(12, 0, 3), key_in(12, 0, 4)]);
    rig.flush();
    let check = rig.check();
    assert_eq!(check.journal_rows, 0);
    assert!(check.pending.is_empty());
    assert_eq!(rig.store.meta().min_pend_from(), 5);
    assert_eq!(rig.store.mem.len(), 0);
}

/// The same inserts and flushes give byte-identical rows.
#[test]
fn merges_are_deterministic() {
    let run = |seed: u64| {
        let rig = StoreRig::new(Policy {
            k0: 30,
            k0_hard: 60,
            budget_pages: 2,
            u_max: 1000,
            ..Policy::tiny()
        });
        let mut rng = SplitMix64(seed);
        for _ in 0..40 {
            let keys: Vec<Key> = (0..rng.below(20) + 1)
                .map(|_| {
                    let p = rng.below(6) as u8;
                    random_key_in(&mut rng, p)
                })
                .collect();
            rig.insert(keys);
            if rng.below(2) == 0 {
                rig.flush();
            }
        }
        rig.flush();
        rig.check();
        rig.rows()
    };
    assert_eq!(run(5), run(5));
    assert_ne!(run(5), run(6));
}

/// redb pin: a chunk row of 192 keys fills one 4 KiB leaf, so 1,024 of
/// them take 1,024 single-page leaves.  A redb format change that spilled
/// them to two-page nodes would double the run bytes every estimate in
/// ADR-0011 rests on.
#[test]
fn a_full_chunk_row_fills_exactly_one_4_kib_leaf() {
    let rig = StoreRig::new(Policy {
        k0: 0,
        k0_hard: 0,
        ..Policy::tiny()
    });
    let before = rig.db.raw_stats().expect("stats");
    // Four full chunks in every partition's base.
    rig.insert(full_partitions(&mut SplitMix64(0x6c65_6166), 0, 4 * CHUNK));
    rig.flush();
    let check = rig.check();
    assert_eq!((check.run_rows, check.journal_rows), (1024, 0));
    let after = rig.db.raw_stats().expect("stats");
    assert_eq!(after.page_size, 4096);
    let leaves = after.leaf_pages - before.leaf_pages;
    assert!(
        (1024..1034).contains(&leaves),
        "{leaves} leaves for 1,024 chunk rows"
    );
    // Every chunk's node is a single page: nothing spilled.  One node
    // may take two: the meta row's 3,098 bytes share a leaf with the
    // bucket's small rows here, and redb rounds that leaf up rather than
    // split it.
    let slack = after.live_tree_bytes() - (after.leaf_pages + after.branch_pages) * after.page_size;
    assert!(
        slack <= after.page_size,
        "{slack} bytes past one page a node: {after:?}"
    );
}

/// A journal row of 192 keys fits one leaf as well, and a flush writes
/// its keys as full rows: two batches of 49,152 keys, 512 rows.
#[test]
fn a_full_journal_row_fills_one_leaf() {
    let rig = StoreRig::new(Policy {
        k0: usize::MAX,
        k0_hard: usize::MAX,
        ..Policy::tiny()
    });
    let before = rig.db.raw_stats().expect("stats");
    rig.insert(full_partitions(&mut SplitMix64(0x6a6f_7572), 1, 2 * CHUNK));
    rig.flush();
    let check = rig.check();
    assert_eq!((check.journal_rows, check.journal_keys), (512, 512 * CHUNK));
    let after = rig.db.raw_stats().expect("stats");
    let leaves = after.leaf_pages - before.leaf_pages;
    assert!(
        (512..522).contains(&leaves),
        "{leaves} leaves for 512 journal rows"
    );
    assert_eq!(
        after.live_tree_bytes(),
        (after.leaf_pages + after.branch_pages) * after.page_size
    );
}

// ---------------------------------------------------------------------
// Keys an adversary grinds, and restarts
// ---------------------------------------------------------------------

/// A random key whose first hash160 byte is 0: what an adversary grinds
/// for, in about 256 tries a key, to crowd a partition placed by that
/// byte.
fn ground_key(rng: &mut SplitMix64) -> Key {
    let mut key = random_key(rng);
    key[1] = 0;
    key
}

/// Blocks whose every key shares a first hash160 byte still spread over
/// every partition, so a flush's merges stay within the budget plus one
/// small merge, and no partition's runs outgrow the others'.  Placed by
/// that byte, every key would land in one partition, whose base rewrites
/// alone would write every key's page in each flush that merged it,
/// whatever the budget.
#[test]
fn keys_ground_to_one_hash160_byte_keep_each_flush_near_its_budget() {
    let policy = Policy {
        k0: 20_000,
        // Out of reach, so the budget is what stops every flush's merges.
        k0_hard: usize::MAX,
        budget_pages: 40,
        u_max: usize::MAX,
        ..Policy::tiny()
    };
    let rig = StoreRig::new(policy);
    let mut rng = SplitMix64(0x6772_696e_6401);
    for _ in 0..40 {
        rig.insert((0..4_000).map(|_| ground_key(&mut rng)).collect());
        rig.flush();
    }
    let mut most = 0u64;
    let mut merges = 0u64;
    for flushed in rig.flushed() {
        let stats = flushed.participant.expect("participant");
        // Each flush journals fewer keys than one batch: its journal
        // rows are its keys over 192, rounded up; and one meta row.
        let journal_rows = stats.keys_journaled.div_ceil(CHUNK as u64);
        most = most.max(stats.rows_put - journal_rows - 1);
        merges += stats.merges;
    }
    assert!(merges > 40, "{merges} merges");
    assert!(
        most <= 2 * policy.budget_pages as u64,
        "a flush wrote {most} run rows against a budget of {}",
        policy.budget_pages
    );
    let meta = rig.store.meta();
    let sizes = rig.store.mem.sizes();
    let held: Vec<u64> = (0..PARTITIONS)
        .map(|p| u64::from(meta.d_keys[p]) + u64::from(meta.b_keys[p]) + sizes[p] as u64)
        .collect();
    let mean = held.iter().sum::<u64>() / PARTITIONS as u64;
    let max = *held.iter().max().expect("partitions");
    assert!(
        max <= 2 * mean,
        "a partition holds {max} keys, the mean {mean}"
    );
    rig.check();
}

/// A stream of blocks mostly ground to one hash160 byte keeps the journal
/// a restart reads near the memtable's size.  Placed by that byte, the
/// crowded partition would win every merge, the others would never be
/// merged, and the journal below their oldest pending flush could never
/// be collected: it would grow by the crowd's keys at every flush.
#[test]
fn keys_ground_to_one_hash160_byte_leave_the_journal_collectable() {
    let policy = Policy {
        k0: 2_000,
        k0_hard: 3_000,
        budget_pages: 1_000_000,
        u_max: usize::MAX,
        ..Policy::tiny()
    };
    let rig = StoreRig::new(policy);
    let mut rng = SplitMix64(0x6772_696e_6402);
    let mut most = 0usize;
    for flush in 1..=300 {
        let mut keys: Vec<Key> = (0..500).map(|_| ground_key(&mut rng)).collect();
        keys.extend((0..5).map(|_| random_key(&mut rng)));
        rig.insert(keys);
        rig.flush();
        if flush % 25 == 0 {
            let check = rig.check();
            most = most.max(check.journal_keys);
            assert_eq!(check.pending.len(), rig.store.mem.len());
        }
    }
    assert!(
        most <= 4 * policy.k0_hard,
        "the journal reached {most} keys, against a memtable of at most {}",
        policy.k0_hard
    );
}

/// A restart reads each partition's journaled keys straight into the
/// vector the memtable keeps, without spare capacity, and they are exactly
/// the journal's pending keys.
#[test]
fn a_restart_loads_each_partition_in_place() {
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("db"), NET);
    let chain = TestChain::new(params());
    let policy = Policy {
        k0: 200,
        k0_hard: 300,
        budget_pages: 2,
        u_max: 100_000,
        ..Policy::tiny()
    };
    let mut rng = SplitMix64(0x6c6f_6164);
    {
        let db = Arc::new(Database::create(&opts).expect("create"));
        let mut subber = new_subber();
        let idx = open_index(&mut subber, &db, &chain, policy);
        for salt in 0..40u32 {
            let keys: Vec<Key> = (0..40).map(|_| random_key(&mut rng)).collect();
            connect(&chain, &mut subber, salt, &keys).expect("connect");
            if salt % 4 == 0 {
                db.flush().expect("flush");
            }
        }
        drop(idx);
        drop(subber);
        db.close().expect("close");
    }
    let db = Arc::new(Database::open(&opts).expect("reopen"));
    let pending = check_layout(&db).expect("layout").expect("bucket").pending;
    assert!(pending.len() > 200, "{} pending", pending.len());
    let mut subber = new_subber();
    let idx = open_index(&mut subber, &db, &chain, policy);
    let store = Arc::clone(idx.lock().expect("index").store());
    assert_eq!(store.mem.snapshot(), pending);
    for p in 0..PARTITIONS {
        assert_eq!(store.mem.spare_capacity(p), 0, "partition {p}");
    }
    drop(idx);
    drop(subber);
    db.close().expect("close");
}
