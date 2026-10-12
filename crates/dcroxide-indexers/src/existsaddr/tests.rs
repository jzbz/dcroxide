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
//! **The overlay copy.**  A connect queued for the daemon's index thread
//! brings a copy of the unconfirmed overlay made when it was queued.  It
//! must hand over exactly what the same connect hands over when it is
//! processed on the spot, and a copy no connect took must not linger.
//!
//! **The prepare step.**  A connect that brings that copy has the part of
//! its work that needs no transaction done before the subscriber claims
//! the database's writer.  It must leave the index, row for row, as the
//! same connect does when it does that work inside its transaction; the
//! result must serve its own connect only; and an update that fails after
//! the prepare must leave the index as it was.  A connect that brings no
//! copy must not be prepared: it takes the overlay as it stands once it
//! has the writer.  The index's lock must be held from a prepare until
//! its connect, and a flush that another thread's commit makes between
//! the two must lose no key.  The power cuts, the lookup races and the
//! hand-over control run both ways.
//!
//! **The key order.**  Keys are compared by an inline comparison of three
//! words, not by the array type's own; the two must be one order, in the
//! comparison itself and in every row a flush writes.
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
use crate::existsaddrindex::{EXISTS_ADDR_INDEX_KEY, ExistsAddrIndex};
use crate::subscriber::{CONNECT_NTFN, IndexNtfn, IndexSubscriber, NO_PREREQS};
use crate::{ChainQueryer, Indexer};

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

/// The connect notification of a block paying `keys` on `parent`.
fn connect_ntfn(parent: &Arc<MsgBlock>, salt: u32, keys: &[Key]) -> IndexNtfn {
    let scripts: Vec<Vec<u8>> = keys.iter().map(|k| script_of(k, params())).collect();
    IndexNtfn {
        ntfn_type: CONNECT_NTFN,
        block: block_on(parent, salt, vec![tx_paying(&scripts)]),
        parent: Arc::clone(parent),
        is_treasury_enabled: false,
    }
}

/// Connect a block paying `keys` on the chain's tip through `subber`.
fn connect(
    chain: &TestChain,
    subber: &mut IndexSubscriber,
    salt: u32,
    keys: &[Key],
) -> Result<(), crate::IdxError> {
    let ntfn = connect_ntfn(&chain.at(chain.tip().0), salt, keys);
    chain.add(&ntfn.block);
    subber.notify(&ntfn)
}

/// How a test hands a connect to the subscriber.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Delivery {
    /// On the spot: the connect copies the unconfirmed overlay itself and
    /// does all of its work inside its transaction.
    Inline,
    /// As the daemon's index thread does: with the copy of the overlay
    /// made when the connect was queued, which has the index prepare the
    /// connect before its transaction begins.
    Queued,
}

/// [`connect`], delivered as `delivery` says.
fn deliver(
    delivery: Delivery,
    chain: &TestChain,
    subber: &mut IndexSubscriber,
    unconfirmed: &crate::ExistsAddrUnconfirmed,
    salt: u32,
    keys: &[Key],
) -> Result<(), crate::IdxError> {
    match delivery {
        Delivery::Inline => connect(chain, subber, salt, keys),
        Delivery::Queued => unconfirmed.with_copy(unconfirmed.copy_for_connect(), || {
            connect(chain, subber, salt, keys)
        }),
    }
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
    /// How the run hands each connect to the subscriber.
    delivery: Delivery,
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
            delivery: Delivery::Inline,
        }
    }

    /// The same steps, each connect delivered as the daemon's index
    /// thread delivers it.
    fn queued(self) -> Script {
        Script {
            delivery: Delivery::Queued,
            ..self
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
    /// The connects that committed, and those of them that used work
    /// prepared before their transaction began.
    connects: usize,
    prepared: usize,
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
    let unconfirmed = idx.lock().expect("index").unconfirmed();
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
                let res = deliver(
                    script.delivery,
                    &chain,
                    &mut subber,
                    &unconfirmed,
                    salt,
                    keys,
                );
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
    let prepared = store.faults.prepared_connects.load(Ordering::SeqCst);
    drop(unconfirmed);
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
        connects: candidates.len() - 1,
        prepared,
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
    every_cut_keeps_index_and_tip_together(Script::random(&mut rng, 22));
}

/// The same run and the same cuts with every connect delivered as the
/// daemon's index thread delivers it, so that each is prepared before its
/// transaction begins.
#[test]
fn a_power_cut_at_every_storage_operation_of_prepared_connects_keeps_index_and_tip_together() {
    let mut rng = SplitMix64(0x7065_7263_7574_0001);
    every_cut_keeps_index_and_tip_together(Script::random(&mut rng, 22).queued());
}

fn every_cut_keeps_index_and_tip_together(script: Script) {
    let full = run(&script, None, true, Break::None);
    full.survived.expect("the uncut run");
    assert!(full.ops > 50, "the run made only {} operations", full.ops);
    // Every connect took the path the script names.
    let want = match script.delivery {
        Delivery::Inline => 0,
        Delivery::Queued => full.connects,
    };
    assert!(full.connects > 0);
    assert_eq!(full.prepared, want, "of {} connects", full.connects);
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
    let rng = SplitMix64::from_entropy("random_runs_cut_at_random_points");
    random_cuts_keep_index_and_tip_together(rng, Delivery::Inline);
}

/// The same with every connect prepared before its transaction begins.
#[test]
fn random_runs_of_prepared_connects_cut_at_random_points_keep_index_and_tip_together() {
    let rng = SplitMix64::from_entropy("random_runs_of_prepared_connects");
    random_cuts_keep_index_and_tip_together(rng, Delivery::Queued);
}

fn random_cuts_keep_index_and_tip_together(mut rng: SplitMix64, delivery: Delivery) {
    for round in 0..12 {
        let script = Script {
            delivery,
            ..Script::random(&mut rng, 30)
        };
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

/// What a race's readers share with its writer.
#[derive(Clone)]
struct Watched {
    /// Keys that must answer true from the moment they are pushed.
    always: Arc<RwLock<Vec<Key>>>,
    /// Keys of each height, pushed before the block connects.
    by_height: Arc<RwLock<Vec<Vec<Key>>>>,
    stop: Arc<AtomicBool>,
    falses: Arc<AtomicUsize>,
    lookups: Arc<AtomicUsize>,
}

impl Watched {
    fn new() -> Watched {
        Watched {
            always: Arc::new(RwLock::new(Vec::new())),
            by_height: Arc::new(RwLock::new(vec![Vec::new()])),
            stop: Arc::new(AtomicBool::new(false)),
            falses: Arc::new(AtomicUsize::new(0)),
            lookups: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Start `n` readers, each looking up, until told to stop, keys that
    /// must answer true: a key handed to the mempool, mostly one of the
    /// newest, and the keys of the tip it read first or of a block below.
    fn readers(&self, n: u64, query: &crate::ExistsAddrQuery) -> Vec<std::thread::JoinHandle<()>> {
        (0..n)
            .map(|t| {
                let (query, watched) = (query.clone(), self.clone());
                std::thread::spawn(move || watched.read(t, &query))
            })
            .collect()
    }

    /// Reader `t`'s lookups, until told to stop.
    fn read(&self, t: u64, query: &crate::ExistsAddrQuery) {
        let mut rng = SplitMix64(t);
        while !self.stop.load(Ordering::SeqCst) {
            // A mempool key, mostly one of the newest.
            let pick = {
                let always = self.always.read().expect("always");
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
            keys.extend(self.by_height.read().expect("heights")[height as usize].clone());
            for key in &keys {
                if !query
                    .exists_address(&address_of(key, params()))
                    .expect("lookup")
                {
                    self.falses.fetch_add(1, Ordering::SeqCst);
                }
            }
            let addrs: Vec<_> = keys.iter().map(|k| address_of(k, params())).collect();
            let found = query.exists_addresses(&addrs).expect("lookups");
            self.falses
                .fetch_add(found.iter().filter(|&&b| !b).count(), Ordering::SeqCst);
            self.lookups.fetch_add(keys.len() * 2, Ordering::SeqCst);
        }
    }

    /// Stop the readers and report what they saw.
    fn finish(&self, readers: Vec<std::thread::JoinHandle<()>>) -> Race {
        self.stop.store(true, Ordering::SeqCst);
        for reader in readers {
            reader.join().expect("reader");
        }
        Race {
            falses: self.falses.load(Ordering::SeqCst),
            lookups: self.lookups.load(Ordering::SeqCst),
        }
    }
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
    delivery: Delivery,
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

    let watched = Watched::new();
    let readers = watched.readers(8, &query);
    let Watched {
        always,
        by_height,
        falses,
        ..
    } = &watched;

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
        deliver(delivery, &chain, &mut subber, &unconfirmed, salt, &keys).expect("connect");
        if fault == RaceFault::HookAfterPublish {
            // Widen the window between the published tip and its keys.
            std::thread::sleep(Duration::from_micros(300));
            idx.lock().expect("index").run_deferred();
        }
        if flush_each {
            db.flush().expect("flush");
        }
    }
    watched.finish(readers)
}

/// No reader ever sees `false` for a key it must find while keys move
/// from the overlay to the memtable.
#[test]
fn lookups_never_miss_a_key_handed_from_the_mempool() {
    for delivery in [Delivery::Inline, Delivery::Queued] {
        let race = race(
            Policy::tiny(),
            delivery,
            false,
            RaceFault::None,
            1500,
            Duration::from_secs(60),
        );
        assert!(
            race.lookups > 1000,
            "{delivery:?}: {} lookups",
            race.lookups
        );
        assert_eq!(race.falses, 0, "{delivery:?}: of {} lookups", race.lookups);
    }
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
    for delivery in [Delivery::Inline, Delivery::Queued] {
        let race = race(
            policy,
            delivery,
            true,
            RaceFault::None,
            800,
            Duration::from_secs(60),
        );
        assert!(
            race.lookups > 1000,
            "{delivery:?}: {} lookups",
            race.lookups
        );
        assert_eq!(race.falses, 0, "{delivery:?}: of {} lookups", race.lookups);
    }
}

/// Control: lookups that read the overlay last, as dcrd's do, miss a key
/// that moves to the memtable between the two reads.
#[test]
fn control_reading_the_overlay_last_misses_keys_in_mid_move() {
    let race = race(
        Policy::tiny(),
        Delivery::Inline,
        false,
        RaceFault::OverlayLast,
        u32::MAX,
        Duration::from_secs(60),
    );
    assert!(race.falses > 0, "no false in {} lookups", race.lookups);
}

/// Control: a hand-over after the tip row is published leaves a window in
/// which a reader sees the tip and misses one of its block's keys, whether
/// the connect did its work inside its transaction or had it prepared.
#[test]
fn control_handing_keys_over_after_the_tip_is_published_misses_them() {
    for delivery in [Delivery::Inline, Delivery::Queued] {
        let race = race(
            Policy::tiny(),
            delivery,
            false,
            RaceFault::HookAfterPublish,
            u32::MAX,
            Duration::from_secs(60),
        );
        assert!(
            race.falses > 0,
            "{delivery:?}: no false in {} lookups",
            race.lookups
        );
    }
}

// ---------------------------------------------------------------------
// The overlay copy a queued connect brings
// ---------------------------------------------------------------------

/// The four keys of an [`overlay_run`]: `a` is in the mempool before the
/// first connect, `b` reaches it once that connect is on its way, and
/// `c` and `d` are paid by the first and the second block.
fn overlay_keys() -> [Key; 4] {
    let mut rng = SplitMix64(11);
    [0; 4].map(|_| random_key(&mut rng))
}

/// Two connects with the mempool transaction paying `b` arriving around
/// the first.  Inline (`queued` false), the first connect copies the
/// overlay itself and `b` arrives after it.  Queued, the copy is made
/// first (`copy_for_connect`), `b` arrives while the connect waits, and
/// the connect then runs under `with_copy`, as the daemon's index thread
/// runs it.
///
/// Returns the index's keys after the first connect, whether a lookup
/// then finds `b`, and the keys after the second connect.
fn overlay_run(queued: bool) -> (Vec<Key>, bool, Vec<Key>) {
    let dir = TempDir::new().expect("tempdir");
    let db = Arc::new(Database::create(&Options::new(dir.path().join("db"), NET)).expect("create"));
    let chain = TestChain::new(params());
    let mut subber = new_subber();
    let idx = open_index(&mut subber, &db, &chain, Policy::tiny());
    let unconfirmed = idx.lock().expect("index").unconfirmed();
    let query = idx.lock().expect("index").query();
    let [a, b, c, d] = overlay_keys();
    unconfirmed.add_unconfirmed_tx(&mempool_tx(&[a]));
    if queued {
        let copy = unconfirmed.copy_for_connect();
        // The pool admits `b` while the connect waits in the queue.
        unconfirmed.add_unconfirmed_tx(&mempool_tx(&[b]));
        unconfirmed
            .with_copy(copy, || connect(&chain, &mut subber, 1, &[c]))
            .expect("connect");
    } else {
        connect(&chain, &mut subber, 1, &[c]).expect("connect");
        unconfirmed.add_unconfirmed_tx(&mempool_tx(&[b]));
    }
    let first = idx.lock().expect("index").logical_keys().expect("keys");
    let b_seen = query
        .exists_address(&address_of(&b, params()))
        .expect("lookup");
    connect(&chain, &mut subber, 2, &[d]).expect("connect");
    let second = idx.lock().expect("index").logical_keys().expect("keys");
    (first, b_seen, second)
}

/// A connect processed after it was queued hands over the overlay as it
/// stood when it was queued, which is what the same connect processed on
/// the spot hands over: a key the pool adds in between is not persisted
/// with that block, is still answered from the overlay, and goes with the
/// next connect.  A queued connect that read the overlay as it stands
/// when it is processed would persist `b` with the first block.
#[test]
fn a_queued_connect_hands_over_the_overlay_as_copied_when_it_was_queued() {
    let [a, b, c, d] = overlay_keys();
    let inline = overlay_run(false);
    let queued = overlay_run(true);
    assert_eq!(queued, inline, "queued against inline");

    let (first, b_seen, second) = queued;
    assert!(first.contains(&a), "the copied mempool key");
    assert!(first.contains(&c), "the first block's key");
    assert!(
        !first.contains(&b),
        "a key added after the connect was queued went with it"
    );
    assert!(b_seen, "the later key is still answered from the overlay");
    for key in [a, b, c, d] {
        assert!(second.contains(&key), "{} after the second", hex(&key));
    }
}

/// A copy no connect took is withdrawn when `with_copy` returns, whether
/// the update inside never reached the index or failed before the index's
/// connect: the next connect copies the overlay as it stands, with the
/// keys of the dropped copy still in it.  A copy left installed would be
/// taken by that connect, which would then leave out `b`.
#[test]
fn a_copy_no_connect_took_is_withdrawn() {
    let dir = TempDir::new().expect("tempdir");
    let db = Arc::new(Database::create(&Options::new(dir.path().join("db"), NET)).expect("create"));
    let chain = TestChain::new(params());
    let mut subber = new_subber();
    let idx = open_index(&mut subber, &db, &chain, Policy::tiny());
    let unconfirmed = idx.lock().expect("index").unconfirmed();
    let [a, b, c, d] = overlay_keys();
    let keys = || idx.lock().expect("index").logical_keys().expect("keys");

    // No update at all.
    unconfirmed.add_unconfirmed_tx(&mempool_tx(&[a]));
    unconfirmed.with_copy(unconfirmed.copy_for_connect(), || ());
    unconfirmed.add_unconfirmed_tx(&mempool_tx(&[b]));
    connect(&chain, &mut subber, 1, &[]).expect("connect");
    assert!(
        keys().contains(&a) && keys().contains(&b),
        "after no update"
    );

    // An update the subscriber refuses before the index's connect: a
    // block two above the index tip.
    unconfirmed.add_unconfirmed_tx(&mempool_tx(&[c]));
    let tip = chain.at(chain.tip().0);
    let skipping = block_on(&block_on(&tip, 7, Vec::new()), 8, Vec::new());
    let refused = unconfirmed.with_copy(unconfirmed.copy_for_connect(), || {
        subber.notify(&IndexNtfn {
            ntfn_type: CONNECT_NTFN,
            block: skipping,
            parent: Arc::clone(&tip),
            is_treasury_enabled: false,
        })
    });
    assert!(refused.is_err(), "the skipped height is refused");
    assert!(!keys().contains(&c), "a refused update handed keys over");
    unconfirmed.add_unconfirmed_tx(&mempool_tx(&[d]));
    connect(&chain, &mut subber, 2, &[]).expect("connect");
    assert!(
        keys().contains(&c) && keys().contains(&d),
        "after a refusal"
    );
}

// ---------------------------------------------------------------------
// The prepare step of a queued connect
// ---------------------------------------------------------------------

/// An index at genesis over its own database and chain, with the handles
/// the prepare tests need.
struct Fixture {
    _dir: TempDir,
    db: Arc<Database>,
    chain: Arc<TestChain>,
    subber: IndexSubscriber,
    idx: Arc<Mutex<ExistsAddrIndex>>,
    store: Arc<AddrStore>,
    unconfirmed: crate::ExistsAddrUnconfirmed,
    query: crate::ExistsAddrQuery,
}

/// What a [`Fixture`]'s index holds, for comparing two of them: the tip
/// row, every key, the memtable's keys, and every row of the bucket.
type IndexState = (Vec<u8>, Vec<Key>, Vec<Key>, Vec<(Vec<u8>, Vec<u8>)>);

impl Fixture {
    fn new(policy: Policy) -> Fixture {
        let dir = TempDir::new().expect("tempdir");
        let db =
            Arc::new(Database::create(&Options::new(dir.path().join("db"), NET)).expect("create"));
        let chain = TestChain::new(params());
        let mut subber = new_subber();
        let idx = open_index(&mut subber, &db, &chain, policy);
        let (store, unconfirmed, query) = {
            let idx = idx.lock().expect("index");
            (Arc::clone(idx.store()), idx.unconfirmed(), idx.query())
        };
        Fixture {
            _dir: dir,
            db,
            chain,
            subber,
            idx,
            store,
            unconfirmed,
            query,
        }
    }

    /// Connects prepared before their transaction, and connects that used
    /// what was prepared for them.
    fn prepared(&self) -> (usize, usize) {
        (
            self.store.faults.prepares.load(Ordering::SeqCst),
            self.store.faults.prepared_connects.load(Ordering::SeqCst),
        )
    }

    /// The connect notification of a block paying `keys` on the tip; the
    /// block is not added to the chain.
    fn next(&self, salt: u32, keys: &[Key]) -> IndexNtfn {
        connect_ntfn(&self.chain.at(self.chain.tip().0), salt, keys)
    }

    fn deliver(&mut self, delivery: Delivery, salt: u32, keys: &[Key]) {
        deliver(
            delivery,
            &self.chain,
            &mut self.subber,
            &self.unconfirmed,
            salt,
            keys,
        )
        .expect("connect");
    }

    /// What the index prepares for `ntfn` when it arrives as a queued
    /// connect does, with the copy of the overlay as it stands.
    fn prepare(&self, ntfn: &IndexNtfn) -> Option<crate::PreparedNtfn> {
        self.unconfirmed
            .with_copy(self.unconfirmed.copy_for_connect(), || {
                self.idx.lock().expect("index").prepare_notification(ntfn)
            })
    }

    /// Process `ntfn` with `prepared` in a transaction of the test's own,
    /// outside the subscriber, and commit it.
    fn apply(&self, ntfn: &IndexNtfn, prepared: Option<crate::PreparedNtfn>) {
        let tx = self.db.begin(true).expect("begin");
        self.idx
            .lock()
            .expect("index")
            .process_prepared_notification(&tx, ntfn, prepared)
            .expect("process");
        tx.commit().expect("commit");
    }

    fn exists(&self, key: &Key) -> bool {
        self.query
            .exists_address(&address_of(key, params()))
            .expect("lookup")
    }

    fn tip_row(&self) -> Vec<u8> {
        let tx = self.db.begin(false).expect("begin");
        let row = tx
            .metadata()
            .bucket(b"idxtips")
            .and_then(|b| b.get(EXISTS_ADDR_INDEX_KEY))
            .expect("tip row");
        tx.rollback().expect("rollback");
        row
    }

    /// The tip row a connect of `block` writes: its hash, then its height.
    fn tip_row_of(block: &MsgBlock) -> Vec<u8> {
        let mut row = block.header.block_hash().0.to_vec();
        row.extend_from_slice(&block.header.height.to_le_bytes());
        row
    }

    fn state(&self) -> IndexState {
        let tx = self.db.begin(false).expect("begin");
        let bucket = tx
            .metadata()
            .bucket(EXISTS_ADDR_INDEX_KEY)
            .expect("bucket")
            .raw_id();
        let rows = tx.try_scan_after(&bucket, None, usize::MAX).expect("rows");
        tx.rollback().expect("rollback");
        let idx = self.idx.lock().expect("index");
        (
            self.tip_row(),
            idx.logical_keys().expect("keys"),
            idx.memtable_keys(),
            rows,
        )
    }
}

fn sorted(mut keys: Vec<Key>) -> Vec<Key> {
    keys.sort_unstable();
    keys
}

/// A queued connect's index work is done while another transaction still
/// holds the database's writer, and so before the subscriber has it: the
/// prepare comes between taking the index's lock and the wait for the
/// writer.  Nothing is handed over until the writer is free.
///
/// The same stall shows the lock order the subscriber keeps: the index's
/// lock is held while the update waits for the writer.
#[test]
fn a_queued_connect_is_prepared_before_the_subscriber_claims_the_writer() {
    let mut f = Fixture::new(Policy::tiny());
    let mut rng = SplitMix64(0x7072_6570_0001);
    let keys: Vec<Key> = (0..5).map(|_| random_key(&mut rng)).collect();
    let pooled = random_key(&mut rng);
    f.unconfirmed.add_unconfirmed_tx(&mempool_tx(&[pooled]));

    let held = f.db.begin(true).expect("begin");
    let (chain, subber, unconfirmed) = (&f.chain, &mut f.subber, &f.unconfirmed);
    let (store, idx) = (&f.store, &f.idx);
    let (prepares, index_locked, handed, connected) = std::thread::scope(|s| {
        let updater = s.spawn(|| deliver(Delivery::Queued, chain, subber, unconfirmed, 1, &keys));
        let deadline = Instant::now() + Duration::from_secs(20);
        while store.faults.prepares.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        let prepares = store.faults.prepares.load(Ordering::SeqCst);
        let index_locked = matches!(idx.try_lock(), Err(std::sync::TryLockError::WouldBlock));
        let handed = store.mem.len();
        // Released whatever was seen, so the updater always finishes.
        held.rollback().expect("rollback");
        (
            prepares,
            index_locked,
            handed,
            updater.join().expect("updater"),
        )
    });
    assert_eq!(
        prepares, 1,
        "the connect was not prepared while another transaction held the writer"
    );
    assert!(
        index_locked,
        "the update waited for the writer without the index's lock"
    );
    assert_eq!(handed, 0, "keys were handed over outside a commit");
    connected.expect("connect");
    assert_eq!(f.prepared(), (1, 1));
    let mut want = keys.clone();
    want.push(pooled);
    assert_eq!(f.store.mem.snapshot(), sorted(want));
}

/// A connect that brings no copy of the overlay is not prepared.  It
/// copies the overlay as it stands once it has the writer, inside its
/// transaction, as dcrd's connect drains the map inside its own
/// (`existsaddrindex.go:451-456`): a key the pool adds while the update
/// waits for the writer goes with this block.  Prepared ahead of that
/// wait, the connect would have read the overlay without the key and
/// left it for the next block.
#[test]
fn a_connect_with_no_copy_takes_the_overlay_once_it_has_the_writer() {
    let mut f = Fixture::new(Policy::tiny());
    let mut rng = SplitMix64(0x7072_6570_0006);
    let keys: Vec<Key> = (0..3).map(|_| random_key(&mut rng)).collect();
    let [pooled, late] = [0; 2].map(|_| random_key(&mut rng));
    f.unconfirmed.add_unconfirmed_tx(&mempool_tx(&[pooled]));

    let held = f.db.begin(true).expect("begin");
    let (chain, subber, unconfirmed) = (&f.chain, &mut f.subber, &f.unconfirmed);
    let idx = &f.idx;
    let connected = std::thread::scope(|s| {
        let updater = s.spawn(|| deliver(Delivery::Inline, chain, subber, unconfirmed, 1, &keys));
        // The update takes the index's lock and then waits for the
        // writer.  The pause is for a connect that reads the overlay
        // ahead of that wait: it has done so before the pool's key
        // arrives.  One that reads it inside its transaction cannot
        // have, however long this takes.
        let deadline = Instant::now() + Duration::from_secs(20);
        while !matches!(idx.try_lock(), Err(std::sync::TryLockError::WouldBlock))
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(1));
        }
        std::thread::sleep(Duration::from_millis(300));
        unconfirmed.add_unconfirmed_tx(&mempool_tx(&[late]));
        held.rollback().expect("rollback");
        updater.join().expect("updater")
    });
    connected.expect("connect");
    assert_eq!(f.prepared(), (0, 0));
    let mut want = keys.clone();
    want.extend([pooled, late]);
    assert_eq!(
        f.store.mem.snapshot(),
        sorted(want),
        "the connect did not hand over the overlay as it stood when it had the writer"
    );
}

/// The index's lock is held without a break from a connect's prepare
/// until that connect has used the result, which is what the prepare's
/// filter rests on: whenever another thread finds the lock free, every
/// connect that was prepared has been made.
///
/// A race.  A subscriber that let the lock go between the two is caught
/// when the watcher gets the lock in that gap, which over these connects
/// it does many times; one that holds it cannot fail.
#[test]
fn the_index_lock_is_held_from_a_prepare_until_its_connect() {
    let mut f = Fixture::new(Policy::tiny());
    let mut rng = SplitMix64(0x7072_6570_0007);
    let stop = AtomicBool::new(false);
    let (chain, subber, unconfirmed) = (&f.chain, &mut f.subber, &f.unconfirmed);
    let (store, idx) = (&f.store, &f.idx);
    let (connected, held, between) = std::thread::scope(|s| {
        let watcher = s.spawn(|| {
            let (mut held, mut between) = (0u64, 0u64);
            while !stop.load(Ordering::SeqCst) {
                if let Ok(_guard) = idx.try_lock() {
                    held += 1;
                    let prepares = store.faults.prepares.load(Ordering::SeqCst);
                    let used = store.faults.prepared_connects.load(Ordering::SeqCst);
                    between += u64::from(prepares != used);
                }
                std::hint::spin_loop();
            }
            (held, between)
        });
        let connected = (1..=4000u32).try_for_each(|salt| {
            let keys = [random_key(&mut rng)];
            deliver(Delivery::Queued, chain, subber, unconfirmed, salt, &keys)
        });
        stop.store(true, Ordering::SeqCst);
        let (held, between) = watcher.join().expect("watcher");
        (connected, held, between)
    });
    connected.expect("connect");
    assert_eq!(f.prepared(), (4000, 4000));
    assert!(held > 1000, "the watcher held the lock only {held} times");
    assert_eq!(
        between, 0,
        "the index's lock was free between a prepare and its connect, {between} times of {held}"
    );
}

/// The same blocks, mempool transactions and flushes leave three indexes
/// identical after every step, row for row: one whose connects are queued
/// and so prepared before their transactions, one whose connects go
/// through the subscriber on the spot, and one whose connects are
/// processed in the test's own transactions, outside the subscriber.  A
/// third of each block's keys were seen before, so the filter leaves keys
/// out on every path.
#[test]
fn a_prepared_connect_leaves_the_index_as_a_connect_inside_its_transaction_does() {
    let mut rng = SplitMix64(0x7072_6570_0002);
    let mut queued = Fixture::new(fixed(Policy::tiny()));
    let mut inline = Fixture::new(fixed(Policy::tiny()));
    let direct = Fixture::new(fixed(Policy::tiny()));
    let mut seen: Vec<Key> = Vec::new();
    let mut connects = 0usize;
    let mut flushed_rows = 0usize;
    for step in 0..150u32 {
        match rng.below(6) {
            0 => {
                let keys = [random_key(&mut rng), random_key(&mut rng)];
                for f in [&queued, &inline, &direct] {
                    f.unconfirmed.add_unconfirmed_tx(&mempool_tx(&keys));
                }
                seen.extend(keys);
            }
            1 => {
                for f in [&queued, &inline, &direct] {
                    f.db.flush().expect("flush");
                }
            }
            _ => {
                let keys: Vec<Key> = (0..1 + rng.below(10))
                    .map(|_| {
                        if !seen.is_empty() && rng.below(3) == 0 {
                            seen[rng.below(seen.len() as u64) as usize]
                        } else {
                            random_key(&mut rng)
                        }
                    })
                    .collect();
                queued.deliver(Delivery::Queued, step, &keys);
                inline.deliver(Delivery::Inline, step, &keys);
                let ntfn = direct.next(step, &keys);
                direct.chain.add(&ntfn.block);
                direct.apply(&ntfn, None);
                seen.extend(keys);
                connects += 1;
            }
        }
        let want = direct.state();
        assert_eq!(queued.state(), want, "step {step}: queued against direct");
        assert_eq!(inline.state(), want, "step {step}: inline against direct");
        flushed_rows = flushed_rows.max(want.3.len());
    }
    assert!(connects > 50, "{connects} connects");
    assert!(
        flushed_rows > 10,
        "the flushes wrote only {flushed_rows} rows"
    );
    // Each index took the path it stands for.
    assert_eq!(queued.prepared(), (connects, connects));
    assert_eq!(inline.prepared(), (0, 0));
    assert_eq!(direct.prepared(), (0, 0));
    for f in [&queued, &inline, &direct] {
        f.db.flush().expect("flush");
        check_layout(&f.db).expect("layout").expect("bucket");
    }
    assert_eq!(queued.state(), direct.state());
    assert_eq!(inline.state(), direct.state());
}

/// What was prepared for one connect serves that connect only.  Handed
/// to the connect of another block, to a disconnect of its own block, or
/// to an index it is not from, it is dropped whole, the overlay copy in
/// it included, and the work is done inside the transaction; the keys
/// copied for it stay in the overlay.
#[test]
fn what_was_prepared_for_one_connect_is_not_used_for_another_notification() {
    let mut f = Fixture::new(Policy::tiny());
    let mut rng = SplitMix64(0x7072_6570_0003);
    let [kx, ky, kz, pooled, added, later] = [0; 6].map(|_| random_key(&mut rng));

    // Two blocks on the genesis block.  The index prepares the connect of
    // one; the other's connect is handed the result.
    f.unconfirmed.add_unconfirmed_tx(&mempool_tx(&[pooled]));
    let x = f.next(1, &[kx]);
    let y = f.next(2, &[ky]);
    let for_x = f.prepare(&x);
    assert!(for_x.is_some(), "a queued connect is prepared");
    assert_eq!(f.prepared(), (1, 0));
    // The pool adds a key after the copy in that result was made.
    f.unconfirmed.add_unconfirmed_tx(&mempool_tx(&[added]));
    f.chain.add(&y.block);
    f.apply(&y, for_x);
    assert_eq!(f.prepared(), (1, 0), "another block's result was used");
    assert_eq!(f.tip_row(), Fixture::tip_row_of(&y.block));
    // The connect of `y` did its own work: its key, and the overlay as it
    // stands now, the later key with it, since the copy went with the
    // result it did not use.
    assert_eq!(f.store.mem.snapshot(), sorted(vec![ky, pooled, added]));
    assert!(!f.exists(&kx), "the other block's key was handed over");

    // A connect's result handed to the disconnect of that same block,
    // whose notification holds the same allocation: the tip moves back
    // and nothing else changes.
    f.deliver(Delivery::Queued, 3, &[kz]);
    assert_eq!(f.prepared(), (2, 1));
    let z = IndexNtfn {
        ntfn_type: CONNECT_NTFN,
        block: f.chain.at(2),
        parent: f.chain.at(1),
        is_treasury_enabled: false,
    };
    f.unconfirmed.add_unconfirmed_tx(&mempool_tx(&[later]));
    let for_z = f.prepare(&z);
    assert_eq!(f.prepared(), (3, 1));
    let before = f.store.mem.snapshot();
    f.apply(
        &IndexNtfn {
            ntfn_type: crate::DISCONNECT_NTFN,
            ..z.clone()
        },
        for_z,
    );
    assert_eq!(f.prepared(), (3, 1), "a disconnect used a connect's result");
    assert_eq!(f.tip_row(), Fixture::tip_row_of(&y.block));
    assert_eq!(f.store.mem.snapshot(), before, "a disconnect handed keys");
    assert!(f.exists(&later), "the copied key left the overlay");

    // A disconnect that arrives with a copy installed prepares nothing.
    assert!(
        f.prepare(&IndexNtfn {
            ntfn_type: crate::DISCONNECT_NTFN,
            ..z.clone()
        })
        .is_none()
    );
    assert_eq!(f.prepared(), (3, 1));

    // Something that is not this index's is dropped, and the connect does
    // its work inside the transaction: the key the pool added goes now.
    f.apply(&z, Some(Box::new(7u32)));
    assert_eq!(f.prepared(), (3, 1));
    assert_eq!(f.tip_row(), Fixture::tip_row_of(&z.block));
    assert_eq!(
        f.store.mem.snapshot(),
        sorted(vec![ky, kz, pooled, added, later])
    );

    // A connect that copies the overlay itself prepares nothing.
    let w = f.next(4, &[kx]);
    assert!(
        f.idx
            .lock()
            .expect("index")
            .prepare_notification(&w)
            .is_none(),
        "a connect with no copy installed was prepared"
    );
    assert_eq!(f.prepared(), (3, 1));
}

/// An update that fails after its connect was prepared leaves the index
/// as it was: the memtable, the tip and the overlay, whose copied keys go
/// with the next connect.  Three ways to fail: the transaction is rolled
/// back, its commit fails, and the transaction never begins.
#[test]
fn an_update_that_fails_after_the_prepare_leaves_the_index_as_it_was() {
    let mut f = Fixture::new(Policy::tiny());
    let mut rng = SplitMix64(0x7072_6570_0004);
    // More keys than `u_max`, so the next commit asks for a flush.
    let first: Vec<Key> = (0..10).map(|_| random_key(&mut rng)).collect();
    let [pooled, fresh] = [0; 2].map(|_| random_key(&mut rng));
    f.deliver(Delivery::Queued, 1, &first);
    f.unconfirmed.add_unconfirmed_tx(&mempool_tx(&[pooled]));
    let memtable = f.store.mem.snapshot();
    let tip = f.tip_row();
    let unchanged = |f: &Fixture, what: &str| {
        assert_eq!(f.store.mem.snapshot(), memtable, "{what}: the memtable");
        assert_eq!(f.tip_row(), tip, "{what}: the tip");
        assert!(f.exists(&pooled), "{what}: the copied key left the overlay");
        assert!(!f.exists(&fresh), "{what}: the block's key is visible");
    };

    // Rolled back, after the connect used what was prepared.
    let ntfn = f.next(2, &[fresh, first[0]]);
    let prepared = f.prepare(&ntfn);
    assert_eq!(f.prepared(), (2, 1));
    {
        let tx = f.db.begin(true).expect("begin");
        f.idx
            .lock()
            .expect("index")
            .process_prepared_notification(&tx, &ntfn, prepared)
            .expect("connect");
        tx.rollback().expect("rollback");
    }
    assert_eq!(f.prepared(), (2, 2));
    unchanged(&f, "a rollback");

    // A commit whose own flush fails: the hook never runs.
    f.store.faults.fail_contribute.store(true, Ordering::SeqCst);
    let failed = deliver(
        Delivery::Queued,
        &f.chain,
        &mut f.subber,
        &f.unconfirmed,
        2,
        &[fresh, first[0]],
    );
    let err = failed.expect_err("the commit's flush must fail");
    assert!(
        err.to_string().contains("injected contribute failure"),
        "{err}"
    );
    assert_eq!(f.prepared(), (3, 3));
    assert!(f.db.is_fatal(), "the store latched");
    f.chain.remove_tip();
    unchanged(&f, "a failed commit");

    // The store is latched, so the next update is prepared and then
    // refused its transaction; what was prepared is dropped.
    let refused = deliver(
        Delivery::Queued,
        &f.chain,
        &mut f.subber,
        &f.unconfirmed,
        2,
        &[fresh, first[0]],
    );
    assert!(refused.is_err(), "a transaction began on a latched store");
    assert_eq!(f.prepared(), (4, 3), "prepared, and never used");
    f.chain.remove_tip();
    unchanged(&f, "a refused transaction");
}

/// Nothing of a connect's prepared work outlives its update.  The same
/// notification, the very block allocation the result was made for,
/// delivered again after its first update rolled back and with nothing
/// prepared, is done afresh inside its transaction: it reads the overlay
/// as it stands by then.
#[test]
fn a_connect_delivered_again_after_its_update_rolled_back_starts_afresh() {
    let f = Fixture::new(Policy::tiny());
    let mut rng = SplitMix64(0x7072_6570_0008);
    let [key, pooled, late] = [0; 3].map(|_| random_key(&mut rng));
    f.unconfirmed.add_unconfirmed_tx(&mempool_tx(&[pooled]));
    let ntfn = f.next(1, &[key]);
    let prepared = f.prepare(&ntfn);
    {
        let tx = f.db.begin(true).expect("begin");
        f.idx
            .lock()
            .expect("index")
            .process_prepared_notification(&tx, &ntfn, prepared)
            .expect("connect");
        tx.rollback().expect("rollback");
    }
    assert_eq!(f.prepared(), (1, 1));
    assert_eq!(f.store.mem.len(), 0, "a rolled-back connect handed keys");

    // The pool adds a key, and the notification arrives again.
    f.unconfirmed.add_unconfirmed_tx(&mempool_tx(&[late]));
    f.chain.add(&ntfn.block);
    f.apply(&ntfn, None);
    assert_eq!(f.prepared(), (1, 1), "a result outlived its update");
    assert_eq!(f.tip_row(), Fixture::tip_row_of(&ntfn.block));
    assert_eq!(f.store.mem.snapshot(), sorted(vec![key, pooled, late]));
}

/// What was prepared stays good across a flush and across another
/// connect.  A flush between the prepare and the transaction merges a
/// partition whose key the filter left out: the key is in a run by then,
/// and is not handed over again.  A connect outside the subscriber hands
/// over one of the keys the filter kept: the hook finds it held and
/// skips it.  The index holds every key once, and a restart loads the
/// same.
///
/// The connect that filters inside its transaction, after the same flush,
/// hands the merged key over again, as a duplicate of the run's.  That is
/// the one difference between the two, and the keys the index holds are
/// the same.
#[test]
fn what_was_prepared_stays_good_across_a_flush_and_another_connect() {
    // Everything merges at every flush, and no commit asks for one.
    let policy = fixed(Policy {
        k0: 0,
        k0_hard: 0,
        u_max: 1000,
        ..Policy::tiny()
    });
    let mut rng = SplitMix64(0x7072_6570_0005);
    let [held, other, fresh, raced, pooled] = [0; 5].map(|_| random_key(&mut rng));
    let run = |prepare_first: bool| {
        let mut f = Fixture::new(policy);
        f.deliver(Delivery::Inline, 1, &[held, other]);
        f.unconfirmed.add_unconfirmed_tx(&mempool_tx(&[pooled]));
        let ntfn = f.next(2, &[held, fresh, raced]);
        let prepared = prepare_first.then(|| f.prepare(&ntfn).expect("prepared"));
        // The flush moves `held` and `other` into their runs.
        f.db.flush().expect("flush");
        assert_eq!(f.store.mem.len(), 0, "the flush merged everything");
        // A sibling connected outside the subscriber hands `raced` over.
        let sibling = f.next(3, &[raced]);
        f.apply(&sibling, None);
        assert_eq!(f.store.mem.snapshot(), sorted(vec![raced, pooled]));

        f.chain.add(&ntfn.block);
        f.apply(&ntfn, prepared);
        assert_eq!(
            f.prepared(),
            (usize::from(prepare_first), usize::from(prepare_first))
        );
        assert_eq!(f.tip_row(), Fixture::tip_row_of(&ntfn.block));
        let memtable = f.store.mem.snapshot();
        for key in [held, other, fresh, raced, pooled] {
            assert!(f.exists(&key), "{} is missing", hex(&key));
        }
        let keys = f.idx.lock().expect("index").logical_keys().expect("keys");
        assert_eq!(keys, sorted(vec![held, other, fresh, raced, pooled]));
        // Durable, and the same after a restart.
        f.db.flush().expect("flush");
        check_layout(&f.db).expect("layout").expect("bucket");
        let Fixture {
            _dir: dir,
            db,
            chain,
            subber,
            idx,
            store,
            unconfirmed,
            query,
        } = f;
        drop((subber, idx, store, unconfirmed, query));
        db.close().expect("close");
        drop(db);
        let db =
            Arc::new(Database::open(&Options::new(dir.path().join("db"), NET)).expect("reopen"));
        let mut subber = new_subber();
        let idx = open_index(&mut subber, &db, &chain, policy);
        let reopened = idx.lock().expect("index").logical_keys().expect("keys");
        assert_eq!(reopened, keys, "after a restart");
        drop(idx);
        drop(subber);
        db.close().expect("close");
        memtable
    };
    // Prepared before the flush: `held` was left out as held and is in
    // its run; `raced` is held once.
    assert_eq!(run(true), sorted(vec![fresh, raced, pooled]));
    // Filtered inside the transaction, after the flush: `held` again.
    assert_eq!(run(false), sorted(vec![held, fresh, raced, pooled]));
}

/// Another thread's commit flushes between a queued connect's prepare and
/// its transaction, at every connect, while readers look keys up.
///
/// The test's own transaction holds the writer until the connect has
/// been prepared, and its commit then runs the flush that the keys of the
/// connect before ask for, which under `k0` = 0 merges every partition.
/// So each key the prepare left out as held, half of every block's, is in
/// a run and out of the memtable by the time the connect's hook runs.  No
/// lookup misses a key, each connect hands over exactly the keys its
/// prepare kept, and the index ends with every key once, in memory and on
/// disk.
#[test]
fn a_flush_between_a_prepare_and_its_transaction_loses_no_key() {
    const CONNECTS: usize = 300;
    // Everything merges at every flush, and a commit asks for one as soon
    // as a key is unjournaled.
    let policy = fixed(Policy {
        k0: 0,
        k0_hard: 0,
        u_max: 1,
        ..Policy::tiny()
    });
    let mut f = Fixture::new(policy);
    let mut rng = SplitMix64(0x7072_6570_0009);
    let watched = Watched::new();
    let readers = watched.readers(4, &f.query);
    let mut all: BTreeSet<Key> = BTreeSet::new();

    // A first block, for the memtable to hold keys at the first prepare.
    let first: Vec<Key> = (0..6).map(|_| random_key(&mut rng)).collect();
    watched
        .by_height
        .write()
        .expect("heights")
        .push(first.clone());
    f.deliver(Delivery::Inline, 0, &first);
    all.extend(first);

    let mut left_out = 0usize;
    for n in 1..=CONNECTS {
        // Half of the block's keys are in the memtable, handed over by
        // the connect before, and half are new; every third block finds
        // two keys in the mempool as well.
        let held = f.store.mem.snapshot();
        assert!(!held.is_empty(), "connect {n}: nothing is held");
        let keys: Vec<Key> = (0..6)
            .map(|i| match i % 2 {
                0 => held[rng.below(held.len() as u64) as usize],
                _ => random_key(&mut rng),
            })
            .collect();
        let mut pooled: Vec<Key> = Vec::new();
        if n % 3 == 0 {
            pooled.extend([random_key(&mut rng), random_key(&mut rng)]);
            f.unconfirmed.add_unconfirmed_tx(&mempool_tx(&pooled));
            watched.always.write().expect("always").extend(&pooled);
        }
        watched
            .by_height
            .write()
            .expect("heights")
            .push(keys.clone());

        let writer = f.db.begin(true).expect("begin");
        let (chain, subber, unconfirmed) = (&f.chain, &mut f.subber, &f.unconfirmed);
        let store = &f.store;
        let flushes = || store.faults.finished.lock().expect("log").len();
        let (prepares, flushed, connected) = std::thread::scope(|s| {
            let updater = s.spawn(|| {
                deliver(
                    Delivery::Queued,
                    chain,
                    subber,
                    unconfirmed,
                    n as u32,
                    &keys,
                )
            });
            let deadline = Instant::now() + Duration::from_secs(20);
            while store.faults.prepares.load(Ordering::SeqCst) < n && Instant::now() < deadline {
                std::thread::yield_now();
            }
            let prepares = store.faults.prepares.load(Ordering::SeqCst);
            let before = flushes();
            // The connect is prepared and waits for the writer: this
            // commit's flush falls between the two.
            writer.commit().expect("commit");
            let flushed = flushes() - before;
            (prepares, flushed, updater.join().expect("updater"))
        });
        assert_eq!(
            prepares, n,
            "connect {n} was not prepared while another transaction held the writer"
        );
        connected.expect("connect");
        assert_eq!(
            flushed, 1,
            "connect {n}: the commit before it did not flush"
        );
        assert_eq!(flushes(), n, "connect {n}: a flush besides that one");
        // What the connect handed over is what its prepare kept: the keys
        // the memtable did not hold then.  The others are in the runs.
        let kept: BTreeSet<Key> = keys
            .iter()
            .chain(&pooled)
            .copied()
            .filter(|key| held.binary_search(key).is_err())
            .collect();
        left_out += keys.len() + pooled.len() - kept.len();
        assert!(
            f.store.mem.snapshot() == kept.into_iter().collect::<Vec<Key>>(),
            "connect {n} did not hand over exactly the keys its prepare kept"
        );
        all.extend(keys);
        all.extend(pooled);
    }
    let race = watched.finish(readers);
    assert!(race.lookups > 1000, "{} lookups", race.lookups);
    assert_eq!(race.falses, 0, "of {} lookups", race.lookups);
    assert_eq!(f.prepared(), (CONNECTS, CONNECTS));
    assert!(
        left_out >= CONNECTS,
        "the prepares left out {left_out} keys"
    );

    let want: Vec<Key> = all.into_iter().collect();
    let keys = f.idx.lock().expect("index").logical_keys().expect("keys");
    assert!(
        keys == want,
        "the index's keys are not the blocks' and the pool's"
    );
    f.db.flush().expect("flush");
    check_layout(&f.db).expect("layout").expect("bucket");
    let stored = super::store::stored_keys(&f.db)
        .expect("stored")
        .expect("index");
    assert!(stored == want, "the stored keys are not the index's");
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
// The key order
// ---------------------------------------------------------------------

/// Pairs `(a, b)` with `a` before `b` in byte order, chosen so that a
/// comparison by words gets them wrong if it reads a word little-endian,
/// compares words as signed integers, takes the words out of order, or
/// leaves a byte out.  For each byte position: the keys agree before it,
/// differ at it, and after it either agree or disagree the other way in
/// every byte.
fn ordered_pairs() -> Vec<(Key, Key)> {
    let mut pairs = Vec::new();
    for at in 0..21 {
        for (lo, hi) in [(0x00, 0x01), (0x7f, 0x80), (0x00, 0xff), (0xfe, 0xff)] {
            for before in [0x00, 0x5a, 0xff] {
                for (after_a, after_b) in [(0x33, 0x33), (0xff, 0x00), (0x80, 0x7f)] {
                    let (mut a, mut b) = ([before; 21], [before; 21]);
                    a[at] = lo;
                    b[at] = hi;
                    a[at + 1..].fill(after_a);
                    b[at + 1..].fill(after_b);
                    pairs.push((a, b));
                }
            }
        }
    }
    pairs
}

/// Random keys, many of them a copy of the one before with a byte, or
/// everything from a byte on, changed: keys that agree for a random
/// number of bytes.
fn clustered_keys(rng: &mut SplitMix64, n: usize) -> Vec<Key> {
    let mut keys: Vec<Key> = Vec::with_capacity(n);
    while keys.len() < n {
        let key = match (keys.last(), rng.below(4)) {
            (Some(&last), 0) => {
                let mut key = last;
                key[rng.below(21) as usize] = rng.next_u64() as u8;
                key
            }
            (Some(&last), 1) => {
                let mut key = random_key(rng);
                let agree = rng.below(22) as usize;
                key[..agree].copy_from_slice(&last[..agree]);
                key
            }
            (Some(&last), 2) => last,
            _ => random_key(rng),
        };
        keys.push(key);
    }
    keys
}

/// The inline comparison is the order of the keys' bytes, the one the
/// array type itself has: on every adversarial pair in both directions,
/// on equal keys, on random and clustered keys, and as a sort.  It is
/// the order of every sorted row on disk, so any difference would be a
/// format change.
#[test]
fn the_inline_key_comparison_is_the_byte_order() {
    use core::cmp::Ordering::{Equal, Greater, Less};

    for (a, b) in ordered_pairs() {
        assert!(a < b, "the pair is not ordered: {} {}", hex(&a), hex(&b));
        assert_eq!(super::cmp_keys(&a, &b), Less, "{} {}", hex(&a), hex(&b));
        assert_eq!(super::cmp_keys(&b, &a), Greater, "{} {}", hex(&b), hex(&a));
        assert_eq!(super::cmp_keys(&a, &a), Equal, "{}", hex(&a));
        assert_eq!(super::cmp_keys(&b, &b), Equal, "{}", hex(&b));
    }

    let mut rng = SplitMix64::from_entropy("the_inline_key_comparison_is_the_byte_order");
    let keys = clustered_keys(&mut rng, 200_000);
    for pair in keys.windows(2) {
        let (a, b) = (pair[0], pair[1]);
        assert_eq!(
            super::cmp_keys(&a, &b),
            a.cmp(&b),
            "{} {}",
            hex(&a),
            hex(&b)
        );
        assert_eq!(
            super::cmp_keys(&b, &a),
            b.cmp(&a),
            "{} {}",
            hex(&b),
            hex(&a)
        );
    }
    for _ in 0..200_000 {
        let a = keys[rng.below(keys.len() as u64) as usize];
        let b = keys[rng.below(keys.len() as u64) as usize];
        assert_eq!(
            super::cmp_keys(&a, &b),
            a.cmp(&b),
            "{} {}",
            hex(&a),
            hex(&b)
        );
    }

    let mut by_bytes = keys.clone();
    by_bytes.sort_unstable();
    let mut inline = keys;
    inline.sort_unstable_by(super::cmp_keys);
    assert!(inline == by_bytes, "the two orders sort differently");
}

/// Every place that compares keys with the inline comparison gives what
/// the byte order gives: the memtable's lookup and merge, the runs' union
/// and the rows' order check, here; and the journal's sort and the
/// chunks a flush writes, as bytes on disk.
#[test]
fn every_place_that_compares_keys_keeps_the_byte_order() {
    let mut rng = SplitMix64(0x6f72_6465_7201);
    let mut keys = clustered_keys(&mut rng, 3_000);
    for (a, b) in ordered_pairs() {
        keys.extend([a, b]);
    }
    let all: BTreeSet<Key> = keys.iter().copied().collect();
    let sorted_all: Vec<Key> = all.iter().copied().collect();

    // The merge of two disjoint sorted halves, and the union of two
    // sorted lists that share a third of their keys.
    let evens: Vec<Key> = sorted_all.iter().copied().step_by(2).collect();
    let odds: Vec<Key> = sorted_all.iter().copied().skip(1).step_by(2).collect();
    assert_eq!(super::memtable::merge_sorted(&evens, &odds), sorted_all);
    assert_eq!(super::memtable::merge_sorted(&odds, &evens), sorted_all);
    let low: Vec<Key> = sorted_all
        .iter()
        .enumerate()
        .filter(|(i, _)| i % 3 != 0)
        .map(|(_, k)| *k)
        .collect();
    let high: Vec<Key> = sorted_all
        .iter()
        .enumerate()
        .filter(|(i, _)| i % 3 != 1)
        .map(|(_, k)| *k)
        .collect();
    assert_eq!(runs::union(&low, &high), sorted_all);
    assert_eq!(runs::union(&high, &low), sorted_all);

    // A row's order check: ascending keys pass, and a pair out of order
    // or repeated does not.
    for row in sorted_all.chunks(CHUNK) {
        let value = runs::encode_chunk(row);
        assert_eq!(
            runs::decode_keys(&value, CHUNK, "a row").expect("ascending"),
            row
        );
    }
    for (a, b) in ordered_pairs() {
        assert!(runs::decode_keys(&runs::encode_chunk(&[a, b]), CHUNK, "a row").is_ok());
        assert!(runs::decode_keys(&runs::encode_chunk(&[b, a]), CHUNK, "a row").is_err());
        assert!(runs::decode_keys(&runs::encode_chunk(&[a, a]), CHUNK, "a row").is_err());
    }

    // The memtable's lookup, over journaled keys and unjournaled runs:
    // every key held is found, and for every adversarial pair the key
    // left out is not, though its neighbour is held.
    let rig = StoreRig::new(Policy {
        k0: usize::MAX,
        k0_hard: usize::MAX,
        u_max: usize::MAX,
        ..Policy::tiny()
    });
    let part = rig.store.partitioner();
    let holds = |key: &Key| rig.store.mem.contains(part.of(key), key);
    let (journaled, unjournaled) = keys.split_at(keys.len() / 2);
    rig.insert(journaled.to_vec());
    rig.flush();
    for batch in unjournaled.chunks(97) {
        rig.insert(batch.to_vec());
    }
    for key in &sorted_all {
        assert!(holds(key), "{} is held", hex(key));
    }
    for _ in 0..3_000 {
        let key = random_key(&mut rng);
        assert_eq!(holds(&key), all.contains(&key), "{}", hex(&key));
    }
    for (a, b) in ordered_pairs() {
        for mut near in [a, b] {
            near[20] ^= 1;
            assert_eq!(holds(&near), all.contains(&near), "{}", hex(&near));
            near[0] ^= 0x80;
            assert_eq!(holds(&near), all.contains(&near), "{}", hex(&near));
        }
    }

    // The journal's rows of the first flush hold exactly the first half
    // of the keys in byte order, as one sorted batch cut into rows.
    let rows = rig.rows();
    let journal: Vec<Key> = rows
        .iter()
        .filter(|(row, _)| row[4] == super::journal::JOURNAL_TAG)
        .flat_map(|(_, value)| value.chunks(21).map(|k| Key::try_from(k).expect("a key")))
        .collect();
    let want: BTreeSet<Key> = journaled.iter().copied().collect();
    assert!(want.len() > CHUNK, "the batch fills more than one row");
    assert!(
        journal == want.iter().copied().collect::<Vec<Key>>(),
        "the journal's rows are not the batch in byte order"
    );

    // Merged into runs, every level's chunks hold its keys in byte
    // order, chunk after chunk.
    let rig = StoreRig::new(Policy {
        k0: 0,
        k0_hard: 0,
        ..Policy::tiny()
    });
    rig.insert(keys.clone());
    rig.flush();
    let part = rig.store.partitioner();
    let mut levels: std::collections::BTreeMap<(u8, u8), Vec<Key>> = Default::default();
    for (row, value) in rig.rows() {
        if row[4] == runs::RUN_TAG {
            levels
                .entry((row[5], row[6]))
                .or_default()
                .extend(value.chunks(21).map(|k| Key::try_from(k).expect("a key")));
        }
    }
    let mut in_runs = 0usize;
    for ((p, _), level) in &levels {
        let want: Vec<Key> = sorted_all
            .iter()
            .copied()
            .filter(|key| part.of(key) == *p)
            .collect();
        assert!(*level == want, "partition {p}'s run is not in byte order");
        in_runs += level.len();
    }
    assert_eq!(in_runs, sorted_all.len());
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
