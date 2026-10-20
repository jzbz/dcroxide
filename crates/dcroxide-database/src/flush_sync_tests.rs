// SPDX-License-Identifier: ISC
//! The block-file sync of a flush, wherever it runs, and a power cut at
//! every storage operation of the flushes of a scripted run.
//!
//! With background commits a flush that may be handed over takes what
//! the block-file sync owes on the thread that captures it, under the
//! writer semaphore, and leaves running it to the thread that commits,
//! which syncs before it writes a row.  The capturing thread goes on
//! writing blocks meanwhile, so a sync can run while blocks are written
//! to a file it syncs, and its discharge must leave that file owed to
//! the next sync.  Without background commits, and for a flush that
//! acknowledges durability, the sync runs on the capturing thread before
//! the write transaction is opened, as before.
//!
//! The power-cut rig here holds both halves of the store to the cut.
//! The metadata file sits on a [`PowerLossBackend`], which discards what
//! was never synced.  The block files are real files, so the store's
//! sync hook ([`crate::blockfile::SyncHook`]) stands in for their power:
//! each fsync is counted in the backend's sequence of storage operations
//! and refused once the power is out, and an admitted one records the
//! length of its file as it began, which is all the fsync can be relied
//! on to cover.  At the cut each block file is cut back to that length,
//! or to nothing when no fsync before the cut reached it, which loses
//! every block byte a crash may lose.  The reopened store must then be at
//! one of the run's flushes, every block that flush's metadata names
//! there to be read back whole.
//!
//! Only code inside the crate can reach the hook, so the sweep lives
//! here rather than with the power cuts of `tests/background_commit.rs`.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "test arithmetic over small counts"
)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use dcroxide_chainhash::{Hash, hash_h};
use dcroxide_testutil::powerloss::PowerLossBackend;

use crate::blockfile::{SyncEvent, SyncHook};
use crate::{Database, Error, FlushObservation, METADATA_FILE, Options, SharedBackend};

const NET: u32 = 0x1214_1c16;

/// The overlay's maximum: one fill of 48 rows of a kibibyte arms the
/// next commit's flush.
const CACHE_MAX: u64 = 64 * 1024;

/// Two records of 300 block bytes fit in a block file and a record of
/// 300 and one of 400 do not, so the script's blocks share files and
/// rotate to new ones.
const MAX_BLOCK_FILE: u32 = 700;

/// Longer than anything here takes.
const NEVER: Duration = Duration::from_secs(60);

/// A point the thread running a sync plan can be held at, once the plan
/// has run and before what it synced is discharged.
#[derive(Default)]
struct Hold {
    /// Whether to hold, and whether a thread has arrived.
    state: Mutex<(bool, bool)>,
    changed: Condvar,
}

impl Hold {
    fn arm(&self) {
        *self.state.lock().expect("hold") = (true, false);
    }

    /// Called by the thread to hold: wait while armed.
    fn pass(&self) {
        let mut state = self.state.lock().expect("hold");
        if !state.0 {
            return;
        }
        state.1 = true;
        self.changed.notify_all();
        while state.0 {
            state = self.changed.wait(state).expect("hold");
        }
    }

    fn wait_reached(&self, timeout: Duration) -> bool {
        let state = self.state.lock().expect("hold");
        let (state, _) = self
            .changed
            .wait_timeout_while(state, timeout, |state| !state.1)
            .expect("hold");
        state.1
    }

    fn release(&self) {
        self.state.lock().expect("hold").0 = false;
        self.changed.notify_all();
    }
}

/// The block files' side of the power: which bytes of each file the
/// fsyncs admitted before the cut cover.
struct BlockPower {
    power: Arc<PowerLossBackend>,
    /// File number to the length the file had when its latest admitted
    /// fsync began.
    durable: Mutex<BTreeMap<u32, u64>>,
    /// Each admitted fsync's file and the name of the thread that ran it,
    /// in order.
    synced_on: Mutex<Vec<(u32, Option<String>)>>,
    hold: Hold,
}

impl BlockPower {
    fn new(power: Arc<PowerLossBackend>) -> Arc<BlockPower> {
        Arc::new(BlockPower {
            power,
            durable: Mutex::default(),
            synced_on: Mutex::default(),
            hold: Hold::default(),
        })
    }

    /// The hook to set on a store's block files.
    fn hook(self: &Arc<Self>) -> SyncHook {
        let me = Arc::clone(self);
        Arc::new(move |event| match event {
            SyncEvent::Fsync(num, path) => {
                me.power.admit_external()?;
                let len = std::fs::metadata(path).map_or(0, |m| m.len());
                me.durable.lock().expect("durable").insert(num, len);
                me.synced_on
                    .lock()
                    .expect("synced on")
                    .push((num, std::thread::current().name().map(String::from)));
                Ok(())
            }
            SyncEvent::Ran => {
                me.hold.pass();
                Ok(())
            }
        })
    }

    /// Set the hook on `db`'s block files.
    fn install(self: &Arc<Self>, db: &Database) {
        db.inner
            .block_store
            .lock()
            .expect("block store lock poisoned")
            .sync_hook = Some(self.hook());
    }

    /// Leave each block file in `dir` as the cut leaves it: the bytes the
    /// last fsync admitted before the cut covered, or none.
    fn cut(&self, dir: &Path) {
        let durable = self.durable.lock().expect("durable");
        for entry in std::fs::read_dir(dir).expect("the database directory") {
            let path = entry.expect("an entry").path();
            if path.extension().is_none_or(|e| e != "fdb") {
                continue;
            }
            let num: u32 = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .and_then(|stem| stem.parse().ok())
                .expect("a block file's number");
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .expect("open a block file");
            let len = file.metadata().expect("metadata").len();
            let keep = durable.get(&num).copied().unwrap_or(0).min(len);
            file.set_len(keep).expect("cut a block file back");
        }
    }
}

/// A raw block of `len` bytes at `height`, its bytes drawn from `tag`,
/// with its hash.
fn raw_block(height: u32, tag: u8, len: usize) -> (Hash, Vec<u8>) {
    let mut raw: Vec<u8> = (0..len)
        .map(|i| tag.wrapping_mul(31).wrapping_add(i as u8))
        .collect();
    raw[128..132].copy_from_slice(&height.to_le_bytes());
    (hash_h(&raw[..180]), raw)
}

/// One commit of the script: its tag, the block it stores, and whether
/// it fills the overlay enough to arm the next commit's flush.
struct Step {
    tag: u8,
    block: Option<(Hash, u32, Vec<u8>)>,
    fill: bool,
}

/// The script: rounds of five commits.  A stores a block and arms a
/// flush, which T trips; C stores a block while that flush syncs, held
/// between its fsync and its discharge when its commit was handed over;
/// D arms a flush with no block, which E trips.  So every block C stores
/// is made durable by E's flush alone, which syncs it only if the sync
/// that ran beside C left its file owed.  In the second round C's block
/// does not fit in the file A's went to and starts the next one.
fn script() -> Vec<Step> {
    let mut steps = Vec::new();
    for round in 0..3u8 {
        let tag = 10 * (round + 1);
        let c_len = if round == 1 { 400 } else { 300 };
        let block = |tag: u8, len: usize| {
            let height = u32::from(tag) * 1000;
            let (hash, raw) = raw_block(height, tag, len);
            Some((hash, height, raw))
        };
        steps.push(Step {
            tag,
            block: block(tag, 300),
            fill: true,
        });
        steps.push(Step {
            tag: tag + 1,
            block: None,
            fill: false,
        });
        steps.push(Step {
            tag: tag + 2,
            block: block(tag + 2, c_len),
            fill: false,
        });
        steps.push(Step {
            tag: tag + 3,
            block: None,
            fill: true,
        });
        steps.push(Step {
            tag: tag + 4,
            block: None,
            fill: false,
        });
    }
    steps
}

/// The commit of one step: its marker row, its fill rows, its block.
fn commit(db: &Database, step: &Step) -> Result<(), Error> {
    db.update(|tx| {
        let rows = tx.metadata().bucket(b"rows").expect("bucket");
        rows.put(&[0xee, step.tag], &[step.tag])?;
        if step.fill {
            for i in 0..48u8 {
                rows.put(&[step.tag, i], &[step.tag; 1024])?;
            }
        }
        if let Some((hash, _, raw)) = &step.block {
            tx.store_block_raw(hash, raw.clone())?;
        }
        Ok(())
    })
}

/// What one run of the script did.
struct Run {
    /// Storage operations, the block files' fsyncs among them.
    ops: u64,
    /// Steps whose commit returned `Ok`.
    committed: usize,
    /// Steps found durable after the cut.
    durable: usize,
    /// Flushes whose block-file sync ran on the commit thread.
    synced_on_committer: usize,
    /// Whether each C step's block was written while a sync was held.
    held: usize,
}

/// Run the script over a new store, with background commits or without,
/// the power failing after `cut` storage operations when given; then let
/// go of the store as a dying process does, cut the power, and reopen
/// the files alone.
fn run(background: bool, cut: Option<u64>) -> Run {
    let dir = tempfile::tempdir().expect("temp dir");
    let db_dir = dir.path().join("db");
    std::fs::create_dir_all(&db_dir).expect("mkdir");
    let power = PowerLossBackend::create(&db_dir.join(METADATA_FILE), true);
    let mut opts = Options::new(&db_dir, NET);
    opts.backend = Some(Arc::clone(&power) as SharedBackend);
    opts.background_commit = background;
    opts.cache_max_size = CACHE_MAX;
    opts.max_block_file_size = MAX_BLOCK_FILE;
    let flushes = Arc::new(AtomicU64::new(0));
    {
        let flushes = Arc::clone(&flushes);
        opts.flush_observer = Some(Arc::new(move |_: &FlushObservation| {
            flushes.fetch_add(1, Ordering::SeqCst);
        }));
    }
    let db = Database::create(&opts).expect("create");
    db.update(|tx| tx.metadata().create_bucket(b"rows").map(|_| ()))
        .expect("the bucket");
    db.flush().expect("flush");
    let blocks = BlockPower::new(Arc::clone(&power));
    blocks.install(&db);
    let flushed_before = flushes.load(Ordering::SeqCst);
    let ops_before = power.ops();
    if let Some(n) = cut {
        power.power_fails_after(n);
    }

    let steps = script();
    let (mut committed, mut held) = (0usize, 0usize);
    let mut i = 0;
    while i < steps.len() {
        // T's flush is held between its sync and the discharge when it
        // was handed over, while C writes its block.
        let holds = background && i % 5 == 1;
        if holds {
            blocks.hold.arm();
        }
        if commit(&db, &steps[i]).is_err() {
            blocks.hold.release();
            break;
        }
        committed = i + 1;
        if holds {
            assert!(
                blocks.hold.wait_reached(NEVER),
                "a handed-over flush never reached the end of its sync"
            );
            let wrote = commit(&db, &steps[i + 1]);
            blocks.hold.release();
            if wrote.is_err() {
                break;
            }
            held += 1;
            committed = i + 2;
            i += 1;
        }
        if db.wait_background_commit().is_err() {
            break;
        }
        i += 1;
    }
    let _ = db.wait_background_commit();
    let ops = power.ops() - ops_before;
    let landed_flushes = (flushes.load(Ordering::SeqCst) - flushed_before) as usize;
    let synced_on_committer = blocks
        .synced_on
        .lock()
        .expect("synced on")
        .iter()
        .filter(|(_, thread)| thread.as_deref() == Some(crate::COMMIT_THREAD_NAME))
        .count();
    // Flush 2k + 1 captured through round k's A, flush 2k + 2 through
    // its D.
    let landed = match landed_flushes {
        0 => 0,
        n if n % 2 == 1 => (n / 2) * 5 + 1,
        n => (n / 2 - 1) * 5 + 4,
    };
    drop(db);
    power.cut_power();
    blocks.cut(&db_dir);

    let db = Database::open(&Options::new(&db_dir, NET)).unwrap_or_else(|e| {
        panic!("cut {cut:?} (background {background}): the store does not reopen: {e}")
    });
    let mut durable = 0usize;
    db.view(|tx| {
        let rows = tx.metadata().bucket(b"rows").expect("bucket");
        for (i, step) in steps.iter().enumerate() {
            let marked = rows.get(&[0xee, step.tag]).is_some();
            if marked {
                assert_eq!(
                    durable, i,
                    "cut {cut:?} (background {background}): step {i} is durable and an \
                     earlier one is not"
                );
                durable = i + 1;
            }
            if step.fill {
                let filled = (0..48u8)
                    .filter(|r| rows.get(&[step.tag, *r]).is_some())
                    .count();
                assert_eq!(
                    filled,
                    if marked { 48 } else { 0 },
                    "cut {cut:?} (background {background}): step {i}'s rows are torn"
                );
            }
            if let Some((hash, height, raw)) = &step.block {
                if marked {
                    assert!(
                        tx.has_block(hash, *height)?,
                        "cut {cut:?} (background {background}): step {i}'s block is not \
                         there"
                    );
                    assert_eq!(
                        &tx.fetch_block(hash, *height)?,
                        raw,
                        "cut {cut:?} (background {background}): step {i}'s block"
                    );
                } else {
                    assert!(
                        !tx.has_block(hash, *height)?,
                        "cut {cut:?} (background {background}): step {i}'s block is there \
                         without its commit"
                    );
                }
            }
        }
        Ok(())
    })
    .expect("view");
    assert!(
        durable <= committed && durable >= landed,
        "cut {cut:?} (background {background}): {durable} steps durable, {committed} \
         committed, {landed} made durable by the flushes seen to land"
    );
    // The store goes on from there.
    let (hash, raw) = raw_block(1, 0x77, 300);
    db.update(|tx| tx.store_block_raw(&hash, raw))
        .expect("store after the power cut");
    db.close().expect("close");
    Run {
        ops,
        committed,
        durable,
        synced_on_committer,
        held,
    }
}

/// Cut the power at every storage operation of a whole run of the
/// script, from the first after the store is set up to the last, and at
/// none, and hold what each cut leaves to a prefix of the run's commits
/// that is no shorter than what the flushes seen to land made durable,
/// with every block that prefix stores read back whole and none of those
/// after it there.  `DCROXIDE_CRASH_SWEEP_EVERY` takes one operation in
/// that many instead, as it does in the other sweeps.
fn sweep(background: bool) {
    let stride: u64 = match std::env::var("DCROXIDE_CRASH_SWEEP_EVERY") {
        Ok(v) => v.parse().expect("DCROXIDE_CRASH_SWEEP_EVERY is a count"),
        Err(_) => 1,
    };
    assert!(stride > 0, "DCROXIDE_CRASH_SWEEP_EVERY is at least 1");
    let whole = run(background, None);
    let steps = script().len();
    assert_eq!(whole.committed, steps);
    assert_eq!(
        whole.durable,
        steps - 1,
        "the last flush captured through the last D"
    );
    if background {
        assert_eq!(
            (whole.synced_on_committer, whole.held),
            (6, 3),
            "every flush synced on the commit thread, and every C wrote while one was held"
        );
    } else {
        assert_eq!(
            whole.synced_on_committer, 0,
            "no flush synced on a thread of its own"
        );
    }
    let mut tips = std::collections::BTreeSet::new();
    for cut in (0..=whole.ops).step_by(stride as usize) {
        let run = run(background, Some(cut));
        tips.insert(run.durable);
    }
    assert!(
        tips.len() >= 6,
        "the cuts left the store at too few different commits to show anything: {tips:?}"
    );
}

/// A power cut at every storage operation of flushes whose block-file
/// sync runs on the commit thread, blocks written beside it, leaves a
/// store that reopens at one of the flushes with every block it names.
#[test]
fn a_power_cut_at_every_operation_of_flushes_synced_on_the_commit_thread_recovers() {
    sweep(true);
}

/// The same with every flush committed on the thread that captures it
/// (`DCROXIDE_DB_SYNC_COMMIT`), which syncs the block files before it
/// opens the write transaction.
#[test]
fn a_power_cut_at_every_operation_of_flushes_synced_where_captured_recovers() {
    sweep(false);
}

/// A block written while a handed-over flush's sync is held between its
/// fsync and its discharge leaves its file owed: the flush lands with the
/// file still on the dirty list, the next flush syncs it, and a power cut
/// after that flush keeps the block.
#[test]
fn a_block_written_while_a_handed_over_flush_syncs_is_owed_to_the_next_flush() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db_dir = dir.path().join("db");
    std::fs::create_dir_all(&db_dir).expect("mkdir");
    let power = PowerLossBackend::create(&db_dir.join(METADATA_FILE), true);
    let mut opts = Options::new(&db_dir, NET);
    opts.backend = Some(Arc::clone(&power) as SharedBackend);
    opts.background_commit = true;
    opts.cache_max_size = CACHE_MAX;
    let db = Database::create(&opts).expect("create");
    db.update(|tx| tx.metadata().create_bucket(b"rows").map(|_| ()))
        .expect("the bucket");
    db.flush().expect("flush");
    let blocks = BlockPower::new(Arc::clone(&power));
    blocks.install(&db);
    let dirty = || {
        db.inner
            .block_store
            .lock()
            .expect("block store lock poisoned")
            .dirty_nums()
    };

    let steps = script();
    commit(&db, &steps[0]).expect("A: a block and a fill");
    assert_eq!(dirty(), vec![0]);
    blocks.hold.arm();
    commit(&db, &steps[1]).expect("T: the commit that trips the flush");
    assert!(blocks.hold.wait_reached(NEVER), "the flush synced");
    assert_eq!(
        blocks.synced_on.lock().expect("synced on").as_slice(),
        [(0, Some(crate::COMMIT_THREAD_NAME.to_string()))],
        "the commit thread synced file 0"
    );
    assert_eq!(dirty(), vec![0], "not yet discharged");
    commit(&db, &steps[2]).expect("C: a block beside the sync");
    blocks.hold.release();
    db.wait_background_commit().expect("the flush landed");
    assert_eq!(dirty(), vec![0], "C's block is still owed");

    commit(&db, &steps[3]).expect("D: a fill");
    commit(&db, &steps[4]).expect("E: the commit that trips the next flush");
    db.wait_background_commit().expect("the next flush landed");
    assert!(dirty().is_empty(), "the next flush synced C's block");
    assert_eq!(blocks.synced_on.lock().expect("synced on").len(), 2);

    drop(db);
    power.cut_power();
    blocks.cut(&db_dir);
    let db = Database::open(&Options::new(&db_dir, NET)).expect("reopen");
    db.view(|tx| {
        let (hash, height, raw) = steps[2].block.as_ref().expect("C's block");
        assert_eq!(&tx.fetch_block(hash, *height)?, raw, "C's block is durable");
        Ok(())
    })
    .expect("view");
    db.close().expect("close");
}
