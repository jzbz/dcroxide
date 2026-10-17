// SPDX-License-Identifier: ISC
//! Replay of dcrd's full block test battery
//! (`data/fullblock_vectors.txt`): every test instance produced by
//! dcrd's own `fullblocktests.Generate` — a scripted regression
//! network chain of fully signed blocks with real tickets, votes,
//! revocations, and reorganizations alongside hundreds of
//! specifically invalid variants with their expected rejection
//! kinds — driven through the chain engine with full validation
//! including script execution, exactly like dcrd's own
//! `TestFullBlocks` driver.  This is the single broadest
//! cross-validation of the consensus engine in the repository.
//!
//! The battery is replayed three times: on a chain with no store, and on
//! two chains over a database, one committing each metadata flush on the
//! thread that trips it and one on a thread of its own
//! (`Options::background_commit`).  Where a flush's commit runs is no
//! part of consensus: all three give the same verdict on every row, and
//! the two stores end at the same tip with the same UTXO set, which the
//! second still holds when it is opened again.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use dcroxide_blockchain::RuleErrorKind;
use dcroxide_blockchain::process::{Chain, UtxoStats};
use dcroxide_chaincfg::{Params, regnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, FlushObservation, Options};
use dcroxide_testutil::unhex;
use dcroxide_wire::MsgBlock;

fn parse_hash(s: &str) -> Hash {
    let bytes = unhex(s);
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    Hash(h)
}

#[test]
fn fullblock_vectors() {
    let params = regnet_params();
    let mut chain = Chain::new(&params, Hash::ZERO, false);
    replay(&mut chain, &params, 0);
}

/// Two days: under a clock this far ahead every block of the battery
/// looks old, so the chain never latches to current and no connect asks
/// for a durable flush.  The flushes are then the ones commits trip,
/// which are the ones that can commit on a thread of their own.
const CLOCK_OFFSET: i64 = 48 * 60 * 60;

/// Replay the battery on a chain over a database whose write cache holds
/// little, so that many commits flush it, with those flushes' commits on
/// a thread of their own when `background` is set.  Returns the tip and
/// the UTXO statistics the chain ends at, and the same read from the
/// store once it has been closed and opened again.
fn replay_over_a_store(background: bool) -> [(Hash, UtxoStats); 2] {
    let params = regnet_params();
    let dir = tempfile::TempDir::new().expect("tempdir");
    let mut opts = Options::new(dir.path().join("chain"), params.net.0);
    opts.cache_max_size = 4 * 1024;
    opts.background_commit = background;
    let flushes = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
    {
        let flushes = Arc::clone(&flushes);
        opts.flush_observer = Some(Arc::new(move |obs: &FlushObservation| {
            flushes[usize::from(obs.background)].fetch_add(1, Ordering::SeqCst);
        }));
    }
    let db = Database::create(&opts).expect("create database");
    let mut chain = Chain::open(db.clone(), &params, Hash::ZERO, false, 0).expect("open chain");
    replay(&mut chain, &params, CLOCK_OFFSET);
    let end = (
        chain.best_snapshot().hash,
        chain.fetch_utxo_stats().expect("stats"),
    );
    chain.flush(&params).expect("flush the chain");
    drop(chain);
    db.close().expect("close");
    // The store's file stays locked for as long as a handle lives.
    drop(db);

    let [inline, on_their_own_thread] = [
        flushes[0].load(Ordering::SeqCst),
        flushes[1].load(Ordering::SeqCst),
    ];
    // The battery's blocks are small: a 4 KiB write cache is what makes
    // dozens of its commits flush.  A few flushes are asked for outright,
    // by the reorganizations and the flush above, and commit where they
    // are asked for in either mode.
    if background {
        assert!(
            on_their_own_thread >= 40 && on_their_own_thread > inline,
            "{on_their_own_thread} flushes committed on a thread of their own, {inline} did not"
        );
    } else {
        assert!(
            inline >= 40 && on_their_own_thread == 0,
            "{inline} flushes, {on_their_own_thread} of them on a thread of their own"
        );
    }

    let db = Database::open(&Options::new(dir.path().join("chain"), params.net.0)).expect("reopen");
    let mut chain = Chain::open(db.clone(), &params, Hash::ZERO, false, 0).expect("reopen chain");
    let reopened = (
        chain.best_snapshot().hash,
        chain.fetch_utxo_stats().expect("stats"),
    );
    drop(chain);
    db.close().expect("close");
    [end, reopened]
}

/// Every row of the battery gets the same verdict on a chain whose
/// metadata flushes commit on a thread of their own, and that chain ends
/// at the tip and the UTXO set of one whose flushes commit where they
/// are tripped, durably.
#[test]
fn fullblock_vectors_with_commits_on_their_own_thread() {
    let [inline, inline_reopened] = replay_over_a_store(false);
    let [background, background_reopened] = replay_over_a_store(true);
    assert_eq!(inline, inline_reopened, "the inline store, reopened");
    assert_eq!(background, inline, "the two chains end alike");
    assert_eq!(
        background_reopened, inline,
        "and what is durable is the same"
    );
}

/// Drive every row of the battery through `chain` and check each one's
/// verdict, with the clock `clock_offset` seconds ahead of the battery's.
/// The one row whose verdict is the clock's, the block too far in the
/// future, is always judged by the battery's own.
fn replay(chain: &mut Chain, params: &Params, clock_offset: i64) {
    let data = include_str!("data/fullblock_vectors.txt");
    // The battery is generated relative to the wall clock (the
    // too-far-in-the-future block), so the dump records its
    // generation time for the replay to use as its current time.
    let mut now: i64 = 0;
    let mut counts = [0usize; 6];

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "now" => now = f[1].parse::<i64>().expect("now") + clock_offset,
            "accept" => {
                // accept <name> <mainchain> <orphan> <blockhex>
                let name = f[1];
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                let (fork_len, errs) = chain.process_block(&block, now, params);
                // dcrd's driver treats a missing parent as an
                // accepted orphan.
                let is_orphan = errs.len() == 1 && errs[0].kind == RuleErrorKind::MissingParent;
                assert!(
                    errs.is_empty() || is_orphan,
                    "block {name} should have been accepted: {errs:?}"
                );
                let is_main_chain = !is_orphan && fork_len == 0;
                assert_eq!(is_main_chain.to_string(), f[2], "{name}: main chain flag");
                assert_eq!(is_orphan.to_string(), f[3], "{name}: orphan flag");
                counts[0] += 1;
            }
            "reject" => {
                // reject <name> <kind> <blockhex>
                let name = f[1];
                let (block, _) = MsgBlock::from_bytes(&unhex(f[3])).expect("block");
                let now = if f[2] == "ErrTimeTooNew" {
                    now - clock_offset
                } else {
                    now
                };
                let (_, errs) = chain.process_block(&block, now, params);
                assert!(!errs.is_empty(), "block {name} should have been rejected");
                assert_eq!(
                    errs[0].kind.kind_name(),
                    f[2],
                    "{name}: reject kind ({})",
                    errs[0].description
                );
                counts[1] += 1;
            }
            "orphanorreject" => {
                // orphanorreject <name> <blockhex>
                let name = f[1];
                let (block, _) = MsgBlock::from_bytes(&unhex(f[2])).expect("block");
                let (_, errs) = chain.process_block(&block, now, params);
                assert!(
                    !errs.is_empty(),
                    "block {name} should have been an orphan or rejected"
                );
                counts[2] += 1;
            }
            "tip" => {
                // tip <name> <hash>
                let tip = chain.best_chain.tip().expect("tip");
                assert_eq!(
                    chain.store.node(tip).hash,
                    parse_hash(f[2]),
                    "{}: expected tip",
                    f[1]
                );
                counts[3] += 1;
            }
            "skipnano" => {
                // skipnano <name> <kind>: the nanosecond-precision
                // timestamp rejection only exists for in-memory
                // blocks — the wire encoding stores whole seconds —
                // so the instance cannot be replayed from serialized
                // bytes.
                assert_eq!(f[2], "ErrInvalidTime", "{}: skip kind", f[1]);
                counts[5] += 1;
            }
            "noncanon" => {
                // noncanon <name> <rawhex>
                assert!(
                    MsgBlock::from_bytes(&unhex(f[2])).is_err(),
                    "{}: non-canonical block should fail to decode",
                    f[1]
                );
                counts[4] += 1;
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [205, 353, 3, 14, 1, 1], "row counts");
}
