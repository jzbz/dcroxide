// SPDX-License-Identifier: ISC
//! Reorganizations and invalidations that read the per-block rows back
//! from the database under their height-first keys (ADR-0010).
//!
//! A disconnect reads the block it removes, that block's spend journal
//! row, and, to regenerate a side chain's stake nodes, the per-height
//! stake undo and new-tickets rows.  The other database-backed reorg
//! tests stay inside the chain's recent in-memory window, where all of
//! that is served from memory, and `rekey_layout.rs` prunes and restarts
//! only once the battery is done.  Here one chain is restarted from its
//! data directory, with its window pruned, before every step of dcrd's
//! full block battery from just before its first side chain, and again
//! before each invalidation and reconsideration at the end, so those
//! reads come from the database under each block's height.
//!
//! Three chains replay the battery: one with no database, whose
//! in-memory mirrors keep every row and are the reference; one backed by
//! a database and restarted only at checkpoints; and the one restarted
//! before every step.  At each checkpoint the seven re-keyed buckets of
//! the two database-backed chains must hold the same keys, each naming
//! its block's height, and the same rows, and those rows must be the
//! reference's.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::{BTreeMap, BTreeSet};

use dcroxide_blockchain::RuleErrorKind;
use dcroxide_blockchain::chaindb::{
    GCS_FILTER_BUCKET_NAME, HEADER_CMTS_BUCKET_NAME, SPEND_JOURNAL_BUCKET_NAME,
    TREASURY_BUCKET_NAME, db_fetch_header_commitments,
};
use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::treasurydb::db_fetch_treasury_balance;
use dcroxide_chaincfg::{Params, regnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_stake::stakedb::{db_fetch_block_undo_data, db_fetch_new_tickets};
use dcroxide_stake::ticketdb::{STAKE_BLOCK_UNDO_DATA_BUCKET_NAME, TICKETS_IN_BLOCK_BUCKET_NAME};
use dcroxide_testutil::unhex;
use dcroxide_wire::{BlockHeader, MsgBlock};
use tempfile::TempDir;

/// The database's internal block index bucket.
const BLOCK_INDEX: &[u8] = b"ffldb-blockidx";

/// The seven buckets keyed by height first.
const BUCKETS: [&[u8]; 7] = [
    SPEND_JOURNAL_BUCKET_NAME,
    GCS_FILTER_BUCKET_NAME,
    HEADER_CMTS_BUCKET_NAME,
    TREASURY_BUCKET_NAME,
    STAKE_BLOCK_UNDO_DATA_BUCKET_NAME,
    TICKETS_IN_BLOCK_BUCKET_NAME,
    BLOCK_INDEX,
];

/// A block index row's value: the block's location in the block files
/// (twelve bytes), then its 180-byte header.
const BLOCK_LOCATION_LEN: usize = 12;

/// One step of the battery, with what the battery expects of it.
enum Step {
    /// Accepted; on the main chain or not, an orphan or not.
    Accept(String, MsgBlock, bool, bool),
    /// Rejected with the named error kind.
    Reject(String, MsgBlock, String),
    /// Either an orphan or rejected.
    OrphanOrReject(String, MsgBlock),
    /// The expected tip.
    Tip(String, Hash),
}

impl Step {
    /// The block the step submits, if any.
    fn block(&self) -> Option<&MsgBlock> {
        match self {
            Step::Accept(_, block, ..) | Step::Reject(_, block, _) => Some(block),
            Step::OrphanOrReject(_, block) => Some(block),
            Step::Tip(..) => None,
        }
    }
}

/// The battery's clock and steps.
fn battery() -> (i64, Vec<Step>) {
    let mut now = 0;
    let mut steps = Vec::new();
    for line in include_str!("data/fullblock_vectors.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let block = |hex: &str| MsgBlock::from_bytes(&unhex(hex)).expect("block").0;
        match f[0] {
            "now" => now = f[1].parse().expect("now"),
            "accept" => steps.push(Step::Accept(
                f[1].into(),
                block(f[4]),
                f[2] == "true",
                f[3] == "true",
            )),
            "reject" => steps.push(Step::Reject(f[1].into(), block(f[3]), f[2].into())),
            "orphanorreject" => steps.push(Step::OrphanOrReject(f[1].into(), block(f[2]))),
            "tip" => {
                let hash = Hash(unhex(f[2]).try_into().expect("a 32-byte hash"));
                steps.push(Step::Tip(f[1].into(), hash));
            }
            _ => {}
        }
    }
    (now, steps)
}

/// Run one step, checking the battery's expectation of it.
fn run_step(chain: &mut Chain, step: &Step, now: i64, params: &Params, who: &str) {
    match step {
        Step::Accept(name, block, main, orphan) => {
            let (fork_len, errs) = chain.process_block(block, now, params);
            let is_orphan = errs.len() == 1 && errs[0].kind == RuleErrorKind::MissingParent;
            assert!(errs.is_empty() || is_orphan, "{who}: {name}: {errs:?}");
            assert_eq!(is_orphan, *orphan, "{who}: {name} orphan");
            assert_eq!(
                !is_orphan && fork_len == 0,
                *main,
                "{who}: {name} main chain"
            );
        }
        Step::Reject(name, block, kind) => {
            let (_, errs) = chain.process_block(block, now, params);
            assert!(!errs.is_empty(), "{who}: {name} must be rejected");
            assert_eq!(errs[0].kind.kind_name(), kind, "{who}: {name}");
        }
        Step::OrphanOrReject(name, block) => {
            let (_, errs) = chain.process_block(block, now, params);
            assert!(!errs.is_empty(), "{who}: {name} orphan or reject");
        }
        Step::Tip(name, hash) => {
            assert_eq!(chain.best_snapshot().hash, *hash, "{who}: {name} tip");
        }
    }
}

/// Whether two valid blocks with data share the most work.  Nodes
/// loaded from the database all start with received order zero
/// (`blockindex.rs:397`), as dcrd's do, so a restart across such a tie
/// can change which of them `better_candidate` picks (`:544`): the
/// restarted chain is then right to disagree with the others, and the
/// restart is skipped.
fn top_work_tie(chain: &Chain, known: &[Hash]) -> bool {
    let works: Vec<_> = known
        .iter()
        .filter_map(|hash| chain.index.lookup_node(hash))
        .map(|id| chain.store.node(id))
        .filter(|node| node.status.have_data() && !node.status.known_invalid())
        .map(|node| node.work_sum)
        .collect();
    works
        .iter()
        .max()
        .is_some_and(|max| works.iter().filter(|w| *w == max).count() > 1)
}

/// Restart a chain from its data directory, as a clean shutdown and a
/// start would, and optionally prune its recent window to the tip so
/// that every older row is read from the database.
fn restart(chain: Chain, opts: &Options, params: &Params, prune: bool) -> Chain {
    let mut chain = chain;
    chain.flush(params).expect("flush");
    chain
        .db
        .as_ref()
        .expect("db-backed")
        .close()
        .expect("close");
    drop(chain);
    let db = Database::open(opts).expect("reopen the database");
    let mut chain = Chain::open(db, params, Hash::ZERO, false, 0).expect("reopen the chain");
    if prune {
        chain.prune_chain_memory(0);
    }
    chain
}

/// Every row of the seven buckets, in walk order.
type Rows = BTreeMap<&'static [u8], Vec<(Vec<u8>, Vec<u8>)>>;

fn rows(db: &Database) -> Rows {
    let mut out = Rows::new();
    db.view(|tx| {
        let meta = tx.metadata();
        for name in BUCKETS {
            let mut rows = Vec::new();
            meta.bucket(name).expect("bucket").for_each(|key, value| {
                rows.push((key.to_vec(), value.to_vec()));
                Ok(())
            })?;
            out.insert(name, rows);
        }
        Ok(())
    })
    .expect("walk the buckets");
    out
}

/// A height-then-hash key's height and hash, checked against the block
/// index: the height must be the block's own.
fn decode(chain: &Chain, key: &[u8], what: &str) -> (u32, Hash) {
    assert_eq!(key.len(), 36, "{what}: height || hash, {key:02x?}");
    let height = u32::from_be_bytes(key[..4].try_into().expect("height"));
    let hash = Hash(key[4..].try_into().expect("hash"));
    let node = chain
        .index
        .lookup_node(&hash)
        .unwrap_or_else(|| panic!("{what}: {hash} is not in the block index"));
    assert_eq!(
        chain.store.node(node).height,
        i64::from(height),
        "{what}: {hash}"
    );
    (height, hash)
}

/// Check a database-backed chain's seven buckets against the reference
/// chain, whose in-memory mirrors hold every row it ever wrote.
fn check_against_reference(who: &str, chain: &Chain, reference: &Chain, known: &[Hash]) {
    let tip = chain.best_snapshot();
    assert_eq!(tip.hash, reference.best_snapshot().hash, "{who}: tip");
    let tip = u32::try_from(tip.height).expect("height");
    let db = chain.db.as_ref().expect("db-backed");
    let all = rows(db);
    for (name, rows) in &all {
        assert!(
            rows.windows(2).all(|w| w[0].0 < w[1].0),
            "{who}: {} walks in key order",
            String::from_utf8_lossy(name)
        );
    }

    // The spend journal holds exactly the main chain's blocks past
    // genesis, with the reference's rows.
    let mut journal = BTreeMap::new();
    for (key, value) in &all[SPEND_JOURNAL_BUCKET_NAME] {
        let (height, hash) = decode(chain, key, "spend journal");
        assert_eq!(
            chain.block_hash_by_height(i64::from(height)),
            Some(hash),
            "{who}: a journal row off the main chain"
        );
        journal.insert(hash.0, value.clone());
    }
    assert_eq!(journal, reference.spend_journal, "{who}: spend journal");
    assert_eq!(journal.len(), tip as usize, "{who}: one row per block");

    // Filters, side chains included.
    let mut filters = BTreeMap::new();
    for (key, value) in &all[GCS_FILTER_BUCKET_NAME] {
        let (_, hash) = decode(chain, key, "filter");
        filters.insert(hash.0, value.clone());
    }
    let want: BTreeMap<[u8; 32], Vec<u8>> = reference
        .filters
        .iter()
        .map(|(hash, filter)| (*hash, filter.bytes().to_vec()))
        .collect();
    assert_eq!(filters, want, "{who}: filters");

    // Header commitments and treasury state, read through their helpers
    // under the key's height.  (The battery predates both agendas, so
    // these hold no rows; the checks keep the keys honest if it grows
    // them.)
    let mut commitments = BTreeMap::new();
    let mut treasury = BTreeMap::new();
    db.view(|tx| {
        for (key, _) in &all[HEADER_CMTS_BUCKET_NAME] {
            let (height, hash) = decode(chain, key, "commitments");
            let leaves = db_fetch_header_commitments(tx, &hash, height).expect("decode");
            commitments.insert(hash.0, leaves);
        }
        for (key, _) in &all[TREASURY_BUCKET_NAME] {
            let (height, hash) = decode(chain, key, "treasury");
            let state = db_fetch_treasury_balance(tx, &hash, height).expect("decode");
            treasury.insert(hash.0, state.expect("a treasury row"));
        }
        Ok(())
    })
    .expect("read the rows");
    let want: BTreeMap<[u8; 32], Vec<Hash>> = reference
        .header_commitments
        .iter()
        .filter(|(_, leaves)| !leaves.is_empty())
        .map(|(hash, leaves)| (*hash, leaves.clone()))
        .collect();
    assert_eq!(commitments, want, "{who}: header commitments");
    assert_eq!(treasury, reference.treasury_state, "{who}: treasury");

    // The stake rows: one per main chain height, keyed by the height
    // alone, big-endian, each the reference's.
    let heights: Vec<Vec<u8>> = (0..=tip).map(|h| h.to_be_bytes().to_vec()).collect();
    for name in [
        STAKE_BLOCK_UNDO_DATA_BUCKET_NAME,
        TICKETS_IN_BLOCK_BUCKET_NAME,
    ] {
        let keys: Vec<Vec<u8>> = all[name].iter().map(|(key, _)| key.clone()).collect();
        assert_eq!(keys, heights, "{who}: {}", String::from_utf8_lossy(name));
    }
    db.view(|tx| {
        for (height, want) in &reference.stake_undo {
            let got = db_fetch_block_undo_data(tx, *height as u32).expect("undo row");
            assert_eq!(got, *want, "{who}: stake undo at {height}");
        }
        for (height, want) in &reference.stake_new_tickets {
            let got = db_fetch_new_tickets(tx, *height as u32).expect("tickets row");
            assert_eq!(got, *want, "{who}: new tickets at {height}");
        }
        Ok(())
    })
    .expect("read the stake rows");
    assert!(!reference.stake_undo.is_empty() && !reference.stake_new_tickets.is_empty());

    // The block index holds every block with data, each under its own
    // header's height and hash.
    let mut stored = BTreeSet::new();
    for (key, value) in &all[BLOCK_INDEX] {
        let (height, hash) = decode(chain, key, "block index");
        let (header, _) =
            BlockHeader::from_bytes(&value[BLOCK_LOCATION_LEN..]).expect("a stored header");
        assert_eq!(
            (header.height, header.block_hash()),
            (height, hash),
            "{who}"
        );
        stored.insert((height, hash));
    }
    let genesis = chain.block_hash_by_height(0).expect("genesis");
    let mut want = BTreeSet::new();
    for hash in known.iter().chain([&genesis]) {
        if let Some(id) = chain.index.lookup_node(hash)
            && chain.store.node(id).status.have_data()
        {
            want.insert((chain.store.node(id).height as u32, *hash));
        }
    }
    assert_eq!(stored, want, "{who}: block index rows");

    // And every stored block reads back, from the database.
    for (_, hash) in &stored {
        let block = chain.block_by_hash(hash).expect("a stored block");
        assert_eq!(block.header.block_hash(), *hash, "{who}");
    }
}

/// The two database-backed chains hold the same rows: the same keys in
/// every bucket and the same values, apart from where in the block files
/// each stored a block.
fn assert_same_rows(b: &Chain, c: &Chain) {
    let (b, c) = (
        rows(b.db.as_ref().expect("db")),
        rows(c.db.as_ref().expect("db")),
    );
    for name in BUCKETS {
        let strip = |rows: &[(Vec<u8>, Vec<u8>)]| -> Vec<(Vec<u8>, Vec<u8>)> {
            rows.iter()
                .map(|(key, value)| {
                    let skip = if name == BLOCK_INDEX {
                        BLOCK_LOCATION_LEN
                    } else {
                        0
                    };
                    (key.clone(), value[skip..].to_vec())
                })
                .collect()
        };
        assert_eq!(
            strip(&b[name]),
            strip(&c[name]),
            "{}",
            String::from_utf8_lossy(name)
        );
    }
}

#[test]
fn reorganizations_after_restarts_read_the_rows_under_their_heights() {
    let params = regnet_params();
    let (now, steps) = battery();
    let known: Vec<Hash> = steps
        .iter()
        .filter_map(Step::block)
        .map(|block| block.header.block_hash())
        .collect();
    let first_side = steps
        .iter()
        .position(|step| matches!(step, Step::Accept(_, _, false, false)))
        .expect("a side chain block");
    // From a few blocks before the first fork, so the fork point's rows
    // come from the database too.
    let restart_from = first_side.saturating_sub(4);

    let mut a = Chain::new(&params, Hash::ZERO, false);
    let dir = TempDir::new().expect("tempdir");
    let opts_b = Options::new(dir.path().join("b"), params.net.0);
    let opts_c = Options::new(dir.path().join("c"), params.net.0);
    let open = |opts: &Options| {
        let db = Database::create(opts).expect("create database");
        Chain::open(db, &params, Hash::ZERO, false, 0).expect("open chain")
    };
    let (mut b, mut c) = (open(&opts_b), open(&opts_c));

    let mut restarts = 0;
    for (i, step) in steps.iter().enumerate() {
        run_step(&mut a, step, now, &params, "reference");
        run_step(&mut b, step, now, &params, "database");
        if i >= restart_from && step.block().is_some() && !top_work_tie(&c, &known) {
            c = restart(c, &opts_c, &params, true);
            restarts += 1;
        }
        run_step(&mut c, step, now, &params, "restarted");
    }
    assert!(restarts > 100, "{restarts} restarts");

    b = restart(b, &opts_b, &params, false);
    c = restart(c, &opts_c, &params, true);
    check_against_reference("database", &b, &a, &known);
    check_against_reference("restarted", &c, &a, &known);
    assert_same_rows(&b, &c);

    // Invalidate the main chain block at each of the four highest
    // heights where a valid side chain block with data sits, which
    // reorganizes onto that side chain (disconnecting the main chain
    // blocks from the tip down, reading their bodies and journal rows
    // back), then reconsider it, which reorganizes back.
    let tip = a.best_snapshot().height;
    let mut forks: Vec<i64> = known
        .iter()
        .filter_map(|hash| a.index.lookup_node(hash).map(|id| (hash, a.store.node(id))))
        .filter(|(hash, node)| {
            node.height > 0
                && node.status.have_data()
                && !node.status.known_invalid()
                && a.block_hash_by_height(node.height) != Some(**hash)
        })
        .map(|(_, node)| node.height)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    forks.reverse();
    forks.truncate(4);
    assert_eq!(
        forks.len(),
        4,
        "side chain heights near the tip {tip}: {forks:?}"
    );
    for height in forks {
        let victim = a.block_hash_by_height(height).expect("a main chain block");
        let errs = a.invalidate_block(&victim, now, &params);
        assert!(errs.is_empty(), "{errs:?}");
        assert_ne!(
            a.block_hash_by_height(height),
            Some(victim),
            "{victim} disconnected"
        );
        assert!(
            a.best_snapshot().height >= height,
            "onto the side chain at {height}"
        );
        let errs = b.invalidate_block(&victim, now, &params);
        assert!(errs.is_empty(), "{errs:?}");
        c = restart(c, &opts_c, &params, true);
        let errs = c.invalidate_block(&victim, now, &params);
        assert!(errs.is_empty(), "{errs:?}");
        b = restart(b, &opts_b, &params, false);
        c = restart(c, &opts_c, &params, true);
        check_against_reference("database, invalidated", &b, &a, &known);
        check_against_reference("restarted, invalidated", &c, &a, &known);
        assert_same_rows(&b, &c);

        let errs = a.reconsider_block(&victim, now, &params);
        assert!(errs.is_empty(), "{errs:?}");
        assert_eq!(a.best_snapshot().height, tip, "back to the tip");
        let errs = b.reconsider_block(&victim, now, &params);
        assert!(errs.is_empty(), "{errs:?}");
        c = restart(c, &opts_c, &params, true);
        let errs = c.reconsider_block(&victim, now, &params);
        assert!(errs.is_empty(), "{errs:?}");
        b = restart(b, &opts_b, &params, false);
        c = restart(c, &opts_c, &params, true);
        check_against_reference("database, reconsidered", &b, &a, &known);
        check_against_reference("restarted, reconsidered", &c, &a, &known);
        assert_same_rows(&b, &c);
    }
}
