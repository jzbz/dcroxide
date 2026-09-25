// SPDX-License-Identifier: ISC
//! The chain open logs dcrd's CHAN startup lines, and sizes the UTXO
//! cache before its catch-up replay.
//!
//! dcrd's `blockchain.New` runs with the package logger already
//! installed (`log.go:85`) and the UTXO cache already built with its
//! `MaxSize` (`server.go:4005-4009`).  So its open reports the block
//! index load, the UTXO cache initialization that brackets any catch-up
//! replay after a crash, and the chain state it arrived at
//! (`chainio.go:1570-1761`, `utxocache.go:816-1039`,
//! `chain.go:2486-2537`), and that replay flushes at the configured
//! size.  The port's daemon installed its sink and applied
//! `--utxocachemaxsize` only once `Chain::open` had returned: none of
//! those lines was emitted, and the replay after a crash ran silently
//! at the default size.

// Test-harness arithmetic over bounded heights.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use dcroxide_blockchain::RuleErrorKind;
use dcroxide_blockchain::chaindb::{DEPLOYMENT_VER_KEY_NAME, db_fetch_utxo_set_state};
use dcroxide_blockchain::notifications::{LogCallback, LogLevel};
use dcroxide_blockchain::process::{Chain, OpenConfig};
use dcroxide_blockchain::thresholdstate::current_deployment_version;
use dcroxide_chaincfg::{Params, regnet_params, simnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options, SharedBackend, StorageBackend};
use dcroxide_testutil::unhex;
use dcroxide_wire::MsgBlock;
use tempfile::TempDir;

type Captured = Arc<Mutex<Vec<(LogLevel, String)>>>;

/// A log sink that records every line, and the record it fills.
fn capture() -> (Captured, LogCallback) {
    let lines: Captured = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&lines);
    let callback: LogCallback = Box::new(move |level, msg| {
        sink.lock().expect("sink").push((level, msg.to_string()));
    });
    (lines, callback)
}

/// One expected line: exact, or matched by its prefix where it carries
/// a measured duration.
enum Want {
    Exact(LogLevel, String),
    Prefix(LogLevel, &'static str),
}

fn info(msg: impl Into<String>) -> Want {
    Want::Exact(LogLevel::Info, msg.into())
}

fn debug(msg: impl Into<String>) -> Want {
    Want::Exact(LogLevel::Debug, msg.into())
}

/// dcrd's "Loading block index..." and, where the crate has a clock
/// (the `std` feature), the debug timing line that follows it.
fn block_index_load() -> Vec<Want> {
    let mut want = vec![info("Loading block index...")];
    if cfg!(feature = "std") {
        want.push(Want::Prefix(LogLevel::Debug, "Block index loaded in "));
    }
    want
}

/// dcrd's "Deployment version N loaded", which it skips on a network
/// that tracks no deployments.
fn deployment_version(params: &Params) -> Vec<Want> {
    match current_deployment_version(params) {
        0 => Vec::new(),
        version => vec![info(format!("Deployment version {version} loaded"))],
    }
}

/// The lines that end dcrd's `blockchain.New`, from the opened chain's
/// own state: the version lines carry dcrd's current versions, and
/// progress is `VerifyProgress`.
fn chain_opened(chain: &Chain) -> Vec<Want> {
    let (header_hash, header_height) = chain.best_header();
    let tip = chain.best_chain.tip().expect("tip");
    let node = chain.store.node(tip);
    let progress = if header_height == 0 {
        0.0
    } else {
        (node.height as f64 / header_height as f64).min(1.0) * 100.0
    };
    vec![
        info(
            "Blockchain database version info: chain: 14, compression: 1, block index: 3, \
             spend journal: 3",
        ),
        info("UTXO database version info: version: 3, compression: 1, utxo set: 3"),
        info(format!(
            "Best known header: height {header_height}, hash {header_hash}"
        )),
        info(format!(
            "Chain state: height {}, hash {}, total transactions {}, work {}, progress {:.2}%",
            node.height,
            node.hash,
            chain.best_snapshot().total_txns,
            node.work_sum,
            progress
        )),
    ]
}

fn assert_lines(captured: &Captured, want: &[Want]) {
    let got = captured.lock().expect("sink").clone();
    assert_eq!(
        got.len(),
        want.len(),
        "line count differs from dcrd's; saw {got:#?}"
    );
    for (i, (got, want)) in got.iter().zip(want).enumerate() {
        match want {
            Want::Exact(level, msg) => {
                assert_eq!(
                    (&got.0, &got.1),
                    (level, msg),
                    "line {i} differs from dcrd's"
                );
            }
            Want::Prefix(level, prefix) => {
                assert_eq!(&got.0, level, "line {i}'s level differs from dcrd's");
                assert!(
                    got.1.starts_with(prefix) && got.1.len() > prefix.len(),
                    "line {i} is {:?}, not {prefix:?} and a duration",
                    got.1
                );
            }
        }
    }
}

/// A fresh database and a clean restart both log dcrd's startup lines
/// in its order, with the configured cache size.  A fresh dcrd logs the
/// index load too: `initChainState` loads what `createChainState` has
/// just written.
#[test]
fn a_fresh_open_and_a_restart_log_dcrds_startup_lines() {
    // Simnet with a hard-coded assumed valid block of genesis, so both
    // opens reach the two debug lines logged once the index knows that
    // block (`process.go:86`, `chainio.go:1758`).
    let mut params = simnet_params();
    let genesis = params.genesis_block.header.block_hash();
    params.assume_valid = genesis;

    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let open = |db: Database, max_mib: u64| {
        let (lines, sink) = capture();
        let mut config = OpenConfig::new(genesis, false, 0);
        config.log = Some(sink);
        config.utxo_cache_max_bytes = max_mib * 1024 * 1024;
        let chain = Chain::open_with_config(db, &params, config).expect("open chain");
        (chain, lines)
    };
    let checkpoint_and_assume_valid = || {
        vec![
            debug(format!(
                "Fork rejection checkpoint set to {genesis} (height 0)"
            )),
            debug(format!("Assumed valid node is {genesis} (height 0)")),
        ]
    };

    let (chain, lines) = open(Database::create(&opts).expect("create database"), 30);
    let mut want = block_index_load();
    want.extend(checkpoint_and_assume_valid());
    want.extend(deployment_version(&params));
    want.push(info("UTXO cache initializing (max size: 30 MiB)..."));
    want.push(info("UTXO cache initialization completed"));
    want.extend(chain_opened(&chain));
    assert_lines(&lines, &want);
    assert_eq!(
        chain.best_header(),
        (genesis, 0),
        "a fresh chain is at genesis"
    );
    let db = chain.db.clone().expect("db");
    drop(chain);
    db.close().expect("close");
    drop(db);

    let (chain, lines) = open(Database::open(&opts).expect("reopen database"), 1024);
    let mut want = block_index_load();
    want.extend(checkpoint_and_assume_valid());
    want.extend(deployment_version(&params));
    want.push(info("UTXO cache initializing (max size: 1024 MiB)..."));
    want.push(info("UTXO cache initialization completed"));
    want.extend(chain_opened(&chain));
    assert_lines(&lines, &want);
}

/// `Chain::open` keeps dcrd's disabled default: with no sink the open
/// logs nothing, and a sink installed afterwards has missed it all.
#[test]
fn a_sink_installed_after_the_open_sees_none_of_it() {
    let params = simnet_params();
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
    let (lines, sink) = capture();
    chain.set_log_callback(sink);
    // Installed after the open, the sink has seen nothing of it.
    assert_lines(&lines, &[]);
}

/// Replay the full block battery with the clock shifted forward by
/// `clock_offset`.  Two days makes every block look old, so the chain
/// never latches to current and only the periodic interval flushes the
/// UTXO cache: the initial-sync cadence whose unflushed tail an unclean
/// shutdown loses.
fn replay_battery(chain: &mut Chain, params: &Params, clock_offset: i64) {
    let mut now: i64 = 0;
    for line in include_str!("data/fullblock_vectors.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "now" => {
                now = f[1]
                    .parse::<i64>()
                    .expect("now")
                    .saturating_add(clock_offset)
            }
            "accept" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                let (_, errs) = chain.process_block(&block, now, params);
                let is_orphan = errs.len() == 1 && errs[0].kind == RuleErrorKind::MissingParent;
                assert!(errs.is_empty() || is_orphan, "accept {}: {errs:?}", f[1]);
            }
            _ => {}
        }
    }
}

fn recorded_flush_hash(db: &Database) -> Hash {
    let mut recorded = None;
    db.view(|tx| {
        recorded = db_fetch_utxo_set_state(tx).expect("state");
        Ok(())
    })
    .expect("read state");
    recorded.expect("a recorded utxo set state").last_flush_hash
}

/// After a crash the catch-up replay runs between dcrd's two UTXO cache
/// lines, and at the size the chain is opened with.
///
/// A one-byte cache is over its limit as soon as the replay commits a
/// block, so every replayed block flushes and the recorded state reaches
/// the tip within the open.  At the 150 MiB default, which is where the
/// port used to run the replay before the daemon's size arrived, the
/// open's clock never reaches the periodic interval and nothing flushes:
/// the recorded state stays where the crash left it.
#[test]
fn a_crash_catch_up_logs_between_dcrds_utxo_lines_at_the_opened_size() {
    let params = regnet_params();

    // The crash run: the per-block metadata reaches the store, but the
    // recorded utxo set state stays behind the tip.
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let mut chain = Chain::open(
        Database::create(&opts).expect("create database"),
        &params,
        Hash::ZERO,
        true,
        0,
    )
    .expect("open chain");
    replay_battery(&mut chain, &params, 48 * 60 * 60);
    let tip_hash = chain
        .best_chain
        .tip()
        .map(|t| chain.store.node(t).hash)
        .expect("tip");
    let db = chain.db.clone().expect("db");
    let behind = recorded_flush_hash(&db);
    assert_ne!(behind, tip_hash, "the crash run must leave a gap to replay");
    db.flush().expect("db flush");
    drop(chain);
    db.close().expect("close");
    drop(db);

    // The default size replays without flushing: the state the crash
    // left is still the recorded one after the open.
    {
        let db = Database::open(&opts).expect("reopen database");
        let chain =
            Chain::open_with_config(db.clone(), &params, OpenConfig::new(Hash::ZERO, true, 0))
                .expect("the catch-up completes");
        assert_eq!(
            recorded_flush_hash(&db),
            behind,
            "the default-size replay flushes nothing"
        );
        drop(chain);
        db.close().expect("close");
    }

    let (lines, sink) = capture();
    let mut config = OpenConfig::new(Hash::ZERO, true, 0);
    config.log = Some(sink);
    config.utxo_cache_max_bytes = 1;
    let db = Database::open(&opts).expect("reopen database");
    let chain =
        Chain::open_with_config(db.clone(), &params, config).expect("the catch-up completes");
    assert_eq!(
        chain.best_chain.tip().map(|t| chain.store.node(t).hash),
        Some(tip_hash)
    );
    assert_eq!(
        recorded_flush_hash(&db),
        tip_hash,
        "the replay must flush at the size the chain was opened with"
    );

    // dcrd prints the size in whole MiB, so a one-byte cache reads 0.
    let mut want = block_index_load();
    want.extend(deployment_version(&params));
    want.push(info("UTXO cache initializing (max size: 0 MiB)..."));
    want.push(info("UTXO cache initialization completed"));
    want.extend(chain_opened(&chain));
    assert_lines(&lines, &want);
}

/// An in-memory metadata store whose writes and syncs fail once armed:
/// a commit that has to flush then fails after its transaction body has
/// run.
#[derive(Debug, Default)]
struct FailingWrites {
    bytes: Mutex<Vec<u8>>,
    failing: AtomicBool,
}

impl FailingWrites {
    fn check(&self) -> Result<(), std::io::Error> {
        if self.failing.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("injected write failure"));
        }
        Ok(())
    }

    fn range(len: usize, offset: u64, n: usize) -> Result<std::ops::Range<usize>, std::io::Error> {
        let start = usize::try_from(offset)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        match start.checked_add(n) {
            Some(end) if end <= len => Ok(start..end),
            _ => Err(std::io::Error::from(std::io::ErrorKind::InvalidInput)),
        }
    }
}

impl StorageBackend for FailingWrites {
    fn len(&self) -> Result<u64, std::io::Error> {
        Ok(self.bytes.lock().expect("store lock").len() as u64)
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> Result<(), std::io::Error> {
        let bytes = self.bytes.lock().expect("store lock");
        let range = Self::range(bytes.len(), offset, out.len())?;
        out.copy_from_slice(&bytes[range]);
        Ok(())
    }

    fn set_len(&self, len: u64) -> Result<(), std::io::Error> {
        self.check()?;
        let len = usize::try_from(len)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        self.bytes.lock().expect("store lock").resize(len, 0);
        Ok(())
    }

    fn sync_data(&self) -> Result<(), std::io::Error> {
        self.check()
    }

    fn write(&self, offset: u64, data: &[u8]) -> Result<(), std::io::Error> {
        self.check()?;
        let mut bytes = self.bytes.lock().expect("store lock");
        let range = Self::range(bytes.len(), offset, data.len())?;
        bytes[range].copy_from_slice(data);
        Ok(())
    }
}

/// dcrd logs "Deployment version N loaded" inside the transaction that
/// records the version (`chainio.go:1570`), ahead of its commit, so a
/// commit that fails `New` still leaves the line printed before the
/// error.
#[test]
fn the_deployment_version_line_precedes_its_commit() {
    let params = simnet_params();
    let version = current_deployment_version(&params);
    assert!(version > 1, "simnet tracks deployments");

    let store = Arc::new(FailingWrites::default());
    let dir = TempDir::new().expect("tempdir");
    let mut opts = Options::new(dir.path().join("chain"), params.net.0);
    opts.backend = Some(Arc::clone(&store) as SharedBackend);
    // Any commit that leaves something in the overlay flushes it to the
    // store.
    opts.cache_max_size = 0;
    let db = Database::create(&opts).expect("create database");
    drop(Chain::open(db.clone(), &params, Hash::ZERO, false, 0).expect("open chain"));

    // An older recorded version leaves the next open a row to rewrite,
    // and a store that refuses writes fails that rewrite's commit.
    db.update(|tx| {
        tx.metadata()
            .put(DEPLOYMENT_VER_KEY_NAME, &(version - 1).to_le_bytes())
    })
    .expect("record an older deployment version");
    store.failing.store(true, Ordering::SeqCst);

    let (lines, sink) = capture();
    let mut config = OpenConfig::new(Hash::ZERO, false, 0);
    config.log = Some(sink);
    assert!(
        Chain::open_with_config(db, &params, config).is_err(),
        "the deployment version commit must fail"
    );
    let mut want = block_index_load();
    want.extend(deployment_version(&params));
    assert_lines(&lines, &want);
}
