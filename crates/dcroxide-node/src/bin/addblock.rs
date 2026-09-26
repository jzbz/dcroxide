// SPDX-License-Identifier: ISC
//! The `addblock` tool (dcrd `cmd/addblock`): bulk-import blocks from
//! a bootstrap-format file into the block database, running each
//! block through the chain engine with bulk-import mode enabled and
//! maintaining the enabled indexes.

// The final tally mirrors Go's arithmetic over the import counters.
#![allow(clippy::arithmetic_side_effects)]

use std::path::Path;
use std::sync::{Arc, Mutex};

use dcroxide_blockchain::process::{Chain, OpenConfig};
use dcroxide_chaincfg::Params;
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, ErrorKind, Options};
use dcroxide_node::addblock::{
    ADDBLOCK_HELP, AddblockConfig, AddblockConfigError, load_addblock_config, run_import,
};
use dcroxide_node::config::{REFUSED_DEFAULT_HOME, app_data_dir};
use dcroxide_node::go_duration_string;

/// The UTXO cache size dcrd's addblock imports with, in bytes (a fixed
/// `100 * 1024 * 1024` in `newBlockImporter`,
/// `cmd/addblock/import.go:318`; the tool has no flag for it).
const ADDBLOCK_UTXO_CACHE_MAX_BYTES: u64 = 100 * 1024 * 1024;

/// dcrd's addblock logs through slog subsystem loggers on stdout; the
/// port keeps the daemon's minimal level+tag line style.
fn log_info(msg: &str) {
    dcroxide_node::logging::info("MAIN", msg);
}

fn log_error(msg: &str) {
    dcroxide_node::logging::error("MAIN", msg);
}

/// Open the block database, creating it when it does not yet exist
/// (dcrd addblock's `loadBlockDB` over `database.Open` then
/// `database.Create`).
fn load_block_db(cfg: &AddblockConfig, net: u32) -> Result<Database, String> {
    let db_path = Path::new(&cfg.data_dir).join(format!("blocks_{}", cfg.db_type));
    log_info(&format!(
        "Loading block database from '{}'",
        db_path.display()
    ));
    let mut opts = Options::new(&db_path, net);
    // dcrd's addblock hands the database driver its BCDB logger
    // (`database.UseLogger(backendLogger.Logger("BCDB"))`,
    // `cmd/addblock/addblock.go:76`), so a repair or a corrupt store
    // found at open is reported here as the daemon reports it.
    opts.log = Some(dcroxide_node::logging::bcdb_log_sink());
    let db = match Database::open(&opts) {
        Ok(db) => db,
        Err(e) if e.kind == ErrorKind::DbDoesNotExist => {
            // dcrd's addblock creates the data directory owner-only
            // (`os.MkdirAll(cfg.DataDir, 0700)`, `cmd/addblock/addblock.go`
            // 48), and ffldb then makes the database directory beneath
            // it 0700 as well; `std::fs::create_dir_all` would leave
            // both 0755 under the usual umask.
            dcroxide_database::create_dir_all_owner_only(&db_path)
                .map_err(|e| format!("unable to create database directory: {e}"))?;
            Database::create(&opts).map_err(|e| e.to_string())?
        }
        Err(e) => return Err(e.to_string()),
    };
    log_info("Block database loaded");
    Ok(db)
}

/// The real main (dcrd's `realMain`, whose error return `os.Exit(1)`s).
fn real_main() -> Result<(), ()> {
    // Load configuration and parse the command line (dcrd's
    // `loadConfig`; the help exit is also an error exit, a dcrd quirk).
    let goos = match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    };
    // A `$HOME` a `String` cannot hold is refused, as argv is, rather
    // than read as unset, which put the default data directory in the
    // current directory (`flags::getenv_utf8`).
    let env_refused = std::cell::RefCell::new(None);
    let home = app_data_dir(goos, "dcroxide", false, &|name| {
        dcroxide_node::flags::getenv_utf8(name, &env_refused)
    });
    // With that lookup refused, dcrd's default holds bytes no `--datadir`
    // can spell, so the "." it fell back to must not stand in for it: a
    // `--datadir=./data` is not the default.
    let home = if env_refused.borrow().is_some() {
        String::from(REFUSED_DEFAULT_HOME)
    } else {
        home
    };
    let default_data_dir = Path::new(&home).join("data").to_string_lossy().into_owned();

    let args: Vec<String> = match dcroxide_node::flags::args_after_program() {
        Ok(args) => args,
        Err(bad) => {
            log_error(&format!(
                "invalid UTF-8 in command line argument: {}",
                bad.to_string_lossy()
            ));
            return Err(());
        }
    };
    let (cfg, params) = match load_addblock_config(&args, &default_data_dir) {
        Ok(loaded) => loaded,
        Err(AddblockConfigError::Help) => {
            print!("{ADDBLOCK_HELP}");
            return Err(());
        }
        Err(AddblockConfigError::Error(msg)) => {
            eprintln!("{msg}");
            eprint!("{ADDBLOCK_HELP}");
            return Err(());
        }
    };
    // Refused only now, so the help and configuration exits stay dcrd's,
    // and before the import opens anything under the default data
    // directory.  A `--datadir` naming another leaves the default, and the
    // `$HOME` dcrd reads for it at package init, unused, so dcrd's import
    // runs: refused only when the data directory is the default one.
    let default_net_dir = Path::new(&default_data_dir)
        .join(params.name)
        .to_string_lossy()
        .into_owned();
    if cfg.data_dir == default_net_dir
        && let Some(err) = env_refused.take()
    {
        log_error(&err);
        return Err(());
    }

    import_main(&cfg, &params)
}

/// Closes the block database however [`import_main`] returns once it
/// has opened it (dcrd's deferred `db.Close()` straight after
/// `loadBlockDB`, `cmd/addblock/addblock.go:86`).  The close flushes
/// the database write cache, so an import that stops on a bad block or
/// a short read keeps every block processed before the error, as
/// dcrd's does.  Held from right after the open, it drops after
/// everything built later.
struct BlockDbCloser(Database);

impl Drop for BlockDbCloser {
    fn drop(&mut self) {
        if let Err(e) = self.0.close() {
            // dcrd discards the deferred close's error; it is logged
            // here, as the daemon logs its own, so a close whose flush
            // failed does not pass silently.
            log_error(&format!("Unable to close the block database: {e}"));
        }
    }
}

/// The part of `realMain` after the configuration is loaded: load the
/// database, open the input file, build the importer and run it.
fn import_main(cfg: &AddblockConfig, params: &Params) -> Result<(), ()> {
    // Load the block database (dcrd's `loadBlockDB`).
    let db = match load_block_db(cfg, params.net.0) {
        Ok(db) => db,
        Err(e) => {
            log_error(&format!("Failed to load database: {e}"));
            return Err(());
        }
    };
    let _db_closer = BlockDbCloser(db.clone());

    // Open the input file before any chain or index work (dcrd's
    // `realMain` opens it between `loadBlockDB` and
    // `newBlockImporter`).
    let mut infile = match std::fs::File::open(&cfg.in_file) {
        Ok(f) => f,
        Err(e) => {
            log_error(&format!("Failed to open file {}: {}", cfg.in_file, e));
            return Err(());
        }
    };

    // Initialize the chain over the database (a fresh database creates
    // the genesis chain state) and create the enabled indexes, catching
    // them up to the main chain — dcrd's `newBlockImporter` body, whose
    // failures all report as a failed importer.  dcrd's addblock builds
    // its chain without an assume-valid anchor, so every imported block
    // validates fully — though bulk-import mode below skips the script
    // checks either way.  The indexes are NOT maintained during the
    // import (dcrd's chain never notifies the subscriber; the daemon's
    // server does, and addblock has no server), so the imported blocks
    // index on the next daemon start's catch-up.
    let created_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut config = OpenConfig::new(Hash([0u8; 32]), false, created_unix);
    // dcrd's addblock hands the chain its CHAN logger
    // (`blockchain.UseLogger(backendLogger.Logger("CHAN"))`,
    // `cmd/addblock/addblock.go:77`) before the chain is built, so the
    // open's startup lines, and whatever the chain logs during the
    // import, print as they do there.
    config.log = Some(dcroxide_node::chainntfns::chain_log_sink());
    // dcrd's addblock builds its UTXO cache at a fixed 100 MiB, not the
    // daemon's 150 MiB default (`cmd/addblock/import.go:315-319`), and
    // ahead of `blockchain.New`.
    config.utxo_cache_max_bytes = ADDBLOCK_UTXO_CACHE_MAX_BYTES;
    let chain = match Chain::open_with_config(db.clone(), params, config) {
        Ok(chain) => chain,
        Err(e) => {
            log_error(&format!("Failed create block importer: {e:?}"));
            return Err(());
        }
    };
    let chain = Arc::new(Mutex::new(chain));

    // Enable bulk import mode to allow several validation checks to be
    // skipped when importing blocks (dcrd `chain.EnableBulkImportMode`).
    chain.lock().expect("chain mutex poisoned").bulk_import_mode = true;

    // dcrd's addblock binds the indexers' package logger to INDX
    // (`indexers.UseLogger(backendLogger.Logger("INDX"))`,
    // `cmd/addblock/addblock.go:78`) and announces each enabled index
    // under its own MAIN logger just ahead of creating it
    // (`cmd/addblock/import.go:344`, `:352`).
    let logs = dcroxide_node::indexes::IndexLogs {
        indexers: Some(dcroxide_node::logging::indx_log_sink()),
        announce: Some(dcroxide_node::logging::subsystem_log_sink("MAIN")),
    };
    let interrupt: dcroxide_indexers::Interrupt =
        Arc::new(core::sync::atomic::AtomicBool::new(false));
    let _indexes = match dcroxide_node::indexes::start_indexes(
        interrupt,
        Arc::new(db),
        Arc::clone(&chain),
        params.clone(),
        cfg.tx_index,
        !cfg.no_exists_addr_index,
        &logs,
    ) {
        Ok(indexes) => indexes,
        Err(e) => {
            log_error(&format!("Failed create block importer: {e}"));
            return Err(());
        }
    };

    log_info("Starting import");
    let mut log = |msg: String| log_info(&msg);
    let (stats, err) = run_import(&chain, params, &mut infile, cfg.progress, &mut log);
    if let Some(err) = err {
        log_error(&err);
        return Err(());
    }

    // Make the import durable (dcrd's deferred `db.Close()` flushes
    // the database write cache).
    if let Err(e) = chain.lock().expect("chain mutex poisoned").flush(params) {
        log_error(&format!("Failed to flush the block database: {e:?}"));
        return Err(());
    }

    log_info(&format!(
        "Processed a total of {} blocks ({} imported, {} already known) in {}",
        stats.blocks_processed,
        stats.blocks_imported,
        stats.blocks_processed - stats.blocks_imported,
        go_duration_string(stats.duration_nanos),
    ));

    Ok(())
}

fn main() {
    if real_main().is_err() {
        std::process::exit(1);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// dcrd's addblock makes the data directory with
    /// `os.MkdirAll(cfg.DataDir, 0700)` before `database.Create`, so
    /// importing into a `--datadir` on a shared path does not leave a
    /// tree every local user can walk.
    #[test]
    fn the_created_data_directory_is_owner_only() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("data").join("mainnet");
        let cfg = AddblockConfig {
            data_dir: data_dir.to_string_lossy().into_owned(),
            db_type: "redb".to_string(),
            test_net: false,
            sim_net: false,
            in_file: "bootstrap.dat".to_string(),
            no_exists_addr_index: false,
            tx_index: false,
            progress: 10,
        };

        let db = load_block_db(&cfg, 0x0709_1101).unwrap();
        db.close().unwrap();

        let db_path = data_dir.join("blocks_redb");
        assert_eq!(
            mode_of(&db_path),
            0o700,
            "the block database directory must be owner-only"
        );
        assert_eq!(
            mode_of(&data_dir),
            0o700,
            "the data directory addblock creates must be owner-only"
        );
    }

    /// The leading consecutive main-chain prefix of accepted blocks
    /// from dcrd's `fullblocktests.Generate` battery, as raw block
    /// bytes (regnet).
    fn accepted_prefix_raw(limit: usize) -> Vec<Vec<u8>> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../dcroxide-blockchain/tests/data/fullblock_vectors.txt"
        );
        let data = std::fs::read_to_string(path).expect("fullblock vectors");
        let mut tip = dcroxide_chaincfg::regnet_params().genesis_hash;
        let mut blocks = Vec::new();
        for line in data.lines() {
            let f: Vec<&str> = line.split(' ').collect();
            if f[0] != "accept" {
                continue;
            }
            let raw = dcroxide_testutil::unhex(f[4]);
            let (block, _) = dcroxide_wire::MsgBlock::from_bytes(&raw).expect("block");
            if f[2] != "true" || block.header.prev_block != tip {
                continue;
            }
            tip = block.header.block_hash();
            blocks.push(raw);
            if blocks.len() == limit {
                break;
            }
        }
        assert_eq!(blocks.len(), limit, "battery must provide the prefix");
        blocks
    }

    /// dcrd defers `db.Close()` straight after `loadBlockDB`, and the
    /// close flushes the database write cache, so an import that stops
    /// on a block that does not link keeps every block processed
    /// before the error.  Without the close the blocks sit in the
    /// metadata overlay and are lost when the tool exits.
    #[test]
    fn a_failed_import_keeps_the_blocks_processed_before_the_error() {
        let params = dcroxide_chaincfg::regnet_params();
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("data");

        // Blocks one and three: the second record does not link.
        let blocks = accepted_prefix_raw(3);
        let mut stream = Vec::new();
        for raw in [&blocks[0], &blocks[2]] {
            dcroxide_database::bootstrap::write_block(&mut stream, params.net.0, raw)
                .expect("write record");
        }
        let in_file = tmp.path().join("bootstrap.dat");
        std::fs::write(&in_file, &stream).unwrap();

        let cfg = AddblockConfig {
            data_dir: data_dir.to_string_lossy().into_owned(),
            db_type: "ffldb".to_string(),
            test_net: false,
            sim_net: false,
            in_file: in_file.to_string_lossy().into_owned(),
            no_exists_addr_index: false,
            tx_index: false,
            progress: 10,
        };
        assert_eq!(import_main(&cfg, &params), Err(()), "the gap must fail");

        // The next open finds the first block on the main chain.
        let db = Database::open(&Options::new(data_dir.join("blocks_ffldb"), params.net.0))
            .expect("reopen the database");
        let chain = Chain::open(db.clone(), &params, Hash([0u8; 32]), false, 0).expect("chain");
        let (first, _) = dcroxide_wire::MsgBlock::from_bytes(&blocks[0]).expect("block");
        let best = chain.best_snapshot();
        assert_eq!(
            (best.height, best.hash),
            (1, first.header.block_hash()),
            "the block imported before the error must persist"
        );
        drop(chain);
        db.close().unwrap();
    }
}
