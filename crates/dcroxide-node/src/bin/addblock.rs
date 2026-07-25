// SPDX-License-Identifier: ISC
//! The `addblock` tool (dcrd `cmd/addblock`): bulk-import blocks from
//! a bootstrap-format file into the block database, running each
//! block through the chain engine with bulk-import mode enabled and
//! maintaining the enabled indexes.

// The final tally mirrors Go's arithmetic over the import counters.
#![allow(clippy::arithmetic_side_effects)]

use std::path::Path;
use std::sync::{Arc, Mutex};

use dcroxide_blockchain::process::Chain;
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, ErrorKind, Options};
use dcroxide_node::addblock::{
    ADDBLOCK_HELP, AddblockConfig, AddblockConfigError, load_addblock_config, run_import,
};
use dcroxide_node::config::app_data_dir;
use dcroxide_node::go_duration_string;

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
    let opts = Options::new(&db_path, net);
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
    let home = app_data_dir(goos, "dcrd", false, &|name| std::env::var(name).ok());
    let default_data_dir = Path::new(&home).join("data").to_string_lossy().into_owned();

    let args: Vec<String> = std::env::args().skip(1).collect();
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

    // Load the block database (dcrd's `loadBlockDB`).
    let db = match load_block_db(&cfg, params.net.0) {
        Ok(db) => db,
        Err(e) => {
            log_error(&format!("Failed to load database: {e}"));
            return Err(());
        }
    };

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
    let chain = match Chain::open(db.clone(), &params, Hash([0u8; 32]), false, created_unix) {
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

    if cfg.tx_index {
        log_info("Transaction index is enabled");
    }
    if !cfg.no_exists_addr_index {
        log_info("Exists address index is enabled");
    }
    let interrupt: dcroxide_indexers::Interrupt =
        Arc::new(core::sync::atomic::AtomicBool::new(false));
    let _indexes = match dcroxide_node::indexes::start_indexes(
        interrupt,
        Arc::new(db),
        Arc::clone(&chain),
        params.clone(),
        cfg.tx_index,
        !cfg.no_exists_addr_index,
    ) {
        Ok(indexes) => indexes,
        Err(e) => {
            log_error(&format!("Failed create block importer: {e}"));
            return Err(());
        }
    };

    log_info("Starting import");
    let mut log = |msg: String| log_info(&msg);
    let (stats, err) = run_import(&chain, &params, &mut infile, cfg.progress, &mut log);
    if let Some(err) = err {
        log_error(&err);
        return Err(());
    }

    // Make the import durable (dcrd's deferred `db.Close()` flushes
    // the database write cache).
    if let Err(e) = chain.lock().expect("chain mutex poisoned").flush(&params) {
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
}
