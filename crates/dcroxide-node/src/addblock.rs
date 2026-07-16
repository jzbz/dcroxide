// SPDX-License-Identifier: ISC
//! The `addblock` tool's decision core (dcrd `cmd/addblock`): the
//! go-flags configuration front-end over the shared scanner, and the
//! bulk block importer that reads dcrd's bootstrap file format
//! (`<network u32> <length u32> <serialized block>` records) and runs
//! each block through the chain engine with bulk-import mode enabled.
//!
//! dcrd splits the importer across three goroutines (a reader, a
//! processor, and a status collector) purely to overlap file reads
//! with block processing; the port runs the same loop synchronously —
//! the observable record handling, error texts, and progress logging
//! are identical, only the read/process overlap is traded away.

// The importer mirrors Go's arithmetic over bounded counters and the
// calendar math over `div_euclid`/`rem_euclid` outputs.
#![allow(clippy::arithmetic_side_effects)]

use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::{RuleErrorKind, render_multi_error};
use dcroxide_chaincfg::Params;
use dcroxide_chainhash::Hash;
use dcroxide_wire::{MAX_BLOCK_PAYLOAD, MsgBlock};

use crate::flags::{OptKind, OptSpec, ScanMode};

/// The `addblock` configuration (dcrd `cmd/addblock/config.go`'s
/// `config` struct with its defaults applied).
#[derive(Debug, Clone)]
pub struct AddblockConfig {
    /// The dcrd data directory (`-b`/`--datadir`), namespaced by the
    /// selected network after validation.
    pub data_dir: String,
    /// The database backend (`--dbtype`).
    pub db_type: String,
    /// Use the test network (`--testnet`).
    pub test_net: bool,
    /// Use the simulation test network (`--simnet`).
    pub sim_net: bool,
    /// The file containing the blocks (`-i`/`--infile`).
    pub in_file: String,
    /// Do not build the exists address index (`--noexistsaddrindex`).
    pub no_exists_addr_index: bool,
    /// Build the transaction index (`--txindex`).
    pub tx_index: bool,
    /// Progress announcement interval in seconds (`-p`/`--progress`).
    pub progress: i64,
}

/// The `addblock` option registry (the go-flags struct tags of dcrd's
/// `config`, plus the help option go-flags registers itself).
pub const ADDBLOCK_OPTIONS: [OptSpec; 9] = [
    OptSpec {
        long: "datadir",
        short: Some('b'),
        field: "DataDir",
        kind: OptKind::Str,
    },
    OptSpec {
        long: "dbtype",
        short: None,
        field: "DbType",
        kind: OptKind::Str,
    },
    OptSpec {
        long: "testnet",
        short: None,
        field: "TestNet",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "simnet",
        short: None,
        field: "SimNet",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "infile",
        short: Some('i'),
        field: "InFile",
        kind: OptKind::Str,
    },
    OptSpec {
        long: "noexistsaddrindex",
        short: None,
        field: "NoExistsAddrIndex",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "txindex",
        short: None,
        field: "TxIndex",
        kind: OptKind::Bool,
    },
    OptSpec {
        long: "progress",
        short: Some('p'),
        field: "Progress",
        kind: OptKind::Int,
    },
    OptSpec {
        long: "help",
        short: Some('h'),
        field: "Help",
        kind: OptKind::Bool,
    },
];

/// The help text for the tool (go-flags `WriteHelp` renders this from
/// the struct tags; the text itself is hand-written like the daemon's
/// not-yet-generated help, while the exit paths keep dcrd's codes).
pub const ADDBLOCK_HELP: &str = "\
Usage:
  addblock [OPTIONS]

Application Options:
  -b, --datadir=          Location of the dcrd data directory
      --dbtype=           Database backend to use for the Block Chain
      --testnet           Use the test network
      --simnet            Use the simulation test network
  -i, --infile=           File containing the block(s)
      --noexistsaddrindex Do not build a full index of which addresses were
                          ever seen on the blockchain
      --txindex           Build a full hash-based transaction index which
                          makes all transactions available via the
                          getrawtransaction RPC
  -p, --progress=         Show a progress message each time this number of
                          seconds have passed -- Use 0 to disable progress
                          announcements

Help Options:
  -h, --help              Show this help message
";

/// How loading the configuration ended when it did not produce one.
#[derive(Debug)]
pub enum AddblockConfigError {
    /// Help was requested: the caller prints [`ADDBLOCK_HELP`] to
    /// stdout and exits 1 (dcrd's `loadConfig` returns the go-flags
    /// `ErrHelp` to `realMain`, whose caller `os.Exit(1)`s — help
    /// exits nonzero, a dcrd quirk kept as-is).
    Help,
    /// A parse or validation error: the caller prints the message and
    /// then the help text to stderr, and exits 1 (go-flags'
    /// `PrintErrors` plus `loadConfig`'s `parser.WriteHelp(os.Stderr)`).
    Error(String),
}

/// Load the `addblock` configuration from the command line (dcrd
/// `cmd/addblock`'s `loadConfig`): defaults, the go-flags parse over
/// the shared scanner, the mutually-exclusive network selection, the
/// database type validation, the per-network data directory
/// namespacing, and the input file existence check, with dcrd's exact
/// error texts.
pub fn load_addblock_config(
    args: &[String],
    default_data_dir: &str,
) -> Result<(AddblockConfig, Params), AddblockConfigError> {
    let mut cfg = AddblockConfig {
        data_dir: default_data_dir.to_string(),
        db_type: "ffldb".to_string(),
        test_net: false,
        sim_net: false,
        in_file: "bootstrap.dat".to_string(),
        no_exists_addr_index: false,
        tx_index: false,
        progress: 10,
    };
    let mut help = false;

    let (_state, err) = crate::flags::scan_args_in(
        &ADDBLOCK_OPTIONS,
        &mut |spec, value| {
            let val = value.unwrap_or("");
            match spec.long {
                "datadir" => cfg.data_dir = val.to_string(),
                "dbtype" => cfg.db_type = val.to_string(),
                "testnet" => cfg.test_net = true,
                "simnet" => cfg.sim_net = true,
                "infile" => cfg.in_file = val.to_string(),
                "noexistsaddrindex" => cfg.no_exists_addr_index = true,
                "txindex" => cfg.tx_index = true,
                "progress" => cfg.progress = crate::gostd::go_parse_int(val, 64)?,
                "help" => help = true,
                _ => {}
            }
            Ok(())
        },
        args,
        ScanMode::PassDoubleDash,
    );
    // go-flags raises ErrHelp the moment it parses the help option; the
    // single-pass scan approximates that by letting a parsed help flag
    // win over a later argument's error.
    if help {
        return Err(AddblockConfigError::Help);
    }
    if let Some(err) = err {
        return Err(AddblockConfigError::Error(err.message()));
    }

    // Multiple networks can't be selected simultaneously (dcrd counts
    // the flags and picks the params as it goes).
    let mut num_nets = 0;
    let mut params = dcroxide_chaincfg::mainnet_params();
    if cfg.test_net {
        num_nets += 1;
        params = dcroxide_chaincfg::testnet3_params();
    }
    if cfg.sim_net {
        num_nets += 1;
        params = dcroxide_chaincfg::simnet_params();
    }
    if num_nets > 1 {
        return Err(AddblockConfigError::Error(
            "loadConfig: the testnet, regtest, and simnet params can't be \
             used together -- choose one of the three"
                .to_string(),
        ));
    }

    // Validate database type (Go renders the supported slice as
    // `[ffldb]`).
    if cfg.db_type != "ffldb" {
        return Err(AddblockConfigError::Error(format!(
            "loadConfig: the specified database type [{}] is invalid -- supported types [ffldb]",
            cfg.db_type
        )));
    }

    // Namespace the data directory per network (dcrd
    // `filepath.Join(cfg.DataDir, activeNetParams.Name)`).
    cfg.data_dir = std::path::Path::new(&cfg.data_dir)
        .join(params.name)
        .to_string_lossy()
        .into_owned();

    // Ensure the specified block file exists (Go's `fileExists`
    // returns true unless the stat error is specifically
    // not-found, so a stat failure passes config validation and
    // surfaces later at the open).
    let exists = match std::fs::metadata(&cfg.in_file) {
        Ok(_) => true,
        Err(e) => e.kind() != std::io::ErrorKind::NotFound,
    };
    if !exists {
        return Err(AddblockConfigError::Error(format!(
            "loadConfig: the specified block file [{}] does not exist",
            cfg.in_file
        )));
    }

    Ok((cfg, params))
}

/// The import totals (dcrd `importResults` without the error, which
/// the run returns separately).
#[derive(Debug, Default, Clone, Copy)]
pub struct ImportRunStats {
    /// Every record processed, imported or already known.
    pub blocks_processed: i64,
    /// The records that were new to the chain.
    pub blocks_imported: i64,
    /// How long the run took, in nanoseconds.
    pub duration_nanos: i64,
}

/// The importer's progress-log state (dcrd `blockImporter`'s logging
/// fields driving `logProgress`).
struct ProgressLog {
    received_log_blocks: i64,
    received_log_tx: i64,
    last_height: i64,
    last_block_time_unix: i64,
    last_log_time: Instant,
    progress_secs: i64,
}

impl ProgressLog {
    /// dcrd `logProgress`: rate-limited progress announcements, with
    /// the duration truncated to 10s of milliseconds.  A zero (or
    /// negative) interval logs every block — dcrd's help text says
    /// zero disables the announcements, but the comparison it guards
    /// never fires then, a quirk kept as-is.
    fn log_progress(&mut self, log: &mut dyn FnMut(String)) {
        self.received_log_blocks += 1;

        let now = Instant::now();
        let duration = now.duration_since(self.last_log_time);
        // Go's `time.Second*time.Duration(cfg.Progress)` wraps on
        // int64 overflow, so an absurdly large interval flips to
        // logging every block; kept with the wrapping multiply.
        if (duration.as_nanos() as i64) < self.progress_secs.wrapping_mul(1_000_000_000) {
            return;
        }

        // Truncate the duration to 10s of milliseconds.
        let duration_millis = duration.as_millis() as i64;
        let tduration_nanos = 10 * 1_000_000 * (duration_millis / 10);

        let block_str = if self.received_log_blocks == 1 {
            "block"
        } else {
            "blocks"
        };
        let tx_str = if self.received_log_tx == 1 {
            "transaction"
        } else {
            "transactions"
        };
        log(format!(
            "Processed {} {} in the last {} ({} {}, height {}, {})",
            self.received_log_blocks,
            block_str,
            crate::gostd::go_duration_string(tduration_nanos),
            self.received_log_tx,
            tx_str,
            self.last_height,
            go_time_utc_string(self.last_block_time_unix),
        ));

        self.received_log_blocks = 0;
        self.received_log_tx = 0;
        self.last_log_time = now;
    }
}

/// Render a unix timestamp the way Go's default `time.Time` format
/// does for a whole-second time (`2006-01-02 15:04:05 +0000 UTC`).
/// dcrd renders the block time in the machine's local zone (the wire
/// decoder builds `time.Unix` values); the port pins UTC so the
/// output does not depend on the host zone database.
fn go_time_utc_string(unix: i64) -> String {
    // Civil-from-unix over the proleptic Gregorian calendar, per Howard
    // Hinnant's algorithm (the same math Go's time package performs).
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (hh, mm, ss) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}:{ss:02} +0000 UTC")
}

/// Read one block record from the bootstrap stream (dcrd `readBlock`):
/// `Ok(None)` is a clean end of file at the network field, and every
/// other truncation or mismatch is an error with dcrd's text.  Go's
/// `binary.Read` surfaces `io.EOF` only when no bytes were read at
/// all; a partial field is `unexpected EOF`.
fn read_block_record(r: &mut dyn Read, network: u32) -> Result<Option<Vec<u8>>, String> {
    // The network field: a clean EOF here means no more blocks.
    let mut net_bytes = [0u8; 4];
    match read_full(r, &mut net_bytes) {
        ReadFull::Eof => return Ok(None),
        ReadFull::Err(e) => return Err(e),
        ReadFull::Short => return Err("unexpected EOF".to_string()),
        ReadFull::Ok => {}
    }
    let net = u32::from_le_bytes(net_bytes);
    if net != network {
        return Err(format!("network mismatch -- got {net:x}, want {network:x}"));
    }

    // The block length, capped at the wire maximum.
    let mut len_bytes = [0u8; 4];
    match read_full(r, &mut len_bytes) {
        ReadFull::Eof => return Err("EOF".to_string()),
        ReadFull::Err(e) => return Err(e),
        ReadFull::Short => return Err("unexpected EOF".to_string()),
        ReadFull::Ok => {}
    }
    let block_len = u32::from_le_bytes(len_bytes);
    if block_len > MAX_BLOCK_PAYLOAD {
        return Err(format!(
            "block payload of {block_len} bytes is larger than the max allowed {MAX_BLOCK_PAYLOAD} bytes"
        ));
    }

    let mut serialized = vec![0u8; block_len as usize];
    match read_full(r, &mut serialized) {
        ReadFull::Eof => Err("EOF".to_string()),
        ReadFull::Err(e) => Err(e),
        ReadFull::Short => Err("unexpected EOF".to_string()),
        ReadFull::Ok => Ok(Some(serialized)),
    }
}

/// How a full read of a buffer ended (Go `io.ReadFull`'s outcomes:
/// filled, `io.EOF` on zero bytes, `io.ErrUnexpectedEOF` on a partial
/// fill, or an underlying error).
enum ReadFull {
    Ok,
    Eof,
    Short,
    Err(String),
}

fn read_full(r: &mut dyn Read, buf: &mut [u8]) -> ReadFull {
    if buf.is_empty() {
        return ReadFull::Ok;
    }
    let mut filled = 0usize;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => {
                return if filled == 0 {
                    ReadFull::Eof
                } else {
                    ReadFull::Short
                };
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return ReadFull::Err(e.to_string()),
        }
    }
    ReadFull::Ok
}

/// Process one serialized block (dcrd `blockImporter.processBlock`):
/// deserialize, skip already-known blocks, refuse blocks that do not
/// link to the available chain, run the chain rules, and require the
/// block to extend the main chain.  Returns whether the block was
/// imported.
fn process_one(
    chain: &Arc<Mutex<Chain>>,
    params: &Params,
    serialized: &[u8],
    progress: &mut ProgressLog,
) -> Result<bool, String> {
    let (block, _) = MsgBlock::from_bytes(serialized).map_err(|e| e.to_string())?;

    // Update the progress statistics (dcrd counts even blocks that
    // turn out to be already known, and only the regular tree).
    progress.last_block_time_unix = i64::from(block.header.timestamp);
    progress.received_log_tx += block.transactions.len() as i64;

    let block_hash = block.header.block_hash();
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    {
        let chain = chain.lock().expect("chain mutex poisoned");

        // Skip blocks that already exist.
        if chain.have_block(&block_hash) {
            return Ok(false);
        }

        // Don't bother trying to process orphans (dcrd prints the
        // missing parent hash in this text).
        let prev_hash = block.header.prev_block;
        if prev_hash != Hash([0u8; 32]) && !chain.have_block(&prev_hash) {
            return Err(format!(
                "import file contains block {prev_hash} which does not link to the available block chain"
            ));
        }
    }

    // Ensure the block follows all of the chain rules.
    let (fork_len, errs) = chain
        .lock()
        .expect("chain mutex poisoned")
        .process_block(&block, now_unix, params);
    if !errs.is_empty() {
        if errs.iter().any(|e| e.kind == RuleErrorKind::MissingParent) {
            return Err(format!(
                "import file contains an orphan block: {block_hash}"
            ));
        }
        return Err(render_multi_error(&errs));
    }
    if fork_len != 0 {
        return Err(format!(
            "import file contains a block that does not extend the main chain: {block_hash}"
        ));
    }

    Ok(true)
}

/// Run the import over the bootstrap stream (the synchronous body of
/// dcrd's read/process/status handler goroutines): read each record,
/// process it through the chain, and log progress.  Returns the
/// totals alongside the error that stopped the run, if any.
///
/// The enabled indexes are deliberately NOT maintained per block:
/// dcrd's chain never notifies the index subscriber (only the daemon's
/// server does, and addblock has no server), so its importer leaves
/// the index tip where the pre-import catch-up put it and the next
/// daemon start's catch-up indexes the imported blocks.
pub fn run_import(
    chain: &Arc<Mutex<Chain>>,
    params: &Params,
    r: &mut dyn Read,
    progress_secs: i64,
    log: &mut dyn FnMut(String),
) -> (ImportRunStats, Option<String>) {
    let start = Instant::now();
    let mut stats = ImportRunStats::default();
    let mut progress = ProgressLog {
        received_log_blocks: 0,
        received_log_tx: 0,
        last_height: 0,
        last_block_time_unix: 0,
        last_log_time: start,
        progress_secs,
    };

    let err = loop {
        let serialized = match read_block_record(r, params.net.0) {
            Ok(Some(serialized)) => serialized,
            Ok(None) => break None,
            Err(e) => break Some(format!("error reading from input file: {e}")),
        };

        stats.blocks_processed += 1;
        progress.last_height += 1;
        match process_one(chain, params, &serialized, &mut progress) {
            Ok(imported) => {
                if imported {
                    stats.blocks_imported += 1;
                }
                progress.log_progress(log);
            }
            Err(e) => break Some(e),
        }
    };

    stats.duration_nanos = start.elapsed().as_nanos() as i64;
    (stats, err)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strs(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    /// The defaults mirror dcrd's: mainnet, ffldb, bootstrap.dat,
    /// ten-second progress, and the network-namespaced data directory.
    #[test]
    fn defaults_and_network_namespacing() {
        let dir = tempfile::tempdir().expect("temp dir");
        let infile = dir.path().join("bootstrap.dat");
        std::fs::write(&infile, b"").expect("write infile");
        let args = strs(&["--infile", infile.to_str().expect("utf8 path")]);
        let (cfg, params) = match load_addblock_config(&args, "/tmp/dcrd-data") {
            Ok(loaded) => loaded,
            Err(AddblockConfigError::Error(e)) => panic!("unexpected error: {e}"),
            Err(AddblockConfigError::Help) => panic!("unexpected help"),
        };
        assert_eq!(params.name, "mainnet");
        assert_eq!(cfg.db_type, "ffldb");
        assert_eq!(cfg.progress, 10);
        assert!(
            std::path::Path::new(&cfg.data_dir).ends_with("mainnet"),
            "data dir must be network-namespaced: {}",
            cfg.data_dir
        );
        assert!(!cfg.tx_index);
        assert!(!cfg.no_exists_addr_index);
    }

    /// Multiple networks are refused with dcrd's exact error text.
    #[test]
    fn conflicting_networks_are_refused() {
        let args = strs(&["--testnet", "--simnet"]);
        match load_addblock_config(&args, "/tmp/dcrd-data") {
            Err(AddblockConfigError::Error(e)) => assert_eq!(
                e,
                "loadConfig: the testnet, regtest, and simnet params can't be \
                 used together -- choose one of the three"
            ),
            other => panic!(
                "expected the network conflict error, got {:?}",
                other.map(|_| ())
            ),
        }
    }

    /// An unsupported database type is refused with dcrd's text (Go
    /// renders the supported slice as `[ffldb]`).
    #[test]
    fn invalid_db_type_is_refused() {
        let args = strs(&["--dbtype", "leveldb"]);
        match load_addblock_config(&args, "/tmp/dcrd-data") {
            Err(AddblockConfigError::Error(e)) => assert_eq!(
                e,
                "loadConfig: the specified database type [leveldb] is invalid -- supported types [ffldb]"
            ),
            other => panic!("expected the db type error, got {:?}", other.map(|_| ())),
        }
    }

    /// A missing input file is refused with dcrd's text.
    #[test]
    fn missing_infile_is_refused() {
        let args = strs(&["-i", "/nonexistent/bootstrap.dat", "--simnet"]);
        match load_addblock_config(&args, "/tmp/dcrd-data") {
            Err(AddblockConfigError::Error(e)) => assert_eq!(
                e,
                "loadConfig: the specified block file [/nonexistent/bootstrap.dat] does not exist"
            ),
            other => panic!("expected the infile error, got {:?}", other.map(|_| ())),
        }
    }

    /// An unknown option surfaces go-flags' unknown-flag text through
    /// the shared scanner, and the help option wins.
    #[test]
    fn scanner_errors_and_help() {
        match load_addblock_config(&strs(&["--bogus"]), "/tmp/dcrd-data") {
            Err(AddblockConfigError::Error(e)) => assert_eq!(e, "unknown flag `bogus'"),
            other => panic!("expected unknown flag, got {:?}", other.map(|_| ())),
        }
        assert!(matches!(
            load_addblock_config(&strs(&["-h"]), "/tmp/dcrd-data"),
            Err(AddblockConfigError::Help)
        ));
        assert!(matches!(
            load_addblock_config(&strs(&["--help"]), "/tmp/dcrd-data"),
            Err(AddblockConfigError::Help)
        ));
        // A non-integer progress value wraps as go-flags' marshal error.
        match load_addblock_config(&strs(&["-p", "ten"]), "/tmp/dcrd-data") {
            Err(AddblockConfigError::Error(e)) => assert!(
                e.contains("invalid argument for flag `-p, --progress'")
                    && e.contains("expected int"),
                "unexpected marshal error: {e}"
            ),
            other => panic!("expected marshal error, got {:?}", other.map(|_| ())),
        }
    }

    /// The bootstrap record reader keeps dcrd's `readBlock` outcomes:
    /// clean EOF at the network field, `unexpected EOF` on partial
    /// fields, the network mismatch text, and the payload cap.
    #[test]
    fn record_reader_error_texts() {
        let net = 0x12345678u32;

        // Clean EOF.
        let mut empty: &[u8] = &[];
        assert!(matches!(read_block_record(&mut empty, net), Ok(None)));

        // A partial network field.
        let mut partial: &[u8] = &[0x78, 0x56];
        assert_eq!(
            read_block_record(&mut partial, net),
            Err("unexpected EOF".to_string())
        );

        // A mismatched network (Go %x renders lowercase hex without
        // leading zeros).
        let mut mismatched: &[u8] = &0xdeadbeefu32.to_le_bytes()[..];
        assert_eq!(
            read_block_record(&mut mismatched, net),
            Err("network mismatch -- got deadbeef, want 12345678".to_string())
        );

        // A missing length field is Go's io.EOF from binary.Read.
        let no_len = net.to_le_bytes().to_vec();
        assert_eq!(
            read_block_record(&mut no_len.as_slice(), net),
            Err("EOF".to_string())
        );

        // An oversized payload length.
        let mut oversized = net.to_le_bytes().to_vec();
        oversized.extend_from_slice(&(MAX_BLOCK_PAYLOAD + 1).to_le_bytes());
        assert_eq!(
            read_block_record(&mut oversized.as_slice(), net),
            Err(format!(
                "block payload of {} bytes is larger than the max allowed {} bytes",
                MAX_BLOCK_PAYLOAD + 1,
                MAX_BLOCK_PAYLOAD
            ))
        );

        // A truncated payload.
        let mut truncated = net.to_le_bytes().to_vec();
        truncated.extend_from_slice(&8u32.to_le_bytes());
        truncated.extend_from_slice(&[1, 2, 3]);
        assert_eq!(
            read_block_record(&mut truncated.as_slice(), net),
            Err("unexpected EOF".to_string())
        );

        // A whole record round-trips.
        let mut whole = net.to_le_bytes().to_vec();
        whole.extend_from_slice(&3u32.to_le_bytes());
        whole.extend_from_slice(&[9, 8, 7]);
        assert_eq!(
            read_block_record(&mut whole.as_slice(), net),
            Ok(Some(vec![9, 8, 7]))
        );
    }

    /// The Go default time rendering for whole-second UTC times.
    #[test]
    fn go_time_rendering() {
        assert_eq!(go_time_utc_string(0), "1970-01-01 00:00:00 +0000 UTC");
        // dcrd's mainnet genesis timestamp.
        assert_eq!(
            go_time_utc_string(1_454_954_400),
            "2016-02-08 18:00:00 +0000 UTC"
        );
        assert_eq!(
            go_time_utc_string(1_231_006_505),
            "2009-01-03 18:15:05 +0000 UTC"
        );
    }
}
