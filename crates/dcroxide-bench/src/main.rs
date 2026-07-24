// SPDX-License-Identifier: ISC
//! Development-only benchmark harness (no dcrd counterpart): replays
//! a bootstrap-format block corpus through the live chain engine —
//! full validation, exactly like a network sync but without the
//! network — and reports throughput.  `export` produces the corpus
//! file from a synced data directory; `replay` measures.
//!
//! The tool exists so every optimization piece lands with a number:
//! run `replay` on the same corpus before and after a change.

use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::{Params, mainnet_params, regnet_params, simnet_params, testnet3_params};
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options, bootstrap};
use dcroxide_wire::MsgBlock;

/// The command-line help.
const HELP: &str = "\
dcroxide-bench: replay a block corpus through the live chain engine

Usage:
  dcroxide-bench export --appdata <dir> --out <file> [--net <name>] [--max <n>]
      Export the main chain of a synced (and stopped) dcroxide data
      directory to a bootstrap-format corpus file.  Opening the source
      performs the node's own startup recovery (a running node holds
      the database lock and makes this fail cleanly).

  dcroxide-bench replay --in <file> [--net <name>] [--workdir <dir>]
                        [--assumevalid <hash>] [--max <n>] [--report <n>]
      Replay the corpus into a fresh chain with full live validation,
      reporting throughput every <n> blocks (default 5000).  The work
      directory (default: a fresh directory next to the corpus) must
      not already exist and is left behind for inspection.

  --net is one of mainnet, testnet, simnet, regnet (default mainnet).
";

/// A parsed flag map over the raw arguments.
struct Args {
    values: Vec<(String, String)>,
}

impl Args {
    fn parse(args: &[String], known: &[&str]) -> Result<Args, String> {
        let mut values: Vec<(String, String)> = Vec::new();
        let push =
            |values: &mut Vec<(String, String)>, name: &str, value: String| -> Result<(), String> {
                if !known.contains(&name) {
                    return Err(format!("unknown flag --{name}"));
                }
                if values.iter().any(|(n, _)| n == name) {
                    return Err(format!("--{name} given more than once"));
                }
                values.push((name.to_string(), value));
                Ok(())
            };
        let mut it = args.iter();
        while let Some(arg) = it.next() {
            let Some(name) = arg.strip_prefix("--") else {
                return Err(format!("unexpected argument {arg}"));
            };
            match name.split_once('=') {
                Some((n, v)) => push(&mut values, n, v.to_string())?,
                None => {
                    let value = it
                        .next()
                        .ok_or_else(|| format!("--{name} requires a value"))?;
                    push(&mut values, name, value.clone())?;
                }
            }
        }
        Ok(Args { values })
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.values
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    fn require(&self, name: &str) -> Result<&str, String> {
        self.get(name)
            .ok_or_else(|| format!("--{name} is required"))
    }
}

/// The network parameters and data-directory name for a --net value.
fn net_params(name: &str) -> Result<(Params, &'static str), String> {
    match name {
        "mainnet" => Ok((mainnet_params(), "mainnet")),
        "testnet" => Ok((testnet3_params(), "testnet3")),
        "simnet" => Ok((simnet_params(), "simnet")),
        "regnet" => Ok((regnet_params(), "regnet")),
        other => Err(format!("unknown network {other}")),
    }
}

/// Open the block database under a data directory.
fn open_db(data_dir: &Path, net: u32, create: bool) -> Result<Database, String> {
    let db_path = data_dir.join("blocks_ffldb");
    let opts = Options::new(&db_path, net);
    if create {
        std::fs::create_dir_all(&db_path)
            .map_err(|e| format!("unable to create database directory: {e}"))?;
        Database::create(&opts).map_err(|e| e.to_string())
    } else {
        Database::open(&opts).map_err(|e| e.to_string())
    }
}

/// The peak resident set size of this process in kibibytes, from
/// /proc/self/status (0 when unavailable).
fn peak_rss_kib() -> u64 {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return 0;
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            return rest
                .trim()
                .trim_end_matches(" kB")
                .trim()
                .parse()
                .unwrap_or(0);
        }
    }
    0
}

/// Export the source data directory's main chain as a corpus file.
fn cmd_export(args: &Args) -> Result<(), String> {
    let appdata = PathBuf::from(args.require("appdata")?);
    let out = PathBuf::from(args.require("out")?);
    let (params, net_dir) = net_params(args.get("net").unwrap_or("mainnet"))?;
    let max: i64 = match args.get("max") {
        Some(v) => v.parse().map_err(|e| format!("bad --max: {e}"))?,
        None => i64::MAX,
    };

    let data_dir = appdata.join("data").join(net_dir);
    let db = open_db(&data_dir, params.net.0, false)?;

    // The chain open replays any pending UTXO catch-up, which the
    // export does not need but tolerates; it yields the main-chain
    // hash sequence.
    let created_unix = now_unix();
    let chain = Chain::open(db.clone(), &params, Hash([0u8; 32]), false, created_unix)
        .map_err(|e| format!("unable to open chain: {e:?}"))?;
    let tip_height = chain.best_snapshot().height.min(max);

    let mut hashes = Vec::with_capacity(usize::try_from(tip_height).unwrap_or(0));
    let mut height = 1i64;
    while height <= tip_height {
        let hash = chain
            .block_hash_by_height(height)
            .ok_or_else(|| format!("no main chain hash at height {height}"))?;
        hashes.push(hash);
        height = height.saturating_add(1);
    }

    // Write to a temporary name and rename so a failed export never
    // truncates an existing corpus.
    let tmp = out.with_extension("tmp");
    let file = std::fs::File::create(&tmp).map_err(|e| format!("unable to create {tmp:?}: {e}"))?;
    let mut w = BufWriter::new(file);
    let start = Instant::now();
    let exported = db
        .export_blocks(&mut w, params.net.0, &hashes)
        .map_err(|e| e.to_string())?;
    w.flush().map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &out).map_err(|e| format!("unable to rename {tmp:?}: {e}"))?;
    println!(
        "exported {exported} blocks (heights 1-{tip_height}) to {} in {:.2}s",
        out.display(),
        start.elapsed().as_secs_f64()
    );
    Ok(())
}

/// The current unix time.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Replay the corpus into a fresh chain with live validation.
fn cmd_replay(args: &Args) -> Result<(), String> {
    let input = PathBuf::from(args.require("in")?);
    let (params, _) = net_params(args.get("net").unwrap_or("mainnet"))?;
    let max: u64 = match args.get("max") {
        Some(v) => v.parse().map_err(|e| format!("bad --max: {e}"))?,
        None => u64::MAX,
    };
    let report: u64 = match args.get("report") {
        Some(v) => v.parse().map_err(|e| format!("bad --report: {e}"))?,
        None => 5000,
    };
    if report == 0 {
        return Err("--report must be greater than zero".to_string());
    }
    let assume_valid = match args.get("assumevalid") {
        // Full validation by default: no anchor, every script runs.
        None => Hash([0u8; 32]),
        Some(v) => v
            .parse::<Hash>()
            .map_err(|e| format!("bad --assumevalid: {e:?}"))?,
    };
    let workdir = match args.get("workdir") {
        Some(v) => PathBuf::from(v),
        None => input.with_extension("work"),
    };
    if workdir.exists() {
        return Err(format!(
            "work directory {} already exists; remove it or pass --workdir",
            workdir.display()
        ));
    }

    // Open the corpus before creating anything so a bad --in leaves
    // no orphan work directory behind.
    let file = std::fs::File::open(&input).map_err(|e| format!("unable to open corpus: {e}"))?;
    let mut r = BufReader::new(file);

    let db = open_db(&workdir, params.net.0, true)?;
    let mut chain = Chain::open(db, &params, assume_valid, false, now_unix())
        .map_err(|e| format!("unable to initialize chain: {e:?}"))?;

    println!(
        "replaying {} (assumevalid {}) into {}",
        input.display(),
        if assume_valid == Hash([0u8; 32]) {
            "off".to_string()
        } else {
            assume_valid.to_string()
        },
        workdir.display()
    );

    let start = Instant::now();
    let mut window_start = start;
    let mut blocks = 0u64;
    let mut skipped = 0u64;
    let mut window_blocks = 0u64;
    let mut txs = 0u64;
    let mut bytes = 0u64;
    while blocks < max {
        let serialized = match bootstrap::read_block(&mut r, params.net.0) {
            Ok(Some(serialized)) => serialized,
            Ok(None) => break,
            Err(e) => return Err(format!("error reading corpus: {e}")),
        };
        let (block, _) =
            MsgBlock::from_bytes(&serialized).map_err(|e| format!("bad block: {e}"))?;

        // Skip blocks the chain already has (a foreign corpus may
        // include genesis), like the importer and dcrd's addblock.
        if chain.main_chain_has_block(&block.header.block_hash()) {
            skipped = skipped.saturating_add(1);
            continue;
        }
        bytes = bytes.saturating_add(serialized.len() as u64);
        txs = txs.saturating_add(block.transactions.len() as u64);

        let (_, errs) = chain.process_block(&block, now_unix() as i64, &params);
        if !errs.is_empty() {
            return Err(format!(
                "block {} at height {} rejected: {}",
                block.header.block_hash(),
                block.header.height,
                errs[0].description
            ));
        }

        blocks = blocks.saturating_add(1);
        window_blocks = window_blocks.saturating_add(1);
        if window_blocks == report {
            let elapsed = window_start.elapsed().as_secs_f64();
            println!(
                "height {:>8}: {report} blocks in {elapsed:>7.2}s ({:>7.1} blk/s)",
                block.header.height,
                window_blocks as f64 / elapsed,
            );
            window_blocks = 0;
            window_start = Instant::now();
        }
    }

    // The clean-shutdown flush is part of the measured work: a real
    // sync pays it too, and without it the work directory's tail
    // rolls back on the next open.
    chain
        .flush(&params)
        .map_err(|e| format!("flush failed: {e:?}"))?;

    let elapsed = start.elapsed().as_secs_f64();
    let best = chain.best_snapshot();
    println!("---");
    println!(
        "replayed {blocks} blocks ({txs} regular txs, {:.1} MiB, {skipped} already known) in {elapsed:.2}s",
        bytes as f64 / (1024.0 * 1024.0),
    );
    println!(
        "rate {:.1} blk/s, {:.2} MiB/s; tip height {}; peak RSS {} MiB",
        blocks as f64 / elapsed,
        bytes as f64 / (1024.0 * 1024.0) / elapsed,
        best.height,
        peak_rss_kib() / 1024,
    );
    Ok(())
}

fn main() -> std::process::ExitCode {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let Some((cmd, rest)) = raw.split_first() else {
        print!("{HELP}");
        return std::process::ExitCode::FAILURE;
    };
    let result = match cmd.as_str() {
        "export" => {
            Args::parse(rest, &["appdata", "out", "net", "max"]).and_then(|a| cmd_export(&a))
        }
        "replay" => Args::parse(
            rest,
            &["in", "net", "workdir", "assumevalid", "max", "report"],
        )
        .and_then(|a| cmd_replay(&a)),
        "help" | "--help" | "-h" => {
            print!("{HELP}");
            Ok(())
        }
        other => Err(format!("unknown command {other}")),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("dcroxide-bench: {e}");
            eprint!("{HELP}");
            std::process::ExitCode::FAILURE
        }
    }
}
