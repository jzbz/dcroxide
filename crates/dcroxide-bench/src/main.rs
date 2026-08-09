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
use std::sync::{Arc, Mutex};
use std::time::Instant;

use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::{Params, mainnet_params, regnet_params, simnet_params, testnet3_params};
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options, bootstrap};
use dcroxide_indexers::{
    CONNECT_NTFN, ChainQueryer, ExistsAddrIndex, IndexNtfn, IndexSubscriber, Interrupt, TxIndex,
};
use dcroxide_wire::{BlockHeader, MsgBlock};

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
                        [--flushlog <file>] [--statsevery <n>]
                        [--metacache <MiB>] [--txindex] [--addrindex]
      Replay the corpus into a fresh chain with full live validation,
      reporting throughput every <n> blocks (default 5000).  The work
      directory (default: a fresh directory next to the corpus) must
      not already exist and is left behind for inspection.

      --flushlog writes one JSON line per metadata flush, which is how
      the free-page curve is read under real sync churn rather than the
      synthetic inserts pinprobe applies.  --statsevery N takes the full
      decomposition on every Nth flush (default 25); it walks the whole
      tree, so sampling too often dominates the run it is measuring.
      --metacache sets the overlay ceiling in MiB (default 100, the
      production value).

      --txindex and --addrindex build the optional indexes the daemon
      builds when configured, which Chain::open does not.  Without them
      a replayed store is materially smaller than a synced one -- the
      address index alone is around 3 GiB of tree at mainnet tip -- so
      absolute totals are only comparable to a real datadir when the
      same indexes are enabled.

  dcroxide-bench redbstat --appdata <dir> [--net <name>]
      (--appdata is a node data directory, read from
      <dir>/data/<net>/blocks_ffldb, or a replay --workdir, which holds
      blocks_ffldb at its root; whichever exists is used.)
      Decompose the metadata store's footprint into payload, redb
      overhead, intra-page slack and free pages, as one JSON object.

      This OPENS THE DATABASE FOR WRITING: redb exposes stats() only on
      a write transaction, and opening can repair.  Point it at a copy.
      On btrfs, `cp -a --reflink=always <datadir> <copy>` clones in
      seconds at no space cost.

  dcroxide-bench pinprobe --appdata <dir> [--net <name>] [--writes <n>]
                          [--commits <n>] [--hold <mode>] [--cachemib <n>]
      Apply <writes> scattered metadata writes over <commits> commits
      and print a JSON line per flush, so the free-page curve can be
      read.  --hold selects what is held across the run: none (the
      default), all (one read transaction open throughout), or two (a
      reader spanning exactly two flushes).

      Comparing the arms answers whether a long-lived reader is what
      retains free pages, which ADR-0004 named as its leading
      hypothesis and its 2026-08-07 addendum argues against.  Same
      warning as redbstat: run it on a copy.

  --net is one of mainnet, testnet, simnet, regnet (default mainnet).
";

/// What the flush observer sends to the log writer.
///
/// The writer stops on `Done` rather than on the channel closing. Closing
/// requires every sender to drop, which means every `Arc` transitively
/// holding the observer — the database, the chain, the index handles, the
/// queryer — must be released in the right order first. That held until
/// the indexes were wired in, then silently stopped holding: a completed
/// full-chain replay hung in `join()` with all its records already on
/// disk. An explicit sentinel does not care who else has a sender.
enum FlushMsg {
    /// One JSON record to append.
    Record(String),
    /// Stop; the replay is finished.
    Done,
}

/// Flags that stand alone rather than taking a value.
///
/// The parser otherwise consumes the next token as a value, which would
/// silently swallow the following flag.
const BOOL_FLAGS: [&str; 2] = ["txindex", "addrindex"];

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
                None if BOOL_FLAGS.contains(&name) => {
                    push(&mut values, name, "true".to_string())?;
                }
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

    let flush_log = args.get("flushlog").map(PathBuf::from);
    let stats_every: u64 = match args.get("statsevery") {
        Some(v) => v.parse().map_err(|e| format!("bad --statsevery: {e}"))?,
        None => 25,
    };
    let meta_cache_mib: u64 = match args.get("metacache") {
        Some(v) => v.parse().map_err(|e| format!("bad --metacache: {e}"))?,
        None => 100,
    };

    // Observations go out over a channel to a writer thread, which appends
    // and flushes each line as it arrives.
    //
    // Not accumulated until the end, and not written from the observer
    // either. The observer runs on the flushing thread with the cache lock
    // held, so it must not block on a syscall; but buffering the whole run
    // in memory loses all of it when the run is interrupted, which a replay
    // long enough to be worth measuring frequently is. A channel send is
    // neither.
    let (flush_tx, flush_rx) = std::sync::mpsc::channel::<FlushMsg>();
    let writer = match &flush_log {
        Some(path) => {
            let file = std::fs::File::create(path)
                .map_err(|e| format!("unable to create {}: {e}", path.display()))?;
            Some(std::thread::spawn(move || -> std::io::Result<u64> {
                let mut out = BufWriter::new(file);
                let mut count = 0u64;
                for msg in flush_rx {
                    let FlushMsg::Record(line) = msg else {
                        break;
                    };
                    writeln!(out, "{line}")?;
                    // Flushed per record so an interrupted run keeps every
                    // observation it managed to produce.
                    out.flush()?;
                    count = count.saturating_add(1);
                }
                Ok(count)
            }))
        }
        None => None,
    };
    let db = {
        let db_path = workdir.join("blocks_ffldb");
        std::fs::create_dir_all(&db_path)
            .map_err(|e| format!("unable to create database directory: {e}"))?;
        let mut opts = Options::new(&db_path, params.net.0);
        opts.cache_max_size = meta_cache_mib.saturating_mul(1024 * 1024);
        if flush_log.is_some() {
            opts.flush_stats_every = stats_every;
            let sink = flush_tx.clone();
            opts.flush_observer = Some(Arc::new(
                move |obs: &dcroxide_database::FlushObservation| {
                    let stats = obs
                        .stats
                        .map(|s| s.to_json())
                        .unwrap_or_else(|| "null".to_string());
                    // A closed receiver means the writer is gone; a lost
                    // log line is not worth failing the replay over.
                    let _ = sink.send(FlushMsg::Record(format!(
                        "{{\"flush\":{},\"dirty_entries\":{},\"dirty_bytes\":{},\"elapsed_ms\":{:.3},\"stats_ms\":{:.3},\"flush_ms\":{:.3},\"stats\":{}}}",
                        obs.sequence,
                        obs.dirty_entries,
                        obs.dirty_bytes,
                        obs.elapsed.as_secs_f64() * 1000.0,
                        obs.stats_elapsed.as_secs_f64() * 1000.0,
                        obs.elapsed.saturating_sub(obs.stats_elapsed).as_secs_f64() * 1000.0,
                        stats,
                    )));
                },
            ));
        }
        Arc::new(Database::create(&opts).map_err(|e| e.to_string())?)
    };
    let db_handle = Arc::clone(&db);
    let want_tx_index = args.get("txindex").is_some();
    let want_addr_index = args.get("addrindex").is_some();

    let chain = Arc::new(Mutex::new(
        Chain::open((*db).clone(), &params, assume_valid, false, now_unix())
            .map_err(|e| format!("unable to initialize chain: {e:?}"))?,
    ));

    // The indexes the daemon builds when configured. Chain::open builds
    // none of them, so a replay without these produces a store that is
    // not comparable in size to a synced datadir.
    let queryer: Arc<dyn ChainQueryer> = Arc::new(BenchChainQueryer {
        chain: Arc::clone(&chain),
        params: params.clone(),
    });
    let interrupt: Interrupt = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut subscriber = IndexSubscriber::new(Arc::clone(&interrupt));
    if want_tx_index {
        TxIndex::new(
            &mut subscriber,
            Arc::clone(&db_handle),
            Arc::clone(&queryer),
        )
        .map_err(|e| format!("unable to create the transaction index: {e}"))?;
    }
    if want_addr_index {
        ExistsAddrIndex::new(
            &mut subscriber,
            Arc::clone(&db_handle),
            Arc::clone(&queryer),
        )
        .map_err(|e| format!("unable to create the exists-address index: {e}"))?;
    }
    let indexing = want_tx_index || want_addr_index;

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
        if chain
            .lock()
            .expect("chain mutex poisoned")
            .main_chain_has_block(&block.header.block_hash())
        {
            skipped = skipped.saturating_add(1);
            continue;
        }
        bytes = bytes.saturating_add(serialized.len() as u64);
        txs = txs.saturating_add(block.transactions.len() as u64);

        let (_, errs) = chain.lock().expect("chain mutex poisoned").process_block(
            &block,
            now_unix() as i64,
            &params,
        );
        if !errs.is_empty() {
            return Err(format!(
                "block {} at height {} rejected: {}",
                block.header.block_hash(),
                block.header.height,
                errs[0].description
            ));
        }

        let block_height = block.header.height;

        // Drive the indexes exactly as the daemon does, with the chain
        // lock released: the queryer below takes it, and nesting the two
        // would deadlock the replay.
        if indexing {
            let prev = block.header.prev_block;
            let parent = queryer
                .block_by_hash(&prev)
                .map_err(|e| format!("index parent {prev}: {e}"))?;
            let is_treasury_enabled = queryer
                .is_treasury_agenda_active(&prev)
                .map_err(|e| format!("index treasury state at {prev}: {e}"))?;
            subscriber
                .notify(&IndexNtfn {
                    ntfn_type: CONNECT_NTFN,
                    block: Arc::new(block),
                    parent,
                    is_treasury_enabled,
                })
                .map_err(|e| format!("index update failed: {e}"))?;
        }

        blocks = blocks.saturating_add(1);
        window_blocks = window_blocks.saturating_add(1);
        if window_blocks == report {
            let elapsed = window_start.elapsed().as_secs_f64();
            println!(
                "height {:>8}: {report} blocks in {elapsed:>7.2}s ({:>7.1} blk/s)",
                block_height,
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
        .lock()
        .expect("chain mutex poisoned")
        .flush(&params)
        .map_err(|e| format!("flush failed: {e:?}"))?;

    let elapsed = start.elapsed().as_secs_f64();
    let best_height = {
        let guard = chain.lock().expect("chain mutex poisoned");
        guard.best_snapshot().height
    };
    println!("---");
    println!(
        "replayed {blocks} blocks ({txs} regular txs, {:.1} MiB, {skipped} already known) in {elapsed:.2}s",
        bytes as f64 / (1024.0 * 1024.0),
    );
    println!(
        "rate {:.1} blk/s, {:.2} MiB/s; tip height {}; peak RSS {} MiB",
        blocks as f64 / elapsed,
        bytes as f64 / (1024.0 * 1024.0) / elapsed,
        best_height,
        peak_rss_kib() / 1024,
    );

    if let Some(writer) = writer {
        // Tell the writer to stop rather than waiting for every sender to
        // drop; see FlushMsg.
        let _ = flush_tx.send(FlushMsg::Done);
        let count = writer
            .join()
            .map_err(|_| "flush log writer panicked".to_string())?
            .map_err(|e| format!("writing flush log: {e}"))?;
        if let Some(path) = flush_log {
            println!("wrote {count} flush records to {}", path.display());
        }
    }
    Ok(())
}

/// A [`ChainQueryer`] over the replay's chain, so the indexes can be
/// driven exactly as the daemon drives them.
///
/// Mirrors `dcroxide-node`'s `NodeChainQueryer`. It is duplicated rather
/// than shared because the daemon crate carries the whole P2P and RPC
/// surface, none of which a replay needs; the trait is eight thin
/// accessors, and the alternative was a dependency an order of magnitude
/// larger than the thing being measured.
struct BenchChainQueryer {
    chain: Arc<Mutex<Chain>>,
    params: Params,
}

impl BenchChainQueryer {
    fn locked(&self) -> std::sync::MutexGuard<'_, Chain> {
        self.chain.lock().expect("chain mutex poisoned")
    }
}

impl ChainQueryer for BenchChainQueryer {
    fn main_chain_has_block(&self, hash: &Hash) -> bool {
        self.locked().main_chain_has_block(hash)
    }

    fn chain_params(&self) -> &Params {
        &self.params
    }

    fn best(&self) -> (i64, Hash) {
        let chain = self.locked();
        let best = chain.best_snapshot();
        (best.height, best.hash)
    }

    fn block_header_by_hash(&self, hash: &Hash) -> Result<BlockHeader, String> {
        self.locked()
            .header_by_hash(hash)
            .ok_or_else(|| format!("block {hash} is not known"))
    }

    fn block_hash_by_height(&self, height: i64) -> Result<Hash, String> {
        self.locked()
            .block_hash_by_height(height)
            .ok_or_else(|| format!("no block at height {height} exists"))
    }

    fn block_height_by_hash(&self, hash: &Hash) -> Result<i64, String> {
        self.locked()
            .block_height_by_hash(hash)
            .ok_or_else(|| format!("block {hash} is not in the main chain"))
    }

    fn block_by_hash(&self, hash: &Hash) -> Result<Arc<MsgBlock>, String> {
        self.locked()
            .block_by_hash(hash)
            .map(Arc::new)
            .ok_or_else(|| format!("unable to fetch block {hash}"))
    }

    fn is_treasury_agenda_active(&self, hash: &Hash) -> Result<bool, String> {
        self.locked()
            .is_treasury_agenda_active(hash, &self.params)
            .map_err(|e| e.description)
    }
}

/// Resolve a directory that may be either a node data directory or a
/// `replay --workdir`, which holds `blocks_ffldb` at its root.
///
/// Accepting both matters in practice: the natural thing to do after a
/// replay is to decompose what it produced, and demanding the node layout
/// there would mean the two subcommands could not be pointed at the same
/// path.
fn resolve_store_dir(appdata: &Path, net_dir: &str) -> PathBuf {
    let node_layout = appdata.join("data").join(net_dir);
    if node_layout.join("blocks_ffldb").is_dir() {
        return node_layout;
    }
    appdata.to_path_buf()
}

/// Print the metadata store's footprint decomposition as JSON.
fn cmd_redbstat(args: &Args) -> Result<(), String> {
    let appdata = PathBuf::from(args.require("appdata")?);
    let (params, net_dir) = net_params(args.get("net").unwrap_or("mainnet"))?;
    let data_dir = resolve_store_dir(&appdata, net_dir);
    let db = open_db(&data_dir, params.net.0, false)?;
    let stats = db.raw_stats().map_err(|e| e.to_string())?;
    println!("{}", stats.to_json());
    Ok(())
}

/// What is held open across the probe's flushes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Hold {
    /// Nothing held; the control arm.
    None,
    /// One read transaction open for the whole run.
    All,
    /// A reader spanning exactly two flushes, then released.
    Two,
}

/// Apply scattered writes and report the footprint after each flush.
///
/// The question is whether free pages accumulate because a read
/// transaction pins them, or for a reason no reader controls. Running the
/// same write load with and without a held reader answers it directly: if
/// the curves diverge the reader is the mechanism, and if they coincide it
/// is not, whatever the mechanism turns out to be.
fn cmd_pinprobe(args: &Args) -> Result<(), String> {
    let appdata = PathBuf::from(args.require("appdata")?);
    let (params, net_dir) = net_params(args.get("net").unwrap_or("mainnet"))?;
    let data_dir = resolve_store_dir(&appdata, net_dir);
    let writes: u64 = match args.get("writes") {
        Some(v) => v.parse().map_err(|e| format!("bad --writes: {e}"))?,
        None => 200_000,
    };
    let commits: u64 = match args.get("commits") {
        Some(v) => v.parse().map_err(|e| format!("bad --commits: {e}"))?,
        None => 20,
    };
    let cache_mib: u64 = match args.get("cachemib") {
        Some(v) => v.parse().map_err(|e| format!("bad --cachemib: {e}"))?,
        None => 8,
    };
    let hold = match args.get("hold").unwrap_or("none") {
        "none" => Hold::None,
        "all" => Hold::All,
        "two" => Hold::Two,
        other => return Err(format!("--hold must be none, all or two (got {other})")),
    };
    if commits == 0 {
        return Err("--commits must be at least 1".to_string());
    }

    // Observations are appended from the flushing thread and drained here.
    let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&log);
    let db_path = data_dir.join("blocks_ffldb");
    let mut opts = Options::new(&db_path, params.net.0);
    opts.flush_stats_every = 1;
    // A small ceiling on purpose: the probe has to reach flushes, and at
    // the 100 MiB production default a run short enough to iterate on
    // would never trigger one.
    opts.cache_max_size = cache_mib.saturating_mul(1024 * 1024);
    opts.flush_observer = Some(Arc::new(
        move |obs: &dcroxide_database::FlushObservation| {
            let stats = obs
                .stats
                .map(|s| s.to_json())
                .unwrap_or_else(|| "null".to_string());
            sink.lock().expect("log poisoned").push(format!(
            "{{\"flush\":{},\"dirty_entries\":{},\"dirty_bytes\":{},\"elapsed_ms\":{:.3},\"stats\":{}}}",
            obs.sequence,
            obs.dirty_entries,
            obs.dirty_bytes,
            obs.elapsed.as_secs_f64() * 1000.0,
            stats,
        ));
        },
    ));

    let db = Database::open(&opts).map_err(|e| e.to_string())?;
    eprintln!(
        "pinprobe: {writes} writes over {commits} commits, hold={}",
        match hold {
            Hold::None => "none",
            Hold::All => "all",
            Hold::Two => "two",
        }
    );

    // Held for the whole run in the `all` arm; dropped after two flushes
    // in the `two` arm.
    let mut held = match hold {
        Hold::None => None,
        _ => Some(db.begin(false).map_err(|e| e.to_string())?),
    };

    let per_commit = writes.div_ceil(commits);
    let mut written = 0u64;
    for commit in 0..commits {
        let tx = db.begin(true).map_err(|e| e.to_string())?;
        {
            let meta = tx.metadata();
            let bucket = meta
                .create_bucket_if_not_exists(b"pinprobe")
                .map_err(|e| e.to_string())?;
            for i in 0..per_commit {
                if written >= writes {
                    break;
                }
                // Scatter by hashing the counter, so writes land across the
                // keyspace rather than appending to one edge.
                let key = dcroxide_chainhash::hash_b(&written.to_le_bytes());
                bucket.put(&key, &key).map_err(|e| e.to_string())?;
                written = written.saturating_add(1);
                let _ = i;
            }
        }
        tx.commit().map_err(|e| e.to_string())?;

        if hold == Hold::Two && commit == 1 {
            held = None;
        }
    }
    drop(held);

    for line in log.lock().expect("log poisoned").iter() {
        println!("{line}");
    }
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
            &[
                "in",
                "net",
                "workdir",
                "assumevalid",
                "max",
                "report",
                "flushlog",
                "statsevery",
                "metacache",
                "txindex",
                "addrindex",
            ],
        )
        .and_then(|a| cmd_replay(&a)),
        "redbstat" => Args::parse(rest, &["appdata", "net"]).and_then(|a| cmd_redbstat(&a)),
        "pinprobe" => Args::parse(
            rest,
            &["appdata", "net", "writes", "commits", "hold", "cachemib"],
        )
        .and_then(|a| cmd_pinprobe(&a)),
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
