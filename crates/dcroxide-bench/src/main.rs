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
use std::process::{Command, Stdio};
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
                        [--flushlog <file>] [--writelog <dir>] [--statsevery <n>]
                        [--metacache <MiB>] [--dbcache <MiB>]
                        [--utxocache <MiB>]
                        [--txindex] [--addrindex]
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
      production value) -- ADR-0004's flush-cadence lever.  --dbcache
      sets redb's page cache in MiB (default 1024, redb's own default)
      -- ADR-0004's read-cache lever.  The two interact, so a run that
      moves one without the other answers half a question.

      --writelog captures what the storage ENGINE is handed: one record
      per key/value in the order given, batched on flush boundaries, as
      journal.bin plus a journal.idx of batch offsets.  It exists for
      ADR-0009's candidate engine benchmark, where insertion order would
      otherwise decide the answer -- a sorted bulk load is an LSM's best
      case and a copy-on-write B-tree's worst (a sorted rebuild of this
      store measured 58.29% fill against 64.86%), and a random one is the
      reverse.  Neither is what the engine sees.  It sees one sorted
      sweep per flush over a scattered subset, carrying overwrites and
      deletes.  Capturing that once and replaying it into every candidate
      eliminates the confound instead of balancing it.

      --utxocache sets the UTXO cache ceiling in MiB (dcrd's
      --utxocachemaxsize, default 150).  It belongs with --metacache
      rather than beside it: connecting a block flushes the UTXO cache
      when that ceiling is reached, and that flush forces a durable
      metadata commit whatever the overlay ceiling says.  Raising
      --metacache alone therefore does not decouple flush cadence from
      block connection, which is what ADR-0004's lever (c) proposes.

      --txindex and --addrindex build the optional indexes the daemon
      builds when configured, which Chain::open does not.  Without them
      a replayed store is materially smaller than a synced one -- the
      address index alone is around 3 GiB of tree at mainnet tip -- so
      absolute totals are only comparable to a real datadir when the
      same indexes are enabled.

  dcroxide-bench indexcatchup --workdir <dir> [--net <name>]
                              [--txindex] [--addrindex] [--metacache <mib>]
      Build an index over a FINISHED store in one pass, as dcrd does.

      `replay --addrindex` interleaves index rows across every block
      commit.  dcrd cannot: `addblock` enables indexes without building
      them, so the daemon adds them afterwards in a dedicated catch-up
      pass over a complete database.  That difference is not cosmetic
      for a copy-on-write B-tree, where insertion order drives leaf fill
      and free-page retention, and it confounded the 2026-08-11 payload
      comparison -- which established that the two implementations store
      the same bytes, but could not say how much of the on-disk gap was
      the engine and how much was the write schedule.

      `replay` with no index flags, then this, reproduces dcrd's
      schedule.  Comparing that against `replay --addrindex` isolates
      the schedule term; comparing it against dcrd isolates the engine.

  dcroxide-bench redbstat --appdata <dir> [--net <name>] [--buckets]
      --buckets additionally reports each bucket's rows, payload and
      row-size DISTRIBUTION -- mean, p50, p90, p99 and largest.

      It used to report rows-per-page and a predicted slack instead,
      modelled by dividing the page size by the mean row.  Those columns
      are gone: the model was 13% high on slack and wrong about the
      mechanism, and it drove a proposed storage-format change that
      measurement then refuted.  redb reports page counts per table and
      never per bucket, so a per-bucket page figure is not something this
      tool can measure -- only model.  Read p50 against mean instead;
      where they diverge the mean is a tail artifact.

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

  dcroxide-bench sweep --in <file> --arms <file> --out <file>
                       [--reps <n>] [--net <name>] [--max <n>]
                       [--workdirroot <dir>] [--warmup <n>]
      Compare replay configurations so the comparison survives drift.

      Each line of the arms file is a name, whitespace, then the extra
      replay flags for that arm; blank lines and # comments are
      skipped.  Every arm is run <reps> times (default 3), INTERLEAVED
      rather than blocked, with the order rotated each repetition so no
      arm keeps a fixed position.  Every run gets a fresh workdir and a
      fresh process, and the workdir is deleted before the next run.

      This exists because the obvious design does not work.  Running
      arms in blocks -- all of A, then all of B -- confounds the arms
      with anything that changes over the sweep: two attempts at
      ADR-0004's levers were voided that way, one by a 1.64x drift
      between two runs of an identical configuration.  Interleaving
      spreads that drift across all arms instead of loading it onto the
      last one, and repetition makes it visible.

      --warmup <n> discards the first n runs from the summary (default
      1).  They are still recorded, flagged, so the cost is visible.
      This is not fussiness: the first full-chain run of a sweep took
      6,440 s against 3,866-3,888 s for the same configuration later,
      a 66% cold-start penalty that the drift check then misreported as
      a trend.

      Results are written as one JSON object per run, with the machine
      state at the time of the run, and a summary is printed with each
      arm's median and the drift between the first and second half of
      the sweep.  Read the drift line first: if it is comparable to the
      differences between arms, the sweep has not measured anything.

      The summary also reports whether each arm's range overlaps the
      first arm's.  Prefer that to the medians: disjoint ranges are a
      claim about every observation, where a median difference smaller
      than the drift is a claim about nothing.

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

/// One message to the engine write-log writer.
///
/// The log records what the storage engine is handed and in what order,
/// which is the input ADR-0009's candidate benchmark needs: neither block
/// order nor the sorted finished store, but one sorted sweep per flush
/// carrying overwrites and deletes. Batches are delimited on the flush
/// boundary so a replay into another engine can commit exactly where
/// dcroxide commits.
enum WriteLogMsg {
    /// `op` is 0 for a put and 1 for a delete.
    Record(u8, Vec<u8>, Option<Vec<u8>>),
    /// The flush that was accumulating has committed.
    EndBatch,
    /// Stop; the replay is finished.
    Done,
}

/// Flags that stand alone rather than taking a value.
///
/// The parser otherwise consumes the next token as a value, which would
/// silently swallow the following flag.
const BOOL_FLAGS: [&str; 3] = ["txindex", "addrindex", "buckets"];

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
    let write_log = args.get("writelog").map(PathBuf::from);
    let stats_every: u64 = match args.get("statsevery") {
        Some(v) => v.parse().map_err(|e| format!("bad --statsevery: {e}"))?,
        None => 25,
    };
    let db_cache_mib: Option<u64> = match args.get("dbcache") {
        Some(v) => Some(v.parse().map_err(|e| format!("bad --dbcache: {e}"))?),
        None => None,
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
    // The engine-level write log, for ADR-0009's candidate benchmark. It
    // runs on its own thread for the same reason the flush log does: this
    // sink fires inside the flush transaction, ~102M times over a full
    // chain, and anything slower than a channel send would be measuring
    // the instrument. Records are framed
    // `[u8 op][u32 klen][u32 vlen][key][value]`, one batch per flush,
    // delimited by the batch index written alongside.
    let (wl_tx, wl_rx) = std::sync::mpsc::channel::<WriteLogMsg>();
    let wl_writer = match &write_log {
        Some(dir) => {
            std::fs::create_dir_all(dir)
                .map_err(|e| format!("unable to create {}: {e}", dir.display()))?;
            let bin_path = dir.join("journal.bin");
            let idx_path = dir.join("journal.idx");
            let bin = std::fs::File::create(&bin_path)
                .map_err(|e| format!("unable to create {}: {e}", bin_path.display()))?;
            let idx = std::fs::File::create(&idx_path)
                .map_err(|e| format!("unable to create {}: {e}", idx_path.display()))?;
            Some(std::thread::spawn(
                move || -> std::io::Result<(u64, u64)> {
                    let mut bin = BufWriter::with_capacity(1 << 22, bin);
                    let mut idx = BufWriter::with_capacity(1 << 16, idx);
                    let (mut offset, mut records, mut batches) = (0u64, 0u64, 0u64);
                    let (mut batch_start, mut batch_records) = (0u64, 0u64);
                    for msg in wl_rx {
                        match msg {
                            WriteLogMsg::Record(op, key, val) => {
                                let vlen = val.as_ref().map(|v| v.len()).unwrap_or(0) as u32;
                                bin.write_all(&[op])?;
                                bin.write_all(&(key.len() as u32).to_le_bytes())?;
                                bin.write_all(&vlen.to_le_bytes())?;
                                bin.write_all(&key)?;
                                if let Some(v) = &val {
                                    bin.write_all(v)?;
                                }
                                offset = offset
                                    .saturating_add(9)
                                    .saturating_add(key.len() as u64)
                                    .saturating_add(u64::from(vlen));
                                records = records.saturating_add(1);
                                batch_records = batch_records.saturating_add(1);
                            }
                            WriteLogMsg::EndBatch => {
                                // batch_seq, offset, record_count
                                idx.write_all(&batches.to_le_bytes())?;
                                idx.write_all(&batch_start.to_le_bytes())?;
                                idx.write_all(&batch_records.to_le_bytes())?;
                                batches = batches.saturating_add(1);
                                batch_start = offset;
                                batch_records = 0;
                            }
                            WriteLogMsg::Done => break,
                        }
                    }
                    // Records written after the last flush observation -- the
                    // close-time flush -- would otherwise sit in journal.bin
                    // with no index entry, and a loader driven by the index
                    // would silently skip them. Caught by the smoke replay
                    // landing 26 payload bytes short of the store it captured.
                    if batch_records > 0 {
                        idx.write_all(&batches.to_le_bytes())?;
                        idx.write_all(&batch_start.to_le_bytes())?;
                        idx.write_all(&batch_records.to_le_bytes())?;
                        batches = batches.saturating_add(1);
                    }
                    bin.flush()?;
                    idx.flush()?;
                    Ok((records, batches))
                },
            ))
        }
        None => None,
    };

    let db = {
        let db_path = workdir.join("blocks_ffldb");
        std::fs::create_dir_all(&db_path)
            .map_err(|e| format!("unable to create database directory: {e}"))?;
        let mut opts = Options::new(&db_path, params.net.0);
        opts.cache_max_size = meta_cache_mib.saturating_mul(1024 * 1024);
        if write_log.is_some() {
            let sink = wl_tx.clone();
            opts.write_log = Some(Arc::new(move |key: &[u8], val: Option<&[u8]>| {
                let _ = sink.send(WriteLogMsg::Record(
                    u8::from(val.is_none()),
                    key.to_vec(),
                    val.map(|v| v.to_vec()),
                ));
            }));
        }
        if let Some(mib) = db_cache_mib {
            opts.db_cache_bytes = (mib as usize).saturating_mul(1024 * 1024);
        }
        // The batch delimiter rides on the flush observer, which fires once
        // per flush after the transaction commits — so a batch in the
        // journal is exactly one redb transaction, which is the property
        // that makes the replay faithful.
        if write_log.is_some() && flush_log.is_none() {
            let sink = wl_tx.clone();
            opts.flush_observer = Some(Arc::new(
                move |_obs: &dcroxide_database::FlushObservation| {
                    let _ = sink.send(WriteLogMsg::EndBatch);
                },
            ));
        }
        if flush_log.is_some() {
            opts.flush_stats_every = stats_every;
            let sink = flush_tx.clone();
            let wl_sink = write_log.is_some().then(|| wl_tx.clone());
            opts.flush_observer = Some(Arc::new(
                move |obs: &dcroxide_database::FlushObservation| {
                    if let Some(wl) = &wl_sink {
                        let _ = wl.send(WriteLogMsg::EndBatch);
                    }
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

    let utxo_cache_mib: Option<u64> = match args.get("utxocache") {
        Some(v) => Some(v.parse().map_err(|e| format!("bad --utxocache: {e}"))?),
        None => None,
    };

    let chain = Arc::new(Mutex::new(
        Chain::open((*db).clone(), &params, assume_valid, false, now_unix())
            .map_err(|e| format!("unable to initialize chain: {e:?}"))?,
    ));

    if let Some(mib) = utxo_cache_mib {
        chain
            .lock()
            .expect("chain mutex poisoned")
            .set_utxo_cache_max_bytes(mib.saturating_mul(1024 * 1024));
    }

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

    println!(
        "settings: metacache {} MiB, dbcache {} MiB, utxocache {}, txindex {}, addrindex {}",
        meta_cache_mib,
        db_cache_mib.unwrap_or((dcroxide_database::DEFAULT_DB_CACHE_BYTES / (1024 * 1024)) as u64),
        utxo_cache_mib
            .map(|m| format!("{m} MiB"))
            .unwrap_or_else(|| "default".to_string()),
        want_tx_index,
        want_addr_index,
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

    if let Some(writer) = wl_writer {
        let _ = wl_tx.send(WriteLogMsg::Done);
        let (records, batches) = writer
            .join()
            .map_err(|_| "write log writer panicked".to_string())?
            .map_err(|e| format!("writing write log: {e}"))?;
        if let Some(dir) = write_log {
            println!(
                "wrote {records} write records in {batches} batches to {}",
                dir.display()
            );
        }
    }
    Ok(())
}

/// Build an index over a finished store in one pass, the way dcrd does.
///
/// This exists to remove a confound rather than to be fast. The
/// 2026-08-11 dcrd comparison built dcrd's exists-address index in a
/// dedicated catch-up pass over an already-complete database (`addblock`
/// enables indexes without building them, so the daemon has to run once),
/// while dcroxide's `replay --addrindex` interleaved the same 66.5M rows
/// across 1.1M block commits. Insertion order is a first-order determinant
/// of leaf fill and free-page retention in a copy-on-write B-tree, and
/// largely erased by compaction in an LSM, so the two stores were not
/// comparable on schedule even though they were comparable on content.
///
/// `replay` with no index flags followed by this subcommand reproduces
/// dcrd's schedule exactly, which is what makes the difference between the
/// two runs the engine term rather than the schedule term.
fn cmd_indexcatchup(args: &Args) -> Result<(), String> {
    let workdir = PathBuf::from(args.require("workdir")?);
    let (params, _net_dir) = net_params(args.get("net").unwrap_or("mainnet"))?;

    let db_path = workdir.join("blocks_ffldb");
    if !db_path.exists() {
        return Err(format!(
            "{} holds no blocks_ffldb: point --workdir at a finished replay",
            workdir.display()
        ));
    }
    let mut opts = Options::new(&db_path, params.net.0);
    if let Some(v) = args.get("metacache") {
        let mib: u64 = v.parse().map_err(|e| format!("bad --metacache: {e}"))?;
        opts.cache_max_size = mib.saturating_mul(1024 * 1024);
    }
    // `open`, not `create`: the store already exists, which is the whole
    // point of this pass.
    let db = Arc::new(Database::open(&opts).map_err(|e| e.to_string())?);
    let db_handle = Arc::clone(&db);

    let chain = Arc::new(Mutex::new(
        Chain::open((*db).clone(), &params, Hash([0u8; 32]), false, now_unix())
            .map_err(|e| format!("unable to initialize chain: {e:?}"))?,
    ));
    let queryer: Arc<dyn ChainQueryer> = Arc::new(BenchChainQueryer {
        chain: Arc::clone(&chain),
        params: params.clone(),
    });

    let interrupt: Interrupt = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut subscriber = IndexSubscriber::new(Arc::clone(&interrupt));
    let want_tx_index = args.get("txindex").is_some();
    let want_addr_index = args.get("addrindex").is_some();
    if !want_tx_index && !want_addr_index {
        return Err("nothing to build: pass --txindex and/or --addrindex".to_string());
    }
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

    let (best_height, _) = queryer.best();
    println!(
        "catching up txindex {} addrindex {} to height {best_height} in {}",
        want_tx_index,
        want_addr_index,
        workdir.display()
    );

    let start = Instant::now();
    subscriber
        .catch_up(&*queryer)
        .map_err(|e| format!("index catch-up failed: {e}"))?;
    let elapsed = start.elapsed();

    // The store has to be durable before it is measured, and the flush is
    // part of what the schedule comparison is measuring.
    let flush_start = Instant::now();
    db.flush().map_err(|e| e.to_string())?;
    let flush_elapsed = flush_start.elapsed();
    db.close().map_err(|e| e.to_string())?;

    println!(
        "catch-up {:.1} s over {} blocks ({:.1} blk/s), final flush {:.1} s",
        elapsed.as_secs_f64(),
        best_height,
        best_height as f64 / elapsed.as_secs_f64().max(f64::MIN_POSITIVE),
        flush_elapsed.as_secs_f64(),
    );
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

/// One arm of a sweep: a name and the extra `replay` flags it adds.
struct SweepArm {
    name: String,
    flags: Vec<String>,
}

/// Machine state at the moment a run started, so a suspicious result can
/// be checked against the conditions that produced it rather than
/// re-litigated from memory.
struct RunEnv {
    load1: String,
    mem_available_kb: u64,
    disk_avail_kb: u64,
    cpu_mhz: String,
}

impl RunEnv {
    fn capture(workdir_root: &Path) -> RunEnv {
        let load1 = std::fs::read_to_string("/proc/loadavg")
            .ok()
            .and_then(|s| s.split_whitespace().next().map(str::to_string))
            .unwrap_or_else(|| "?".to_string());
        let mem_available_kb = std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("MemAvailable:"))
                    .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
            })
            .unwrap_or(0);
        let cpu_mhz = std::fs::read_to_string("/proc/cpuinfo")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("cpu MHz"))
                    .and_then(|l| l.split(':').nth(1).map(|v| v.trim().to_string()))
            })
            .unwrap_or_else(|| "?".to_string());
        let disk_avail_kb = disk_avail_kb(workdir_root);
        RunEnv {
            load1,
            mem_available_kb,
            disk_avail_kb,
            cpu_mhz,
        }
    }
}

/// Available space under `path` in kibibytes, via `df` (0 when unknown).
fn disk_avail_kb(path: &Path) -> u64 {
    Command::new("df")
        .arg("-Pk")
        .arg(path)
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .nth(1)
                .and_then(|l| l.split_whitespace().nth(3).and_then(|v| v.parse().ok()))
        })
        .unwrap_or(0)
}

/// Parse the arms file: `name  <flags...>` per line, `#` comments skipped.
fn parse_arms(path: &Path) -> Result<Vec<SweepArm>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("unable to read {}: {e}", path.display()))?;
    let mut arms = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let name = parts
            .next()
            .ok_or_else(|| format!("{}:{}: empty arm", path.display(), i.saturating_add(1)))?;
        arms.push(SweepArm {
            name: name.to_string(),
            flags: parts.map(str::to_string).collect(),
        });
    }
    if arms.is_empty() {
        return Err(format!("{} defines no arms", path.display()));
    }
    Ok(arms)
}

/// The median of a slice, by value.
fn median(values: &mut [f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(core::cmp::Ordering::Equal));
    let mid = values.len() / 2;
    if values.len().is_multiple_of(2) {
        (values[mid.saturating_sub(1)] + values[mid]) / 2.0
    } else {
        values[mid]
    }
}

/// Run a sweep: every arm, every repetition, interleaved and rotated.
fn cmd_sweep(args: &Args) -> Result<(), String> {
    let corpus = PathBuf::from(args.require("in")?);
    let arms = parse_arms(Path::new(args.require("arms")?))?;
    let out_path = PathBuf::from(args.require("out")?);
    let reps: usize = match args.get("reps") {
        Some(v) => v.parse().map_err(|e| format!("bad --reps: {e}"))?,
        None => 3,
    };
    if reps == 0 {
        return Err("--reps must be at least 1".to_string());
    }
    let warmup: usize = match args.get("warmup") {
        Some(v) => v.parse().map_err(|e| format!("bad --warmup: {e}"))?,
        None => 1,
    };
    let net = args.get("net").unwrap_or("mainnet").to_string();
    let workdir_root = PathBuf::from(
        args.get("workdirroot")
            .map(str::to_string)
            .unwrap_or_else(|| ".".to_string()),
    );
    let exe = std::env::current_exe().map_err(|e| format!("locating this binary: {e}"))?;

    let mut out = BufWriter::new(
        std::fs::File::create(&out_path)
            .map_err(|e| format!("unable to create {}: {e}", out_path.display()))?,
    );
    // (arm index, seconds), in execution order, so drift can be read off
    // the sequence rather than assumed absent.
    let mut results: Vec<(usize, f64)> = Vec::new();
    let total = reps.saturating_mul(arms.len());
    let mut run_no = 0usize;

    for rep in 0..reps {
        // Rotate the order each repetition: an arm that always ran last
        // would absorb whatever the sweep accumulates.
        for offset in 0..arms.len() {
            let idx = offset
                .saturating_add(rep)
                .checked_rem(arms.len())
                .unwrap_or(0);
            let arm = &arms[idx];
            run_no = run_no.saturating_add(1);
            let wd = workdir_root.join(format!("sweep-{}-r{}", arm.name, rep.saturating_add(1)));
            let _ = std::fs::remove_dir_all(&wd);

            let env = RunEnv::capture(&workdir_root);
            eprintln!(
                "[{run_no}/{total}] rep {} arm {} (load {}, {} MiB free RAM, {} GiB free disk)",
                rep.saturating_add(1),
                arm.name,
                env.load1,
                env.mem_available_kb / 1024,
                env.disk_avail_kb / (1024 * 1024),
            );

            let mut cmd = Command::new(&exe);
            cmd.arg("replay")
                .arg("--in")
                .arg(&corpus)
                .arg("--workdir")
                .arg(&wd)
                .arg("--net")
                .arg(&net)
                .arg("--report")
                .arg("1000000");
            if let Some(max) = args.get("max") {
                cmd.arg("--max").arg(max);
            }
            for f in &arm.flags {
                cmd.arg(f);
            }

            let started = Instant::now();
            let status = cmd
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .status()
                .map_err(|e| format!("spawning replay: {e}"))?;
            let seconds = started.elapsed().as_secs_f64();
            if !status.success() {
                return Err(format!("arm {} failed: {status}", arm.name));
            }
            let _ = std::fs::remove_dir_all(&wd);

            let warming = run_no <= warmup;
            writeln!(
                out,
                "{{\"run\":{},\"rep\":{},\"arm\":\"{}\",\"seconds\":{:.2},\"warmup\":{},\"load1\":\"{}\",\"mem_avail_kb\":{},\"disk_avail_kb\":{},\"cpu_mhz\":\"{}\"}}",
                run_no,
                rep.saturating_add(1),
                arm.name,
                seconds,
                warming,
                env.load1,
                env.mem_available_kb,
                env.disk_avail_kb,
                env.cpu_mhz,
            )
            .map_err(|e| format!("writing results: {e}"))?;
            out.flush().map_err(|e| format!("writing results: {e}"))?;
            if warming {
                eprintln!("      (warm-up, excluded from the summary)");
            } else {
                results.push((idx, seconds));
            }
        }
    }

    println!(
        "\n--- sweep summary ({} runs, {warmup} warm-up discarded)",
        results.len()
    );
    // Drift first: it decides whether anything below it means anything.
    let half = results.len() / 2;
    if half > 0 {
        let mut first: Vec<f64> = results[..half].iter().map(|(_, s)| *s).collect();
        let mut second: Vec<f64> = results[half..].iter().map(|(_, s)| *s).collect();
        let (a, b) = (median(&mut first), median(&mut second));
        let drift = if a > 0.0 { b / a } else { 0.0 };
        println!(
            "drift  first half {a:.1}s vs second half {b:.1}s = {drift:.2}x \
             (arms are interleaved, so this is elapsed-time drift, not an arm effect)"
        );
        if !(0.91..=1.10).contains(&drift) {
            println!(
                "  WARNING: drift exceeds 10%. Treat any arm difference smaller than \
                 this as unmeasured."
            );
        }
    }
    println!();
    let mut baseline: Option<f64> = None;
    let mut base_range: Option<(f64, f64)> = None;
    for (i, arm) in arms.iter().enumerate() {
        let mut times: Vec<f64> = results
            .iter()
            .filter(|(a, _)| *a == i)
            .map(|(_, s)| *s)
            .collect();
        if times.is_empty() {
            continue;
        }
        let lo = times.iter().cloned().fold(f64::INFINITY, f64::min);
        let hi = times.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let med = median(&mut times);
        let rel = match baseline {
            None => {
                baseline = Some(med);
                String::from("(baseline)")
            }
            Some(b) if b > 0.0 => format!("{:.2}x baseline", med / b),
            Some(_) => String::new(),
        };
        // Prefer this to the medians: disjoint ranges are a claim about
        // every observation, where a median difference smaller than the
        // drift is a claim about nothing.
        let overlap = match base_range {
            None => {
                base_range = Some((lo, hi));
                String::new()
            }
            Some((blo, bhi)) if hi < blo || lo > bhi => String::from("   disjoint from baseline"),
            Some(_) => String::from("   OVERLAPS baseline"),
        };
        println!(
            "{:<16} median {med:>8.1}s   min {lo:>8.1}s   max {hi:>8.1}s   spread {:>5.1}%   {rel}{overlap}",
            arm.name,
            if med > 0.0 {
                100.0 * (hi - lo) / med
            } else {
                0.0
            },
        );
    }
    println!("\nper-run records: {}", out_path.display());
    Ok(())
}

/// Print the metadata store's footprint decomposition as JSON.
fn cmd_redbstat(args: &Args) -> Result<(), String> {
    let appdata = PathBuf::from(args.require("appdata")?);
    let (params, net_dir) = net_params(args.get("net").unwrap_or("mainnet"))?;
    let data_dir = resolve_store_dir(&appdata, net_dir);
    let db = open_db(&data_dir, params.net.0, false)?;

    if args.get("buckets").is_some() {
        // Per-bucket first: it is read-only, where raw_stats below opens a
        // write transaction and perturbs the figures slightly.
        let buckets = db.bucket_stats().map_err(|e| e.to_string())?;
        println!(
            "{:<22} {:>12} {:>12} {:>9} {:>9} {:>9} {:>9} {:>10}",
            "bucket", "rows", "payload MiB", "mean", "p50", "p90", "p99", "largest"
        );
        for b in &buckets {
            println!(
                "{:<22} {:>12} {:>12.1} {:>9.0} {:>9} {:>9} {:>9} {:>10}",
                b.name,
                b.rows,
                b.payload_bytes as f64 / (1024.0 * 1024.0),
                b.mean_row_bytes(),
                b.size_percentile(0.50),
                b.size_percentile(0.90),
                b.size_percentile(0.99),
                b.largest_row_bytes,
            );
        }
        // Byte-exact rows as well, because the table above rounds to 0.1 MiB
        // and the comparison this feeds is a claim of equality: dcrd's
        // `dcrdstat -json` reports whole bytes, so at 0.1 MiB resolution a
        // per-bucket difference of tens of kilobytes would print as agreement.
        println!("\nper-bucket payload in bytes (compare `dcrdstat -json`):");
        let mut total_rows = 0u64;
        let mut total_payload = 0u64;
        for b in &buckets {
            total_rows = total_rows.saturating_add(b.rows);
            total_payload = total_payload.saturating_add(b.payload_bytes);
            println!("  {:<22} {:>12} {:>14}", b.name, b.rows, b.payload_bytes);
        }
        // Printed rather than left to the caller: the unnamed root bucket
        // renders as `<id 00000000>`, which contains a space, so summing
        // this table with awk silently drops that row. It cost 420 bytes of
        // confusion once already.
        println!("  {:<22} {total_rows:>12} {total_payload:>14}", "TOTAL");
        println!(
            "  (this is bucket-attributed payload; raw_stats' stored_leaf_bytes \
             additionally counts the `bidx` bucket-index rows)"
        );
        println!(
            "\nnote: these columns are all MEASURED. This tool used to print a modelled \
             rows/page and predicted slack, derived by dividing the page size by the MEAN \
             row; that model put spendjournalv3 at one row per page and 1.74 GiB of \
             recoverable slack, and the figure reached two ADRs before being measured. \
             The bucket in fact packs 1.55 rows per leaf node and carries 1.536 GiB of \
             slack that no re-keying reaches -- every split tested made the tree LARGER \
             (ADR-0004, 2026-08-12). Read p50 against mean: where they diverge, the mean \
             is a tail artifact and says nothing about how the bucket packs. For the \
             store's real slack use `redbstat` without --buckets: \
             table_fragmented_bytes is measured, and redb reports it per table, never \
             per bucket."
        );
    }

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
                "writelog",
                "statsevery",
                "metacache",
                "txindex",
                "addrindex",
                "dbcache",
                "utxocache",
            ],
        )
        .and_then(|a| cmd_replay(&a)),
        "sweep" => Args::parse(
            rest,
            &[
                "in",
                "arms",
                "reps",
                "out",
                "net",
                "max",
                "workdirroot",
                "warmup",
            ],
        )
        .and_then(|a| cmd_sweep(&a)),
        "indexcatchup" => Args::parse(
            rest,
            &["workdir", "net", "txindex", "addrindex", "metacache"],
        )
        .and_then(|a| cmd_indexcatchup(&a)),
        "redbstat" => {
            Args::parse(rest, &["appdata", "net", "buckets"]).and_then(|a| cmd_redbstat(&a))
        }
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
