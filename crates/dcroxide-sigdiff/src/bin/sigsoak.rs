// SPDX-License-Identifier: ISC
//! `sigsoak`: the signature differential soak's command line.  See `HELP`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dcroxide_sigdiff::class::{CLASSES, ClassSpec, Family, select_classes};
use dcroxide_sigdiff::cmd::Request;
use dcroxide_sigdiff::fingerprint::{fingerprint, source_differences};
use dcroxide_sigdiff::manifest::{
    CARGO_LOCK, LOCKED_CRATES, SCHEMA, check_pin, crate_dir, git_state, lock_versions, oracle_json,
    platform, profile_name, repo_root, rustc_vv, unix_now, utc,
};
use dcroxide_sigdiff::pipe::{OraclePipe, Payload, PipeConfig, PipeFailure};
use dcroxide_sigdiff::record::{OutUse, append_ledger, out_dir_problem};
use dcroxide_sigdiff::reply::Reply;
use dcroxide_sigdiff::run::{self, Mode, RunConfig, RunStatus, class_targets, default_workers};
use dcroxide_testutil::{DCRD_PARITY_COMMIT, hex, parse_seed};
use serde_json::{Value, json};

const HELP: &str = "\
sigsoak: the signature differential soak.  Each named class of inputs is
answered by dcroxide and by dcrd's own code (tools/oracle), case by case;
every case is reproducible from the printed master seed.

usage:
  sigsoak run --out DIR (--floors [--scale F] | --cases N | --budget DUR)
              [--seed HEX] [--classes LIST] [--workers N] [--window N]
              [--flush-every N] [--hang-timeout DUR] [--progress-every DUR]
              [--oracle PATH] [--ledger FILE]
      Run the classes and write the record of the run into DIR, which must
      lie outside the repository and hold nothing (a canary/ directory
      aside).  --floors runs each class's floor (times --scale), --cases N
      runs N cases of each sampled class, --budget runs until the deadline
      with the floors as weights; finite classes always run whole.
  sigsoak replay --seed HEX --class NAME --case N [--oracle PATH]
      Regenerate one case, answer it on both sides and print everything:
      requests, intents, both answers, the comparison and the digest leaf.
  sigsoak compare [--replay] [--exploratory] [--allow-subset]
              [--allow-fingerprint-change] [--allow-pin-change] DIR_A DIR_B
      Hold two runs' digests against each other; a class either run
      completed no case of compares nothing and fails.  --replay: DIR_B is
      a shorter run with DIR_A's seed, compared at DIR_A's checkpoints.
  sigsoak list
      Print every class.
  sigsoak help
      Print this.

LIST is comma-separated class names or patterns with * (EV-*,K-wrap); the
default is every class.  DUR is <n>s, <n>m or <n>h.  --oracle defaults to
DCROXIDE_ORACLE_BIN, or tools/oracle built with the Go toolchain on PATH.
--ledger appends one line per run to FILE.

exit codes: 0 pass; 1 a criterion or comparison failed; 2 usage or
configuration error; 3 aborted (dcroxide hung, or oracle faults exhausted).
";

/// Why a command did not run.
enum Refusal {
    /// A malformed command line: the message, then the help.
    Usage(String),
    /// A configuration the command refuses.
    Config(String),
}

type Outcome = Result<ExitCode, Refusal>;

fn usage(message: impl Into<String>) -> Refusal {
    Refusal::Usage(message.into())
}

fn config(message: impl Into<String>) -> Refusal {
    Refusal::Config(message.into())
}

/// Flags that take no value.
const BOOL_FLAGS: [&str; 6] = [
    "floors",
    "replay",
    "exploratory",
    "allow-subset",
    "allow-fingerprint-change",
    "allow-pin-change",
];

/// A parsed command line: `--name value` or `--name=value` flags, each at
/// most once, from a known set, and positional arguments where a command
/// takes them.
struct Args {
    values: Vec<(String, String)>,
    positional: Vec<String>,
}

impl Args {
    fn parse(args: &[String], known: &[&str], positional: bool) -> Result<Args, Refusal> {
        let mut values: Vec<(String, String)> = Vec::new();
        let mut rest = Vec::new();
        let mut push = |name: &str, value: String| -> Result<(), Refusal> {
            if !known.contains(&name) {
                return Err(usage(format!("unknown flag --{name}")));
            }
            if values.iter().any(|(n, _)| n == name) {
                return Err(usage(format!("--{name} given more than once")));
            }
            values.push((name.to_owned(), value));
            Ok(())
        };
        let mut it = args.iter();
        while let Some(arg) = it.next() {
            let Some(name) = arg.strip_prefix("--") else {
                if positional {
                    rest.push(arg.clone());
                    continue;
                }
                return Err(usage(format!("unexpected argument {arg}")));
            };
            match name.split_once('=') {
                Some((n, v)) => push(n, v.to_owned())?,
                None if BOOL_FLAGS.contains(&name) => push(name, "true".to_owned())?,
                None => {
                    let value = it
                        .next()
                        .ok_or_else(|| usage(format!("--{name} requires a value")))?;
                    push(name, value.clone())?;
                }
            }
        }
        Ok(Args {
            values,
            positional: rest,
        })
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.values
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    fn flag(&self, name: &str) -> Result<bool, Refusal> {
        match self.get(name) {
            None | Some("false") => Ok(false),
            Some("true") => Ok(true),
            Some(other) => Err(usage(format!("--{name} takes no value (got {other:?})"))),
        }
    }

    fn require(&self, name: &str) -> Result<&str, Refusal> {
        self.get(name)
            .ok_or_else(|| usage(format!("--{name} is required")))
    }

    fn number<T: std::str::FromStr>(&self, name: &str) -> Result<Option<T>, Refusal> {
        self.get(name)
            .map(|v| {
                v.parse::<T>()
                    .map_err(|_| usage(format!("--{name} {v:?} is not a number")))
            })
            .transpose()
    }

    fn duration(&self, name: &str) -> Result<Option<Duration>, Refusal> {
        self.get(name)
            .map(|v| {
                parse_duration(v)
                    .ok_or_else(|| usage(format!("--{name} {v:?} is not <n>s, <n>m or <n>h")))
            })
            .transpose()
    }
}

/// `<n>s`, `<n>m` or `<n>h`.
fn parse_duration(text: &str) -> Option<Duration> {
    let unit = match text.as_bytes().last()? {
        b's' => 1,
        b'm' => 60,
        b'h' => 3_600,
        _ => return None,
    };
    let n: u64 = text.get(..text.len().saturating_sub(1))?.parse().ok()?;
    Some(Duration::from_secs(n.checked_mul(unit)?))
}

/// The master seed: `--seed`, or the clock.
fn master_seed(args: &Args) -> Result<u64, Refusal> {
    match args.get("seed") {
        Some(v) => parse_seed(v).ok_or_else(|| usage(format!("--seed {v:?} is not a hex seed"))),
        None => Ok(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64)),
    }
}

/// The oracle: `--oracle`, or testutil's choice.
fn oracle_path(args: &Args) -> Result<PathBuf, Refusal> {
    if let Some(path) = args.get("oracle") {
        return Ok(PathBuf::from(path));
    }
    std::panic::catch_unwind(dcroxide_testutil::oracle_bin).map_err(|_| {
        config(
            "no oracle: pass --oracle, set DCROXIDE_ORACLE_BIN, or put the Go toolchain on PATH \
             to build tools/oracle",
        )
    })
}

/// A request list for a pipe that only asks `build_info`.
struct NoRequests;

impl Payload for NoRequests {
    fn requests(&self) -> &[Request] {
        &[]
    }
}

/// The oracle's `build_info`, from a pipe opened and closed for it.
fn oracle_build_info(bin: &Path) -> Result<Reply, Refusal> {
    let pipe: OraclePipe<NoRequests> =
        OraclePipe::spawn(&PipeConfig::new(bin.to_path_buf()), |_, _| {}).map_err(|f| match f {
            PipeFailure::Spawn(e) => {
                config(format!("the oracle {} did not start: {e}", bin.display()))
            }
            PipeFailure::Oracle { fault, .. } => config(format!("the oracle failed: {fault}")),
        })?;
    let info = pipe.build_info().clone();
    let _ = pipe.finish();
    Ok(info)
}

/// Whether the binary computes with overflow checks: an overflowing add
/// under `catch_unwind`, with a silent hook for the moment.  Called only
/// in an unwinding build, before the run's own hook is installed.
fn overflow_checks() -> bool {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the overflow is the probe: it panics exactly when overflow checks are on"
    )]
    let checked =
        std::panic::catch_unwind(|| std::hint::black_box(u8::MAX) + std::hint::black_box(1u8))
            .is_err();
    std::panic::set_hook(previous);
    checked
}

/// The manifest's `selection`: `all`, the whole families selected, or
/// `partial`.
fn selection(chosen: &[&'static ClassSpec]) -> Value {
    if chosen.len() == CLASSES.len() {
        return json!("all");
    }
    let chosen_names: BTreeSet<&str> = chosen.iter().map(|c| c.name).collect();
    let families: BTreeSet<Family> = chosen.iter().map(|c| c.family).collect();
    let whole = families.iter().all(|f| {
        CLASSES
            .iter()
            .filter(|c| c.family == *f)
            .all(|c| chosen_names.contains(c.name))
    });
    if whole {
        json!(families.iter().map(|f| f.name()).collect::<Vec<_>>())
    } else {
        json!("partial")
    }
}

const RUN_FLAGS: &[&str] = &[
    "out",
    "floors",
    "scale",
    "cases",
    "budget",
    "seed",
    "classes",
    "workers",
    "window",
    "flush-every",
    "hang-timeout",
    "progress-every",
    "oracle",
    "ledger",
];

fn cmd_run(args: &Args, raw: &[String]) -> Outcome {
    let out = PathBuf::from(args.require("out")?);
    let floors = args.flag("floors")?;
    let scale: Option<f64> = args.number("scale")?;
    let cases: Option<u64> = args.number("cases")?;
    let budget = args.duration("budget")?;
    let mode = match (floors, cases, budget) {
        (true, None, None) => {
            let scale = scale.unwrap_or(1.0);
            if !(scale.is_finite() && scale > 0.0) {
                return Err(usage(format!("--scale {scale} is not a positive number")));
            }
            Mode::Floors { scale }
        }
        (false, Some(n), None) if scale.is_none() && n > 0 => Mode::Cases(n),
        (false, None, Some(d)) if scale.is_none() => Mode::Budget(d),
        _ => {
            return Err(usage(
                "give exactly one of --floors [--scale F], --cases N (N > 0) or --budget DUR",
            ));
        }
    };
    let master = master_seed(args)?;
    let classes = select_classes(args.get("classes").unwrap_or("all")).map_err(usage)?;
    let workers = args.number("workers")?.unwrap_or_else(default_workers);
    let window = args.number("window")?.unwrap_or(512);
    let flush_every = args.number("flush-every")?.unwrap_or(64);
    if workers == 0 || flush_every == 0 {
        return Err(usage("--workers and --flush-every are at least 1"));
    }
    let hang_timeout = args
        .duration("hang-timeout")?
        .unwrap_or(Duration::from_secs(120));
    let progress_every = args
        .duration("progress-every")?
        .unwrap_or(Duration::from_secs(60));

    if cfg!(panic = "abort") {
        return Err(config(
            "built with panic = \"abort\": build with --profile soak (or soak-checked), whose \
             panics unwind, so a panic in the code under test is recorded with its case",
        ));
    }
    let root = repo_root().map_err(config)?;
    let cwd = std::env::current_dir().map_err(|e| config(format!("no current directory: {e}")))?;
    if let Some(problem) = out_dir_problem(&out, &cwd, &root, OutUse::Run) {
        return Err(config(format!("--out: {problem}")));
    }
    let out = if out.is_absolute() {
        out
    } else {
        cwd.join(out)
    };
    let source_differs = source_differences(&crate_dir(&root));
    if !source_differs.is_empty() {
        eprintln!(
            "sigsoak: warning: this binary was not built from the checkout at {} ({}); the run \
             is not gate-eligible",
            root.display(),
            source_differs.join(", ")
        );
    }
    let oracle = oracle_path(args)?;
    let build_info = oracle_build_info(&oracle)?;
    let pin = check_pin(&build_info);
    if !pin.consistent() {
        return Err(config(format!(
            "the oracle {} links another specification: {}",
            oracle.display(),
            pin.problems().join("; ")
        )));
    }
    let overflow = overflow_checks();
    install_panic_hook();

    println!("sigsoak: master seed {master:#018x}");
    let git = git_state(&root);
    let profile = profile_name();
    let selection = selection(&classes);
    let gate_eligible = matches!(profile.as_deref(), Some("soak" | "soak-checked"))
        && source_differs.is_empty()
        && git["dirty"] == json!(false)
        && pin.consistent()
        && mode == Mode::Floors { scale: 1.0 }
        && selection != json!("partial");
    let start = unix_now();
    let mut cfg = RunConfig::new(master, classes.clone(), mode, oracle.clone());
    cfg.workers = workers;
    cfg.window = window;
    cfg.flush_every = flush_every;
    cfg.hang_timeout = hang_timeout;
    cfg.progress_every = Some(progress_every);
    cfg.out = Some(out.clone());
    cfg.kind_coverage = gate_eligible;
    let targets: Vec<Value> = classes
        .iter()
        .zip(class_targets(&classes, mode))
        .map(|(c, target)| json!({ "name": c.name, "target": target }))
        .collect();
    cfg.manifest = Some(json!({
        "schema": SCHEMA,
        "command": "run",
        "args": raw,
        "tool": {
            "crate_version": env!("CARGO_PKG_VERSION"),
            "generator_fingerprint": hex(&fingerprint()),
            "source_matches_checkout": source_differs.is_empty(),
            "source_differs": source_differs,
        },
        "master_seed": format!("{master:#018x}"),
        "mode": mode.to_json(),
        "classes": targets,
        "selection": selection,
        "canary": null,
        "workers": workers,
        "window": window,
        "flush_every": flush_every,
        "hang_timeout_s": hang_timeout.as_secs(),
        "start": { "unix": start, "utc": utc(start) },
        "end": null,
        "status": "running",
        "gate_eligible": gate_eligible,
        "git": git,
        "pin": pin.to_json(),
        "oracle": oracle_json(&oracle, &build_info, cfg.gomaxprocs),
        "lock": lock_versions(CARGO_LOCK, &LOCKED_CRATES),
        "rust": {
            "rustc_vv": rustc_vv(&root),
            "profile": profile,
            "debug_assertions": cfg!(debug_assertions),
            "overflow_checks": overflow,
            "panic": if cfg!(panic = "unwind") { "unwind" } else { "abort" },
            "RUSTFLAGS": std::env::var("RUSTFLAGS").ok(),
            "RUSTUP_TOOLCHAIN": std::env::var("RUSTUP_TOOLCHAIN").ok(),
        },
        "platform": platform(),
    }));

    let summary = run::run(&cfg).map_err(config)?;
    eprint!("{}", summary.render());
    eprintln!("sigsoak: {} ({})", summary.status.name(), out.display());
    if let Some(ledger) = args.get("ledger") {
        let modules: Vec<String> = pin
            .modules
            .iter()
            .map(|m| m.built.clone().unwrap_or_default())
            .collect();
        let fields = [
            utc(start),
            "run".to_owned(),
            format!("{master:#018x}"),
            git["head"].as_str().unwrap_or("").to_owned(),
            format!("{DCRD_PARITY_COMMIT} {}", modules.join(" ")),
            summary.cases.to_string(),
            summary.status.name().to_owned(),
            out.display().to_string(),
        ];
        let fields: Vec<&str> = fields.iter().map(String::as_str).collect();
        if let Err(e) = append_ledger(Path::new(ledger), &fields) {
            eprintln!("sigsoak: could not append to the ledger {ledger}: {e}");
        }
    }
    Ok(match summary.status {
        RunStatus::Passed => ExitCode::SUCCESS,
        RunStatus::Failed => ExitCode::from(1),
        RunStatus::Aborted => ExitCode::from(3),
    })
}

fn cmd_replay(args: &Args) -> Outcome {
    let seed = args.require("seed")?;
    let seed =
        parse_seed(seed).ok_or_else(|| usage(format!("--seed {seed:?} is not a hex seed")))?;
    let class = args.require("class")?;
    let index: u64 = args
        .number("case")?
        .ok_or_else(|| usage("--case is required"))?;
    let oracle = oracle_path(args)?;
    install_panic_hook();
    let report = run::replay(seed, class, index, None, &oracle).map_err(config)?;
    println!(
        "class {} case {} under master seed {seed:#018x}",
        report.class, report.index
    );
    println!("case seed {:#018x}", report.case_seed);
    println!("variant {}", report.case.variant);
    for (j, request) in report.case.requests.iter().enumerate() {
        println!("request {j}: {} {}", request.cmd.name(), hex(&request.data));
        println!("  intent: {:?}", report.case.intents[j]);
        match &report.ours[j] {
            Ok(o) => println!("  ours: {} ({:?})", o.answer.describe(), o.detail),
            Err(message) => println!("  ours: panic: {message}"),
        }
        match report.replies.get(j) {
            Some(reply) => println!("  oracle: {}", reply.raw),
            None => println!("  oracle: no answer"),
        }
        if let Some(Some(model)) = report.model.per_request.get(j) {
            println!("  model: {model:?}");
        }
    }
    if let Some(fault) = &report.fault {
        println!("oracle fault: {fault}");
    }
    println!(
        "result: {}",
        match report.result.status {
            dcroxide_sigdiff::compare::Status::Agree => "agree",
            dcroxide_sigdiff::compare::Status::Disagree => "disagree",
            dcroxide_sigdiff::compare::Status::OracleFailure => "oracle failure",
            dcroxide_sigdiff::compare::Status::OursPanicked => "dcroxide panicked",
        }
    );
    for failure in &report.result.failures {
        println!(
            "  {}{}: {}",
            failure.category.name(),
            failure
                .request
                .map(|j| format!(" (request {j})"))
                .unwrap_or_default(),
            failure.detail
        );
    }
    println!("leaf {}", hex(&report.leaf));
    Ok(if report.result.failures.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

/// A run's directory, read back: its manifest and its digests per class
/// (`n -> (digest, final)`).
struct RunRecord {
    manifest: Value,
    digests: BTreeMap<String, BTreeMap<u64, (String, bool)>>,
}

impl RunRecord {
    fn read(dir: &Path) -> Result<RunRecord, Refusal> {
        let read = |name: &str| {
            std::fs::read_to_string(dir.join(name))
                .map_err(|e| config(format!("{}: {e}", dir.join(name).display())))
        };
        let manifest: Value = serde_json::from_str(&read("manifest.json")?)
            .map_err(|e| config(format!("{}/manifest.json: {e}", dir.display())))?;
        let mut digests: BTreeMap<String, BTreeMap<u64, (String, bool)>> = BTreeMap::new();
        for line in read("digests.tsv")?.lines().skip(1) {
            let fields: Vec<&str> = line.split('\t').collect();
            let [class, n, digest, is_final] = fields[..] else {
                return Err(config(format!(
                    "{}/digests.tsv: bad line {line:?}",
                    dir.display()
                )));
            };
            let n: u64 = n
                .parse()
                .map_err(|_| config(format!("{}/digests.tsv: bad count {n:?}", dir.display())))?;
            digests
                .entry(class.to_owned())
                .or_default()
                .insert(n, (digest.to_owned(), is_final == "true"));
        }
        Ok(RunRecord { manifest, digests })
    }

    fn final_row(&self, class: &str) -> Option<(u64, &str)> {
        self.digests
            .get(class)?
            .iter()
            .find_map(|(n, (d, f))| f.then_some((*n, d.as_str())))
    }

    fn modules(&self) -> Value {
        let mut out = serde_json::Map::new();
        if let Some(modules) = self.manifest["pin"]["oracle_modules"].as_object() {
            for (module, pin) in modules {
                out.insert(module.clone(), pin["built"].clone());
            }
        }
        Value::Object(out)
    }
}

fn cmd_compare(args: &Args) -> Outcome {
    let replay = args.flag("replay")?;
    let exploratory = args.flag("exploratory")?;
    let allow_subset = args.flag("allow-subset")?;
    let allow_fingerprint = args.flag("allow-fingerprint-change")?;
    let allow_pin = args.flag("allow-pin-change")?;
    let [dir_a, dir_b] = &args.positional[..] else {
        return Err(usage("compare takes two run directories"));
    };
    let a = RunRecord::read(Path::new(dir_a))?;
    let b = RunRecord::read(Path::new(dir_b))?;
    let mut failures: Vec<String> = Vec::new();
    let mut relaxations: Vec<&str> = Vec::new();

    // A run held against itself compares nothing.
    let canonical = |dir: &str| std::fs::canonicalize(dir).ok();
    if canonical(dir_a).is_some_and(|a| canonical(dir_b) == Some(a)) {
        failures.push(format!("{dir_a} and {dir_b} are the same run"));
    }
    if a.manifest["master_seed"] != b.manifest["master_seed"] {
        failures.push(format!(
            "master seeds differ: {} and {}",
            a.manifest["master_seed"], b.manifest["master_seed"]
        ));
    }
    let classes_a: BTreeSet<&String> = a.digests.keys().collect();
    let classes_b: BTreeSet<&String> = b.digests.keys().collect();
    let common: Vec<&String> = classes_a.intersection(&classes_b).copied().collect();
    let missing: Vec<String> = classes_a
        .symmetric_difference(&classes_b)
        .map(|c| {
            let side = if classes_a.contains(c) { dir_b } else { dir_a };
            format!("{c} (missing from {side})")
        })
        .collect();
    if common.is_empty() {
        failures.push("the runs have no class in common".to_owned());
    }
    if !missing.is_empty() {
        if allow_subset {
            relaxations.push("--allow-subset");
        } else {
            failures.push(format!("classes missing: {}", missing.join(", ")));
        }
    }
    let fp = |r: &RunRecord| r.manifest["tool"]["generator_fingerprint"].clone();
    if fp(&a) != fp(&b) {
        if allow_fingerprint {
            relaxations.push("--allow-fingerprint-change");
        } else {
            failures.push(format!(
                "generator fingerprints differ: {} and {}",
                fp(&a),
                fp(&b)
            ));
        }
    }
    if a.modules() != b.modules() {
        if allow_pin {
            relaxations.push("--allow-pin-change");
        } else {
            failures.push(format!(
                "oracle modules differ: {} and {}",
                a.modules(),
                b.modules()
            ));
        }
    }
    if exploratory {
        relaxations.push("--exploratory");
    } else {
        let eligible = |r: &RunRecord| r.manifest["gate_eligible"] == json!(true);
        let passed = |r: &RunRecord| r.manifest["status"] == json!("passed");
        if !eligible(&a) {
            failures.push(format!("{dir_a} is not gate-eligible"));
        }
        if !replay && !eligible(&b) {
            failures.push(format!("{dir_b} is not gate-eligible"));
        }
        for (dir, r) in [(dir_a, &a), (dir_b, &b)] {
            if !passed(r) {
                failures.push(format!("{dir} has status {}", r.manifest["status"]));
            }
        }
    }

    for class in &common {
        let (Some((n_a, d_a)), Some((n_b, d_b))) = (a.final_row(class), b.final_row(class)) else {
            failures.push(format!("{class}: no final digest"));
            continue;
        };
        let verdict = if n_a == 0 || n_b == 0 {
            format!("nothing compared, at {n_a} and {n_b} cases")
        } else if replay {
            match a.digests[*class].get(&n_b) {
                Some((d, _)) if d == d_b => format!("equal at {n_b}"),
                Some(_) => format!("different at {n_b}"),
                None => format!("{n_b} is not a count {dir_a} recorded"),
            }
        } else if n_a == n_b && d_a == d_b {
            format!("equal at {n_a}")
        } else if n_a != n_b {
            format!("different counts {n_a} and {n_b}")
        } else {
            format!("different at {n_a}")
        };
        println!("  {class}: {verdict}");
        if !verdict.starts_with("equal") {
            failures.push(format!("{class}: {verdict}"));
        }
    }
    for m in &missing {
        println!("  {m}: missing");
    }
    for (dir, r) in [(dir_a, &a), (dir_b, &b)] {
        println!(
            "{dir}: pin {} fingerprint {} selection {} status {}",
            r.modules(),
            fp(r),
            r.manifest["selection"],
            r.manifest["status"]
        );
    }
    for failure in &failures {
        println!("FAIL {failure}");
    }
    let kind = if replay {
        "replay comparison"
    } else {
        "comparison"
    };
    let relaxed = if relaxations.is_empty() {
        String::new()
    } else {
        format!(" (relaxed: {})", relaxations.join(", "))
    };
    let exploratory_note = if exploratory {
        "; exploratory: not gate evidence"
    } else {
        ""
    };
    if failures.is_empty() {
        println!("{kind}: equal{relaxed}{exploratory_note}");
        Ok(ExitCode::SUCCESS)
    } else {
        println!(
            "{kind}: {} failures{relaxed}{exploratory_note}",
            failures.len()
        );
        Ok(ExitCode::from(1))
    }
}

fn cmd_list() -> Outcome {
    for class in CLASSES {
        let size = match class.size {
            dcroxide_sigdiff::class::Size::Sampled { floor } => format!("sampled, floor {floor}"),
            dcroxide_sigdiff::class::Size::Stratified { strata, floor } => {
                format!("{strata} strata, floor {floor}")
            }
            dcroxide_sigdiff::class::Size::Finite { size } => format!("finite, {size}"),
        };
        let commands: Vec<&str> = class.commands.iter().map(|c| c.name()).collect();
        println!(
            "{}\t{}\t{:?}\t{size}\tper-PR {}\t{}\n    {}",
            class.name,
            class.family.name(),
            class.tier,
            class.pr_cases,
            commands.join(","),
            class.doc
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// Notes each panic's place for the record of the case it hit, and prints
/// the first ten.
fn install_panic_hook() {
    static PANICS: AtomicUsize = AtomicUsize::new(0);
    std::panic::set_hook(Box::new(|info| {
        run::note_panic(info);
        let n = PANICS.fetch_add(1, Ordering::Relaxed);
        if n < 10 {
            eprintln!("sigsoak: panic: {info}");
        } else if n == 10 {
            eprintln!("sigsoak: further panics are recorded with their cases, not printed");
        }
    }));
}

fn main() -> ExitCode {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let Some((cmd, rest)) = raw.split_first() else {
        eprint!("{HELP}");
        return ExitCode::from(2);
    };
    let result = match cmd.as_str() {
        "run" => Args::parse(rest, RUN_FLAGS, false).and_then(|a| cmd_run(&a, &raw)),
        "replay" => Args::parse(rest, &["seed", "class", "case", "oracle"], false)
            .and_then(|a| cmd_replay(&a)),
        "compare" => Args::parse(
            rest,
            &[
                "replay",
                "exploratory",
                "allow-subset",
                "allow-fingerprint-change",
                "allow-pin-change",
            ],
            true,
        )
        .and_then(|a| cmd_compare(&a)),
        "list" => Args::parse(rest, &[], false).and_then(|_| cmd_list()),
        "help" | "--help" | "-h" => {
            print!("{HELP}");
            Ok(ExitCode::SUCCESS)
        }
        other => Err(usage(format!("unknown command {other}"))),
    };
    match result {
        Ok(code) => code,
        Err(Refusal::Usage(message)) => {
            eprintln!("sigsoak: {message}");
            eprint!("{HELP}");
            ExitCode::from(2)
        }
        Err(Refusal::Config(message)) => {
            eprintln!("sigsoak: {message}");
            ExitCode::from(2)
        }
    }
}
