// SPDX-License-Identifier: ISC
//! `sigsoak`: the signature differential soak's command line.  See `HELP`.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dcroxide_sigdiff::canary::{CANARIES, MODEL_BASELINE, find_stand_in, select_canaries};
use dcroxide_sigdiff::class::{CLASSES, ClassSpec, Family, select_classes};
use dcroxide_sigdiff::cmd::{Cmd, Request};
use dcroxide_sigdiff::compare::Category;
use dcroxide_sigdiff::fingerprint::{fingerprint, source_differences};
use dcroxide_sigdiff::fuzz::{
    self, ED25519_MODEL_TARGET, FuzzOracle, SEED_MASTER, Target, seed_indices, seed_input,
};
use dcroxide_sigdiff::manifest::{
    Build, CARGO_LOCK, LOCKED_CRATES, PinCheck, SCHEMA, check_pin, crate_dir, gate_eligible,
    git_state, lock_versions, oracle_json, platform, repo_root, rustc_vv, unix_now, utc,
};
use dcroxide_sigdiff::pipe::{OraclePipe, Payload, PipeConfig, PipeFailure};
use dcroxide_sigdiff::record::{
    OutUse, append_ledger, out_dir_problem, write_canary_record, write_json,
};
use dcroxide_sigdiff::reply::Reply;
use dcroxide_sigdiff::run::{
    self, CanaryVolume, Mode, RequestLines, RunConfig, RunStatus, baseline_classes, class_targets,
    default_workers, failure_line,
};
use dcroxide_sigdiff::witness::{self, FILE_NAME, WITNESS_CLASSES, WITNESS_SEED};
use dcroxide_testutil::{DCRD_PARITY_COMMIT, Oracle, hex, parse_seed, unhex};
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
  sigsoak canary --out DIR [--seed HEX] [--canary LIST|all] [--cases N]
              [--workers N] [--oracle PATH]
      Stand deliberately broken models in for dcroxide and show that the
      classes catch them: first the models with no break over N cases of
      every class of the selected model canaries' commands, which must
      agree with dcrd; then each canary over its primary class until it
      first disagrees, which must happen within 10000 cases, and over N
      cases of every other class of its commands, where it may disagree
      only within its footprint.  N defaults to 10000.  Writes
      DIR/canary/, which must hold nothing yet.
  sigsoak replay --seed HEX --class NAME --case N [--canary NAME]
              [--oracle PATH]
      Regenerate one case, answer it on both sides and print everything:
      requests, intents, both answers, the comparison and the digest leaf.
      --canary stands a canary (or model-baseline) in for dcroxide.
  sigsoak compare [--replay] [--exploratory] [--allow-subset]
              [--allow-fingerprint-change] [--allow-pin-change] DIR_A DIR_B
      Hold two runs' digests against each other; a class either run
      completed no case of compares nothing and fails.  --replay: DIR_B is
      a shorter run with DIR_A's seed, compared at DIR_A's checkpoints.
  sigsoak list [--canaries]
      Print every class, or every canary with its primary and footprint.
  sigsoak emit-corpus --out DIR [--seed HEX] [--oracle PATH]
      Write DIR/sigdiff_witness_vectors.txt, the witness vectors
      dcroxide-dcrec keeps: for each witness class, from case 0 under the
      seed (default 0x7769746e65737331), the first case of each variant
      group (a variant's first /-separated part) and each dcrd verdict,
      with dcrd's answer.  Every case must agree with dcrd and get the
      answer it was built for, and each class must fill its lines within
      4096 cases.  DIR must lie outside the repository and hold nothing.
  sigsoak fuzz-seeds --out DIR [--seed HEX] [--cases N]
      Write DIR/<target>/<class>-<index> for each signature fuzz target
      (the five dcrec_diff_* and dcrec_ed25519_model): the input that
      regenerates case <index> of <class> under the seed (default
      0x66757a7a73656564), for the cases the per-PR tests run, or, with
      --cases, N of each sampled class (finite classes of at most 128
      whole, larger ones N at an even stride).  Needs no oracle.  DIR must
      lie outside the repository and hold nothing.
  sigsoak fuzz-replay --target NAME [--canary NAME] [--oracle PATH]
              (FILE... | --hex HEX)
      Decode each input as fuzz target NAME decodes it (dcrec_diff_ecdsa,
      dcrec_diff_recover, dcrec_diff_pubkey, dcrec_diff_schnorr,
      dcrec_diff_ed25519, or dcrec_ed25519_model, which needs no oracle),
      answer it as the target does and print the report: the class, index
      and variant, each request with both intents and both answers, and
      the comparison.  --canary stands a canary in for dcroxide.  An
      oracle that fails on an input is started afresh for the next.
  sigsoak help
      Print this.

LIST is comma-separated class names or patterns with * (EV-*,K-wrap); the
default is every class.  A canary LIST takes names, ids (C1 to C18) or
patterns the same way.  DUR is <n>s, <n>m or <n>h.  --oracle defaults to
DCROXIDE_ORACLE_BIN, or tools/oracle built with the Go toolchain on PATH.
--ledger appends one line per run to FILE.

exit codes: 0 pass; 1 a criterion, a comparison or a replayed fuzz input
failed; 2 usage or configuration error; 3 aborted (dcroxide hung, oracle
faults exhausted, or the oracle failed during emit-corpus).
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
const BOOL_FLAGS: [&str; 7] = [
    "floors",
    "replay",
    "exploratory",
    "allow-subset",
    "allow-fingerprint-change",
    "allow-pin-change",
    "canaries",
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

/// What `run`, `canary` and `emit-corpus` establish before they start.
struct Preflight {
    /// The repository root, canonical.
    root: PathBuf,
    /// `--out`, absolute.
    out: PathBuf,
    /// How the binary's embedded source differs from the checkout's.
    source_differs: Vec<String>,
    /// The oracle binary.
    oracle: PathBuf,
    /// Its `build_info`.
    build_info: Reply,
    /// Its pin check, which passed.
    pin: PinCheck,
    /// How the binary was built.
    build: Build,
}

/// Why an aborting build is refused: a panic in the code under test must
/// unwind to be recorded with its case.
const ABORTING_BUILD: &str = "built with panic = \"abort\": build with --profile soak (or \
                              soak-checked), whose panics unwind, so a panic in the code \
                              under test is recorded with its case";

/// `--out`, checked for `usage`.
struct OutDir {
    /// The repository root, canonical.
    root: PathBuf,
    /// `--out`, absolute.
    out: PathBuf,
    /// How the binary's embedded source differs from the checkout's.
    source_differs: Vec<String>,
}

/// `out` as `usage` may write into it, each problem a refusal (exit 2): a
/// repository root that resolves, and an `out` outside it that `usage`
/// may write into.  A binary built from another tree is only warned about.
fn out_dir(out: &str, usage: OutUse) -> Result<OutDir, Refusal> {
    let root = repo_root().map_err(config)?;
    let cwd = std::env::current_dir().map_err(|e| config(format!("no current directory: {e}")))?;
    let out = PathBuf::from(out);
    if let Some(problem) = out_dir_problem(&out, &cwd, &root, usage) {
        return Err(config(format!("--out: {problem}")));
    }
    let out = if out.is_absolute() {
        out
    } else {
        cwd.join(out)
    };
    let source_differs = source_differences(&crate_dir(&root));
    if !source_differs.is_empty() {
        let consequence = match usage {
            OutUse::Run | OutUse::Canary => "the run is not gate-eligible",
            OutUse::EmitCorpus => "the witness file may not match this checkout's generators",
            OutUse::FuzzSeeds => "the seed inputs may not match this checkout's generators",
        };
        eprintln!(
            "sigsoak: warning: this binary was not built from the checkout at {} ({}); \
             {consequence}",
            root.display(),
            source_differs.join(", ")
        );
    }
    Ok(OutDir {
        root,
        out,
        source_differs,
    })
}

/// The checks `run`, `canary` and `emit-corpus` make before they start,
/// each a refusal (exit 2): a build whose panics unwind, `out` as
/// [`out_dir`] checks it, and an oracle that keeps the pin rule.  Probes
/// the build's overflow checks and installs the panic hook last.
fn preflight(args: &Args, out: &str, usage: OutUse) -> Result<Preflight, Refusal> {
    if cfg!(panic = "abort") {
        return Err(config(ABORTING_BUILD));
    }
    let OutDir {
        root,
        out,
        source_differs,
    } = out_dir(out, usage)?;
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
    let build = Build::current(Some(overflow_checks()));
    install_panic_hook();
    Ok(Preflight {
        root,
        out,
        source_differs,
        oracle,
        build_info,
        pin,
        build,
    })
}

/// The manifest fields `run` and `canary` share, with status `running`.
fn base_manifest(
    command: &str,
    raw: &[String],
    master: u64,
    pre: &Preflight,
    git: &Value,
    gomaxprocs: u32,
    start: u64,
) -> Value {
    let mut rust = pre.build.to_json();
    rust.insert("rustc_vv".into(), json!(rustc_vv(&pre.root)));
    rust.insert("RUSTFLAGS".into(), json!(std::env::var("RUSTFLAGS").ok()));
    rust.insert(
        "RUSTUP_TOOLCHAIN".into(),
        json!(std::env::var("RUSTUP_TOOLCHAIN").ok()),
    );
    json!({
        "schema": SCHEMA,
        "command": command,
        "args": raw,
        "tool": {
            "crate_version": env!("CARGO_PKG_VERSION"),
            "generator_fingerprint": hex(&fingerprint()),
            "source_matches_checkout": pre.source_differs.is_empty(),
            "source_differs": pre.source_differs,
        },
        "master_seed": format!("{master:#018x}"),
        "start": { "unix": start, "utc": utc(start) },
        "end": null,
        "status": "running",
        "git": git,
        "pin": pre.pin.to_json(),
        "oracle": oracle_json(&pre.oracle, &pre.build_info, gomaxprocs),
        "lock": lock_versions(CARGO_LOCK, &LOCKED_CRATES),
        "rust": rust,
        "platform": platform(),
    })
}

/// A run's exit code: 0 passed, 1 failed, 3 aborted.
fn exit_code(status: RunStatus) -> ExitCode {
    match status {
        RunStatus::Passed => ExitCode::SUCCESS,
        RunStatus::Failed => ExitCode::from(1),
        RunStatus::Aborted => ExitCode::from(3),
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
    let out = args.require("out")?;
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

    let pre = preflight(args, out, OutUse::Run)?;
    let out = pre.out.clone();
    println!("sigsoak: master seed {master:#018x}");
    let git = git_state(&pre.root);
    let selection = selection(&classes);
    if mode == (Mode::Floors { scale: 1.0 })
        && let Err(problem) = pre.build.soak_profile()
    {
        eprintln!("sigsoak: warning: the run is not gate-eligible: {problem}");
    }
    let eligible = gate_eligible(
        &pre.build,
        &pre.source_differs,
        &git,
        &pre.pin,
        mode,
        &selection,
    );
    let start = unix_now();
    let mut cfg = RunConfig::new(master, classes.clone(), mode, pre.oracle.clone());
    cfg.workers = workers;
    cfg.window = window;
    cfg.flush_every = flush_every;
    cfg.hang_timeout = hang_timeout;
    cfg.progress_every = Some(progress_every);
    cfg.out = Some(out.clone());
    cfg.kind_coverage = eligible;
    let targets: Vec<Value> = classes
        .iter()
        .zip(class_targets(&classes, mode))
        .map(|(c, target)| json!({ "name": c.name, "target": target }))
        .collect();
    let mut manifest = base_manifest("run", raw, master, &pre, &git, cfg.gomaxprocs, start);
    manifest["mode"] = mode.to_json();
    manifest["classes"] = json!(targets);
    manifest["selection"] = selection;
    manifest["canary"] = Value::Null;
    manifest["workers"] = json!(workers);
    manifest["window"] = json!(window);
    manifest["flush_every"] = json!(flush_every);
    manifest["hang_timeout_s"] = json!(hang_timeout.as_secs());
    manifest["gate_eligible"] = json!(eligible);
    cfg.manifest = Some(manifest);

    let summary = run::run(&cfg).map_err(config)?;
    eprint!("{}", summary.render());
    eprintln!("sigsoak: {} ({})", summary.status.name(), out.display());
    if let Some(ledger) = args.get("ledger") {
        let modules: Vec<String> = pre
            .pin
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
    Ok(exit_code(summary.status))
}

const CANARY_FLAGS: &[&str] = &["out", "seed", "canary", "cases", "workers", "oracle"];

fn cmd_canary(args: &Args, raw: &[String]) -> Outcome {
    let out = args.require("out")?;
    let canaries = select_canaries(args.get("canary").unwrap_or("all")).map_err(usage)?;
    let cases: u64 = args.number("cases")?.unwrap_or(10_000);
    let workers = args.number("workers")?.unwrap_or_else(default_workers);
    if cases == 0 || workers == 0 {
        return Err(usage("--cases and --workers are at least 1"));
    }
    let master = master_seed(args)?;

    let pre = preflight(args, out, OutUse::Canary)?;
    let dir = pre.out.join("canary");
    println!("sigsoak: master seed {master:#018x}");
    let git = git_state(&pre.root);
    let start = unix_now();
    let mut base = RunConfig::new(master, Vec::new(), Mode::Cases(cases), pre.oracle.clone());
    base.workers = workers;
    base.progress_every = Some(Duration::from_secs(60));
    base.out = Some(dir.clone());
    let mut manifest = base_manifest("canary", raw, master, &pre, &git, base.gomaxprocs, start);
    manifest["mode"] = base.mode.to_json();
    manifest["canary"] = json!(canaries.iter().map(|c| c.name).collect::<Vec<_>>());
    manifest["baseline_classes"] = json!(
        baseline_classes(&canaries)
            .iter()
            .map(|c| c.name)
            .collect::<Vec<_>>()
    );
    manifest["workers"] = json!(workers);
    manifest["window"] = json!(base.window);
    manifest["flush_every"] = json!(base.flush_every);
    manifest["hang_timeout_s"] = json!(base.hang_timeout.as_secs());
    manifest["gate_eligible"] = json!(false);
    let manifest_path = dir.join("manifest.json");
    std::fs::create_dir_all(&dir)
        .and_then(|()| write_json(&manifest_path, &manifest))
        .map_err(|e| config(format!("cannot write {}: {e}", manifest_path.display())))?;
    base.manifest = Some(manifest.clone());

    let report = run::canary_run(&base, &canaries, CanaryVolume::Soak { cases }).map_err(config)?;
    let status = report.status();
    manifest["status"] = json!(status.name());
    manifest["end"] = json!({ "unix": unix_now(), "utc": utc(unix_now()) });
    write_canary_record(&dir, &report)
        .and_then(|()| write_json(&manifest_path, &manifest))
        .map_err(|e| config(format!("cannot write the canary record: {e}")))?;
    eprint!("{}", report.render());
    eprintln!("sigsoak: canary run {} ({})", status.name(), dir.display());
    Ok(exit_code(status))
}

const EMIT_FLAGS: &[&str] = &["out", "seed", "oracle"];

fn cmd_emit_corpus(args: &Args) -> Outcome {
    let out = args.require("out")?;
    let master = match args.get("seed") {
        Some(v) => parse_seed(v).ok_or_else(|| usage(format!("--seed {v:?} is not a hex seed")))?,
        None => WITNESS_SEED,
    };
    let pre = preflight(args, out, OutUse::EmitCorpus)?;
    println!("sigsoak: master seed {master:#018x}");
    let lines = match witness::emit(master, &PipeConfig::new(pre.oracle.clone())) {
        Ok(lines) => lines,
        Err(failure) => {
            eprintln!("sigsoak: no witness file:\n{failure}");
            return Ok(ExitCode::from(failure.exit_code()));
        }
    };
    let path = pre.out.join(FILE_NAME);
    std::fs::create_dir_all(&pre.out)
        .and_then(|()| std::fs::write(&path, witness::file(master, &lines)))
        .map_err(|e| config(format!("cannot write {}: {e}", path.display())))?;
    for class in WITNESS_CLASSES {
        let n = lines.iter().filter(|l| l.class == class.name).count();
        eprintln!(
            "  {}: {n} line{}",
            class.name,
            if n == 1 { "" } else { "s" }
        );
    }
    eprintln!("sigsoak: wrote {} lines to {}", lines.len(), path.display());
    Ok(ExitCode::SUCCESS)
}

const FUZZ_SEEDS_FLAGS: &[&str] = &["out", "seed", "cases"];

/// `fuzz-seeds`: every signature fuzz target's seed inputs, one file each,
/// in a directory per target; `dcrec_diff_ed25519`'s are written for
/// `dcrec_ed25519_model` too, so each directory stands alone.
fn cmd_fuzz_seeds(args: &Args) -> Outcome {
    let out = args.require("out")?;
    let master = match args.get("seed") {
        Some(v) => parse_seed(v).ok_or_else(|| usage(format!("--seed {v:?} is not a hex seed")))?,
        None => SEED_MASTER,
    };
    let cases: Option<u64> = args.number("cases")?;
    if cases == Some(0) {
        return Err(usage("--cases is at least 1"));
    }
    let out = out_dir(out, OutUse::FuzzSeeds)?.out;
    println!("sigsoak: master seed {master:#018x}");
    let mut total = 0usize;
    for target in Target::ALL {
        let mut names = vec![target.name()];
        if target == Target::Ed25519 {
            names.push(ED25519_MODEL_TARGET);
        }
        let dirs: Vec<PathBuf> = names.iter().map(|name| out.join(name)).collect();
        for dir in &dirs {
            std::fs::create_dir_all(dir)
                .map_err(|e| config(format!("cannot create {}: {e}", dir.display())))?;
        }
        let mut written = 0usize;
        for class in target.classes() {
            for index in seed_indices(class, cases) {
                let input = seed_input(class, master, index);
                let file = format!("{}-{index}", class.name);
                for dir in &dirs {
                    let path = dir.join(&file);
                    std::fs::write(&path, &input)
                        .map_err(|e| config(format!("cannot write {}: {e}", path.display())))?;
                }
                written = written.saturating_add(1);
            }
        }
        for name in &names {
            eprintln!("  {name}: {written} inputs");
        }
        total = total.saturating_add(written.saturating_mul(names.len()));
    }
    eprintln!("sigsoak: wrote {total} inputs to {}", out.display());
    Ok(ExitCode::SUCCESS)
}

/// The bytes `text` spells in hex, or `None` when it spells none.
fn parse_hex(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    (text.len().is_multiple_of(2) && text.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| unhex(text))
}

const FUZZ_REPLAY_FLAGS: &[&str] = &["target", "canary", "oracle", "hex"];

/// The oracle at `path`, started and held to the pin, for `fuzz-replay`.
fn start_fuzz_oracle(path: &Path) -> Result<FuzzOracle, String> {
    let started = std::panic::catch_unwind(|| Oracle::spawn_at(path))
        .map_err(|_| format!("the oracle {} did not start", path.display()))?;
    FuzzOracle::new(started).map_err(|why| format!("{}: {why}", path.display()))
}

/// `fuzz-replay`: each input checked as its fuzz target checks it, with
/// the target's report printed whatever the outcome.  dcroxide's panics
/// unwind here, so each is reported with its input, and a panic anywhere
/// else in the check (a generator's, say) is caught and reported too.  An
/// oracle that fails on an input, by exiting or by a reply that breaks the
/// protocol, may be gone or out of step with its pipe, so the inputs after
/// that one go to a fresh oracle.
fn cmd_fuzz_replay(args: &Args) -> Outcome {
    if cfg!(panic = "abort") {
        return Err(config(ABORTING_BUILD));
    }
    let name = args.require("target")?;
    let target = match Target::find(name) {
        Some(target) => Some(target),
        None if name == ED25519_MODEL_TARGET => None,
        None => {
            let names: Vec<&str> = Target::ALL.iter().map(|t| t.name()).collect();
            return Err(usage(format!(
                "no fuzz target {name}: {}, or {ED25519_MODEL_TARGET}",
                names.join(", ")
            )));
        }
    };
    let canary = args
        .get("canary")
        .map(|c| {
            find_stand_in(c).ok_or_else(|| {
                config(format!(
                    "no canary {c} (sigsoak list --canaries prints them)"
                ))
            })
        })
        .transpose()?;
    let inputs: Vec<(String, Vec<u8>)> = match (args.get("hex"), args.positional.as_slice()) {
        (Some(text), []) => {
            let data =
                parse_hex(text).ok_or_else(|| usage(format!("--hex {text:?} is not hex")))?;
            vec![("--hex".to_owned(), data)]
        }
        (None, files) if !files.is_empty() => files
            .iter()
            .map(|file| {
                std::fs::read(file)
                    .map(|data| (file.clone(), data))
                    .map_err(|e| config(format!("cannot read {file}: {e}")))
            })
            .collect::<Result<_, _>>()?,
        _ => {
            return Err(usage(
                "fuzz-replay takes input files or --hex HEX, not both",
            ));
        }
    };
    // The oracle, with the path it was started from.
    let mut oracle = match target {
        Some(_) => {
            let path = oracle_path(args)?;
            let oracle = start_fuzz_oracle(&path).map_err(config)?;
            println!("sigsoak: {}", oracle.describe());
            Some((path, oracle))
        }
        None => None,
    };
    install_panic_hook();
    if let Some(canary) = &canary {
        println!(
            "canary {} answers in dcroxide's place on {}",
            canary.name,
            command_names(canary.commands)
        );
    }
    let ours = run::ours_answerer(canary);
    let mut failed = false;
    for (at, (input, data)) in inputs.iter().enumerate() {
        let report = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            match (target, oracle.as_mut()) {
                (Some(target), Some((_, oracle))) => {
                    fuzz::examine(target, data, &ours, &mut |request| oracle.answer(request))
                }
                _ => fuzz::examine_ed25519_model(data, &ours),
            }
        }));
        let mut oracle_failed = false;
        match report {
            Ok(Some(report)) => {
                println!("{input}:\n{report}");
                failed |= !report.agreed();
                oracle_failed = report.failures.iter().any(|f| {
                    matches!(
                        f.category,
                        Category::OracleCrashed | Category::OracleHung | Category::Protocol
                    )
                });
            }
            Ok(None) => println!("{input}: its first byte reaches no class of {name}"),
            Err(payload) => {
                println!(
                    "{input}: panicked: {}",
                    run::panic_message(payload.as_ref())
                );
                failed = true;
            }
        }
        let rest = inputs.len().saturating_sub(at).saturating_sub(1);
        if let Some((path, failing)) = oracle.as_mut()
            && oracle_failed
            && rest > 0
        {
            match start_fuzz_oracle(path) {
                Ok(fresh) => {
                    *failing = fresh;
                    println!("sigsoak: the oracle failed on {input}; a fresh one answers the rest");
                }
                Err(why) => {
                    let unchecked = if rest == 1 {
                        "the input after it was".to_owned()
                    } else {
                        format!("the {rest} inputs after it were")
                    };
                    println!(
                        "sigsoak: the oracle failed on {input} and did not start again: {why}; \
                         {unchecked} not checked"
                    );
                    break;
                }
            }
        }
    }
    Ok(if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
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
    let report = run::replay(seed, class, index, args.get("canary"), &oracle).map_err(config)?;
    println!(
        "class {} case {} under master seed {seed:#018x}",
        report.class, report.index
    );
    println!("case seed {:#018x}", report.case_seed);
    println!("variant {}", report.case.variant);
    if let Some(canary) = &report.canary {
        println!(
            "canary {} answers in dcroxide's place on {}",
            canary.name,
            command_names(canary.commands)
        );
    }
    for (j, request) in report.case.requests.iter().enumerate() {
        let lines = RequestLines {
            j,
            request,
            intent: &report.case.intents[j],
            checked: None,
            ours_label: match &report.canary {
                Some(canary) if canary.covers(request.cmd) => canary.name,
                _ => "ours",
            },
            ours: report.ours.get(j),
            theirs_label: "oracle",
            theirs: report.replies.get(j),
            model: report.model.per_request.get(j).copied().flatten(),
        };
        println!("{lines}");
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
        println!("  {}", failure_line(failure));
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

/// Commands' names, comma-separated.
fn command_names(commands: &[Cmd]) -> String {
    commands
        .iter()
        .map(|c| c.name())
        .collect::<Vec<_>>()
        .join(",")
}

/// `list`: every class, or every canary.  A reader that goes away early
/// (`sigsoak list | head`) ends the listing quietly.
fn cmd_list(args: &Args) -> Outcome {
    let mut out = io::stdout().lock();
    let written = if args.flag("canaries")? {
        list_canaries(&mut out)
    } else {
        list_classes(&mut out)
    };
    match written {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(ExitCode::SUCCESS),
        Err(e) => Err(config(format!("cannot write the list: {e}"))),
    }
}

fn list_classes(out: &mut impl Write) -> io::Result<()> {
    for class in CLASSES {
        let size = match class.size {
            dcroxide_sigdiff::class::Size::Sampled { floor } => format!("sampled, floor {floor}"),
            dcroxide_sigdiff::class::Size::Stratified { strata, floor } => {
                format!("{strata} strata, floor {floor}")
            }
            dcroxide_sigdiff::class::Size::Finite { size } => format!("finite, {size}"),
        };
        writeln!(
            out,
            "{}\t{}\t{:?}\t{size}\tper-PR {}\t{}\n    {}",
            class.name,
            class.family.name(),
            class.tier,
            class.pr_cases,
            command_names(class.commands),
            class.doc
        )?;
    }
    out.flush()
}

fn list_canaries(out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "-\t{}\tmodel\t{}\n    every model with no break; must agree with dcrd on every \
         class of the selected model canaries' commands",
        MODEL_BASELINE.name,
        command_names(MODEL_BASELINE.commands)
    )?;
    for canary in CANARIES {
        let footprint = if canary.footprint.is_empty() {
            "none".to_owned()
        } else {
            canary.footprint.join(",")
        };
        writeln!(
            out,
            "{}\t{}\t{}\t{}\tprimary {}\tfootprint {footprint}\n    {}",
            canary.id,
            canary.name,
            canary.kind(),
            command_names(canary.commands),
            canary.primary,
            canary.doc
        )?;
    }
    out.flush()
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
        "canary" => Args::parse(rest, CANARY_FLAGS, false).and_then(|a| cmd_canary(&a, &raw)),
        "replay" => Args::parse(rest, &["seed", "class", "case", "canary", "oracle"], false)
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
        "list" => Args::parse(rest, &["canaries"], false).and_then(|a| cmd_list(&a)),
        "emit-corpus" => Args::parse(rest, EMIT_FLAGS, false).and_then(|a| cmd_emit_corpus(&a)),
        "fuzz-seeds" => Args::parse(rest, FUZZ_SEEDS_FLAGS, false).and_then(|a| cmd_fuzz_seeds(&a)),
        "fuzz-replay" => {
            Args::parse(rest, FUZZ_REPLAY_FLAGS, true).and_then(|a| cmd_fuzz_replay(&a))
        }
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
