// SPDX-License-Identifier: ISC
//! The pipe and the run loop against a fake oracle, with no Go: this test
//! binary re-executes itself as a child that serves `tools/oracle`'s
//! protocol by the oracle's own rules (ids echoed, a 1 MiB output buffer
//! flushed only when no complete request is buffered or the buffer fills,
//! a flush before a panic's exit and none before a fatal one), and fails on
//! command: it panics, dies, hangs, fails once, lies or breaks the protocol
//! on the request whose data encodes a chosen number.
//!
//! The trigger is a number carried in the request data rather than a
//! request id, because ids restart at 0 on every new oracle, so an id
//! cannot name the same case on the respawned and isolation oracles.
//!
//! libtest writes its own lines to stdout, which would break the protocol,
//! so this test brings its own `main` (`harness = false` in Cargo.toml).
//! It runs the tests below on parallel threads, as libtest would, and
//! honours the libtest options a workspace run may pass on ([`Options`]).

use std::borrow::Cow;
use std::ffi::OsString;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use dcroxide_sigdiff::answer::{Answer, Kind};
use dcroxide_sigdiff::arith::add_be;
use dcroxide_sigdiff::class::{
    Case, ClassSpec, Consistency, Family, Intent, Size, Tags, Tier, generate,
};
use dcroxide_sigdiff::cmd::{self, Cmd, Request};
use dcroxide_sigdiff::compare::{Category, Status};
use dcroxide_sigdiff::digest::leaf;
use dcroxide_sigdiff::entropy::Entropy;
use dcroxide_sigdiff::manifest::{ORACLE_GO_MOD, SIGNATURE_MODULES, go_mod_version};
use dcroxide_sigdiff::pipe::{OraclePipe, Payload, PipeConfig, PipeFailure};
use dcroxide_sigdiff::run::{Mode, RunConfig, RunStatus, Summary, run};
use dcroxide_testutil::{SplitMix64, TempDir, unhex};

/// The first argument that makes this binary the fake oracle.
const FAKE: &str = "--fake-oracle";

/// The first argument that makes this binary a run whose producer never
/// finishes building a case, which the monitor must end with exit code 3.
const BUILD_HANGS: &str = "--build-hangs";

/// The text the fake answers every `ecdsa_parse_der` with: dcrd's kind for
/// any input shorter than 8 bytes, which every case here is.
const TOO_SHORT: &str = "malformed signature: too short";

type Test = (&'static str, fn());

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some(FAKE) {
        fake::serve(&args[2..]);
        return;
    }
    if args.get(1).map(String::as_str) == Some(BUILD_HANGS) {
        let out = PathBuf::from(args.get(2).expect("an output directory"));
        let mut cfg = RunConfig::new(SEED, vec![&T_SLOW], Mode::Cases(10), me());
        cfg.oracle_args = vec![FAKE.into(), "echo".into()];
        cfg.workers = 1;
        cfg.hang_timeout = Duration::from_secs(1);
        cfg.out = Some(out);
        let _ = run(&cfg);
        // The monitor ends the process before the run can return.
        std::process::exit(0);
    }
    let tests: &[Test] = &[
        ("stress_without_deadlock", stress_without_deadlock),
        (
            "every_payload_comes_back_once",
            every_payload_comes_back_once,
        ),
        (
            "a_panic_in_on_case_reaches_the_producer",
            a_panic_in_on_case_reaches_the_producer,
        ),
        ("spawn_failures", spawn_failures),
        ("a_go_panic_names_its_case", a_go_panic_names_its_case),
        ("a_fatal_exit_is_isolated", a_fatal_exit_is_isolated),
        (
            "a_hang_is_killed_and_isolated",
            a_hang_is_killed_and_isolated,
        ),
        (
            "a_hang_behind_a_full_writer_is_killed",
            a_hang_behind_a_full_writer_is_killed,
        ),
        (
            "a_fault_that_does_not_recur_is_an_event",
            a_fault_that_does_not_recur_is_an_event,
        ),
        (
            "a_wrong_id_is_a_protocol_fault",
            a_wrong_id_is_a_protocol_fault,
        ),
        ("four_faults_abort_the_worker", four_faults_abort_the_worker),
        (
            "a_hang_while_building_a_case_ends_the_run",
            a_hang_while_building_a_case_ends_the_run,
        ),
        (
            "a_panic_in_dcroxide_is_recorded",
            a_panic_in_dcroxide_is_recorded,
        ),
        (
            "results_do_not_depend_on_workers",
            results_do_not_depend_on_workers,
        ),
        (
            "a_deadline_and_a_stop_leave_a_prefix",
            a_deadline_and_a_stop_leave_a_prefix,
        ),
        (
            "the_harness_reads_libtest_options",
            the_harness_reads_libtest_options,
        ),
    ];
    let options = Options::parse(&args[1..]);
    let selected: Vec<&Test> = tests
        .iter()
        .filter(|(name, _)| options.selects(name))
        .collect();
    if options.list {
        for (name, _) in &selected {
            println!("{name}: test");
        }
        return;
    }
    let started = Instant::now();
    let threads = options
        .threads
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, usize::from))
        .clamp(1, selected.len().max(1));
    println!(
        "\nrunning {} test{}",
        selected.len(),
        if selected.len() == 1 { "" } else { "s" }
    );
    let next = AtomicUsize::new(0);
    let failed = Mutex::new(Vec::new());
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| {
                while let Some(&&(name, test)) = selected.get(next.fetch_add(1, Ordering::SeqCst)) {
                    if std::panic::catch_unwind(test).is_ok() {
                        println!("test {name} ... ok");
                    } else {
                        println!("test {name} ... FAILED");
                        failed
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .push(name);
                    }
                }
            });
        }
    });
    let failed = failed.into_inner().unwrap_or_else(PoisonError::into_inner);
    println!(
        "\ntest result: {}. {} passed; {} failed; 0 ignored; 0 measured; {} filtered out; \
         finished in {:.2}s",
        if failed.is_empty() { "ok" } else { "FAILED" },
        selected.len().saturating_sub(failed.len()),
        failed.len(),
        tests.len().saturating_sub(selected.len()),
        started.elapsed().as_secs_f64()
    );
    if !failed.is_empty() {
        println!("failures: {}", failed.join(", "));
        std::process::exit(101);
    }
}

/// The libtest options this harness honours: name filters, matched as
/// substrings or, with `--exact`, whole; `--skip`, matched the same way;
/// `--ignored`, which selects nothing, since no test here is ignored;
/// `--list`; and `--test-threads` (or `RUST_TEST_THREADS`).  Every other
/// flag is accepted and has no effect, the value of one that takes a value
/// included, so a value is never read as a filter.
#[derive(Debug, Default)]
struct Options {
    filters: Vec<String>,
    skips: Vec<String>,
    exact: bool,
    ignored_only: bool,
    list: bool,
    threads: Option<usize>,
}

impl Options {
    /// libtest's flags that take a value.
    const TAKE_VALUES: [&'static str; 7] = [
        "--color",
        "--format",
        "--logfile",
        "--shuffle-seed",
        "--skip",
        "--test-threads",
        "-Z",
    ];

    fn parse(args: &[String]) -> Options {
        let mut options = Options {
            threads: std::env::var("RUST_TEST_THREADS")
                .ok()
                .and_then(|v| v.parse().ok()),
            ..Options::default()
        };
        let mut it = args.iter();
        while let Some(arg) = it.next() {
            let (flag, inline) = match arg.split_once('=') {
                Some((flag, value)) if flag.starts_with('-') => (flag, Some(value.to_owned())),
                _ => (arg.as_str(), None),
            };
            let value = if Self::TAKE_VALUES.contains(&flag) {
                inline.or_else(|| it.next().cloned())
            } else {
                None
            };
            match flag {
                "--skip" => options.skips.extend(value),
                "--test-threads" => {
                    options.threads = value.and_then(|v| v.parse().ok()).or(options.threads);
                }
                "--exact" => options.exact = true,
                "--ignored" => options.ignored_only = true,
                "--list" => options.list = true,
                _ if flag.starts_with('-') => {}
                _ => options.filters.push(arg.clone()),
            }
        }
        options
    }

    fn selects(&self, name: &str) -> bool {
        let matches = |pattern: &String| {
            if self.exact {
                name == pattern
            } else {
                name.contains(pattern.as_str())
            }
        };
        !self.ignored_only
            && (self.filters.is_empty() || self.filters.iter().any(matches))
            && !self.skips.iter().any(matches)
    }
}

/// The fake oracle.
mod fake {
    use super::*;
    use std::io::Read as _;

    /// What the fake does on its trigger.
    enum Action {
        Echo,
        Panic(Vec<u64>),
        Fatal(Vec<u64>),
        Hang(Vec<u64>),
        FailOnce(u64, PathBuf),
        WrongId(u64),
        Lie(u64),
        Silent,
    }

    fn numbers(list: &str) -> Vec<u64> {
        list.split(',')
            .map(|n| n.parse().expect("a number"))
            .collect()
    }

    fn action(args: &[String]) -> Action {
        let mode = args.first().map_or("echo", String::as_str);
        let (name, value) = mode.split_once('=').unwrap_or((mode, ""));
        match name {
            "echo" => Action::Echo,
            "panic-at" => Action::Panic(numbers(value)),
            "fatal-at" => Action::Fatal(numbers(value)),
            "hang-at" => Action::Hang(numbers(value)),
            "fail-once-at" => Action::FailOnce(
                value.parse().expect("a number"),
                PathBuf::from(args.get(1).expect("a marker path")),
            ),
            "wrong-id" => Action::WrongId(value.parse().expect("a number")),
            "lie-at" => Action::Lie(value.parse().expect("a number")),
            "silent" => Action::Silent,
            other => panic!("unknown fake oracle mode {other}"),
        }
    }

    /// Serves until stdin ends, flushing as the oracle does: whenever no
    /// complete request is buffered, and when the buffer fills.
    pub(super) fn serve(args: &[String]) {
        let action = action(args);
        let mut input = BufReader::with_capacity(1 << 20, std::io::stdin().lock());
        let mut out = BufWriter::with_capacity(1 << 20, std::io::stdout().lock());
        if let Action::Silent = action {
            // Never answers, not even build_info; waits to be killed.
            let mut sink = Vec::new();
            let _ = input.read_to_end(&mut sink);
            loop {
                std::thread::sleep(Duration::from_secs(60));
            }
        }
        let mut line = String::new();
        loop {
            if !out.buffer().is_empty() && !input.buffer().contains(&b'\n') {
                out.flush().expect("flush");
            }
            line.clear();
            match input.read_line(&mut line) {
                Ok(0) | Err(_) => {
                    let _ = out.flush();
                    return;
                }
                Ok(_) => {}
            }
            let request: serde_json::Value = serde_json::from_str(&line).expect("a request");
            let id = request.get("id").and_then(serde_json::Value::as_u64);
            let cmd = request["cmd"].as_str().expect("cmd");
            if cmd == "build_info" {
                let modules: serde_json::Map<String, serde_json::Value> = SIGNATURE_MODULES
                    .iter()
                    .map(|m| {
                        let v = go_mod_version(ORACLE_GO_MOD, m).expect("required");
                        ((*m).to_owned(), serde_json::Value::from(v))
                    })
                    .collect();
                let reply = serde_json::json!({ "go_version": "go-fake", "modules": modules });
                writeln!(out, "{reply}").expect("write");
                continue;
            }
            let data = unhex(request.get("data").and_then(|d| d.as_str()).unwrap_or(""));
            let n = number(&data);
            let mut id_out = id;
            let mut kind = "ErrSigTooShort";
            match &action {
                Action::Panic(at) if at.contains(&n) => {
                    let _ = out.flush();
                    eprintln!("panic: the fake oracle panics on {n}\n\ngoroutine 1 [running]:");
                    std::process::exit(2);
                }
                Action::Fatal(at) if at.contains(&n) => {
                    eprintln!("fatal error: the fake oracle dies on {n}");
                    std::process::exit(2);
                }
                Action::Hang(at) if at.contains(&n) => loop {
                    std::thread::sleep(Duration::from_secs(60));
                },
                Action::FailOnce(at, marker) if *at == n && !marker.exists() => {
                    std::fs::write(marker, b"failed once").expect("write the marker");
                    eprintln!("fatal error: the fake oracle fails once on {n}");
                    std::process::exit(2);
                }
                Action::WrongId(at) if *at == n => id_out = id.map(|i| i.wrapping_add(1)),
                Action::Lie(at) if *at == n => kind = "ErrSigTooLong",
                _ => {}
            }
            let mut reply = match cmd {
                "ecdsa_parse_der" => serde_json::json!({ "error": TOO_SHORT, "kind": kind }),
                other => {
                    serde_json::json!({ "error": format!("{other}: the fake answers nothing else") })
                }
            };
            if let Some(id) = id_out {
                reply["id"] = serde_json::Value::from(id);
            }
            writeln!(out, "{reply}").expect("write");
        }
    }
}

fn me() -> PathBuf {
    std::env::current_exe().expect("this test binary")
}

fn fake_config(mode: &[&str]) -> PipeConfig {
    let mut args: Vec<OsString> = vec![FAKE.into()];
    args.extend(mode.iter().map(OsString::from));
    PipeConfig {
        args,
        ..PipeConfig::new(me())
    }
}

/// Runs `f` on a thread and ends the process if it takes longer than
/// `limit`: a deadlock fails the test instead of hanging it.
fn within<T: Send + 'static>(
    limit: Duration,
    what: &str,
    f: impl FnOnce() -> T + Send + 'static,
) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)));
    });
    match rx.recv_timeout(limit) {
        Ok(Ok(value)) => value,
        Ok(Err(panic)) => std::panic::resume_unwind(panic),
        Err(_) => {
            eprintln!("{what} did not finish within {limit:?}: a deadlock");
            std::process::exit(1);
        }
    }
}

/// A pipe test's payload: a sequence number and its requests.
struct Numbered(u64, Vec<Request>);

impl Payload for Numbered {
    fn requests(&self) -> &[Request] {
        &self.1
    }
}

/// The seven low big-endian bytes of `n`: an input shorter than 8 bytes,
/// which every DER parser rejects as too short, carrying the number the
/// fake's triggers match.
fn tag(n: u64) -> Vec<u8> {
    n.to_be_bytes()[1..].to_vec()
}

/// Cases of one to four requests, `requests` requests in all, request `k`
/// carrying tag `k`.
fn numbered_cases(requests: u64, seed: u64) -> Vec<Numbered> {
    let mut rng = SplitMix64(seed);
    let mut cases = Vec::new();
    let mut sent = 0u64;
    while sent < requests {
        let n = rng
            .below(4)
            .saturating_add(1)
            .min(requests.saturating_sub(sent));
        let reqs = (sent..sent.saturating_add(n))
            .map(|k| cmd::ecdsa_parse_der(&tag(k)))
            .collect();
        cases.push(Numbered(u64::try_from(cases.len()).expect("small"), reqs));
        sent = sent.saturating_add(n);
    }
    cases
}

/// 100,000 requests through window 4 and flush batch 1, window 512 and
/// flush batch 64, and serial mode, and 20,000 through window 1 with a
/// flush batch far larger than the window holds, so only the flush before
/// a blocking send delivers them, each within 60 s: no deadlock, every case
/// answered in order.
fn stress_without_deadlock() {
    for (window, flush_every, requests) in [
        (4, 1, 100_000),
        (512, 64, 100_000),
        (0, 1, 100_000),
        (1, 1_000, 20_000),
    ] {
        within(Duration::from_secs(60), "the stress run", move || {
            let cases = numbered_cases(requests, 7);
            let total = cases.len();
            let seen = Arc::new(Mutex::new(Vec::with_capacity(total)));
            let sink = Arc::clone(&seen);
            let cfg = PipeConfig {
                window,
                flush_every,
                ..fake_config(&["echo"])
            };
            let mut pipe = OraclePipe::spawn(&cfg, move |p: Numbered, replies| {
                assert_eq!(replies.len(), p.1.len());
                sink.lock().expect("lock").push(p.0);
            })
            .unwrap_or_else(|_| panic!("spawn"));
            assert_eq!(pipe.build_info().go_version.as_deref(), Some("go-fake"));
            for case in cases {
                assert!(pipe.submit(case).is_ok(), "window {window}");
            }
            assert!(pipe.finish().is_ok());
            let seen = seen.lock().expect("lock");
            assert_eq!(seen.len(), total);
            assert!(
                seen.iter()
                    .enumerate()
                    .all(|(i, &n)| u64::try_from(i).expect("small") == n)
            );
        });
    }
}

/// Whatever the fault, every payload comes back exactly once: answered in
/// order through `on_case`, or in the failure after the answered ones.
fn every_payload_comes_back_once() {
    for (mode, window) in [
        ("fatal-at=700", 512),
        ("panic-at=700", 512),
        ("wrong-id=700", 64),
        ("fatal-at=700", 0),
        ("fatal-at=0", 8),
    ] {
        within(Duration::from_secs(60), mode, move || {
            let cases = numbered_cases(2_000, 11);
            let total = cases.len();
            let seen = Arc::new(Mutex::new(Vec::new()));
            let sink = Arc::clone(&seen);
            let cfg = PipeConfig {
                window,
                flush_every: if window == 0 { 1 } else { 16 },
                ..fake_config(&[mode])
            };
            let mut pipe = OraclePipe::spawn(&cfg, move |p: Numbered, _| {
                sink.lock().expect("lock").push(p.0);
            })
            .unwrap_or_else(|_| panic!("spawn"));
            let mut cases = cases.into_iter();
            let mut failure = None;
            for case in cases.by_ref() {
                if let Err(f) = pipe.submit(case) {
                    failure = Some(f);
                    break;
                }
            }
            let failure = match failure {
                Some(f) => f,
                None => pipe.finish().expect_err("the oracle fails"),
            };
            let PipeFailure::Oracle { fault, unanswered } = failure else {
                panic!("{mode}: not an oracle fault");
            };
            let mut all: Vec<u64> = seen.lock().expect("lock").clone();
            all.extend(unanswered.iter().map(|p| p.0));
            all.extend(cases.map(|p| p.0));
            assert_eq!(
                all,
                (0..u64::try_from(total).expect("small")).collect::<Vec<_>>(),
                "{mode} ({fault}): each payload once, in order"
            );
            assert!(!unanswered.is_empty(), "{mode}");
            let expect_kind = if mode.starts_with("wrong-id") {
                "protocol"
            } else {
                "exited"
            };
            assert_eq!(fault.kind_name(), expect_kind, "{mode}: {fault}");
        });
    }
}

/// A panic in `on_case` ends the checker, kills the oracle and reaches
/// the producer, which neither waits for ever nor loses the panic.
fn a_panic_in_on_case_reaches_the_producer() {
    within(Duration::from_secs(60), "the on_case panic", || {
        let cfg = PipeConfig {
            window: 4,
            flush_every: 1,
            ..fake_config(&["echo"])
        };
        let mut pipe = OraclePipe::spawn(&cfg, |p: Numbered, _| {
            assert!(p.0 != 50, "on_case gives up on 50");
        })
        .unwrap_or_else(|_| panic!("spawn"));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            for case in numbered_cases(10_000, 3) {
                if pipe.submit(case).is_err() {
                    return;
                }
            }
            let _ = pipe.finish();
        }));
        let panic = result.expect_err("the checker's panic reaches the producer");
        let message = panic
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| panic.downcast_ref::<&str>().map(|s| (*s).to_owned()))
            .unwrap_or_default();
        assert!(message.contains("on_case gives up on 50"), "{message}");
    });
}

/// A binary that does not start, and an oracle that never answers
/// `build_info`, are spawn failures.
fn spawn_failures() {
    let dir = TempDir::new("sigdiff-spawn");
    let cfg = PipeConfig::new(dir.path().join("no-such-oracle"));
    assert!(matches!(
        OraclePipe::<Numbered>::spawn(&cfg, |_, _| {}),
        Err(PipeFailure::Spawn(_))
    ));
    within(Duration::from_secs(60), "the silent oracle", || {
        let cfg = PipeConfig {
            spawn_timeout: Duration::from_secs(1),
            ..fake_config(&["silent"])
        };
        match OraclePipe::<Numbered>::spawn(&cfg, |_, _| {}) {
            Err(PipeFailure::Spawn(e)) => assert_eq!(e.kind(), std::io::ErrorKind::TimedOut),
            _ => panic!("a silent oracle is a spawn failure"),
        }
    });
}

/// The run-level tests' class: case `i` asks `ecdsa_parse_der` of the
/// seven-byte tag `i`, which both sides reject as too short.
static T_FAKE: ClassSpec = ClassSpec {
    name: "T-fake",
    family: Family::Der,
    commands: &[Cmd::EcdsaParseDer],
    size: Size::Sampled { floor: 10_000_000 },
    tier: Tier::A,
    generator: gen_fake,
    mix: &[],
    pr_cases: 48,
    doc: "the fake oracle's class",
};

fn gen_fake(_: &mut dyn Entropy, index: u64) -> Case {
    Case {
        variant: Cow::Borrowed("fake"),
        requests: vec![cmd::ecdsa_parse_der(&tag(index))],
        intents: vec![Intent::RejectKind("ErrSigTooShort")],
        consistency: Consistency::None,
        tags: Tags::NONE,
    }
}

/// Like [`T_FAKE`], with every tenth case a request dcroxide's adapter
/// cannot decode, so it panics there.
static T_PANICS: ClassSpec = ClassSpec {
    name: "T-panics",
    family: Family::Der,
    commands: &[Cmd::EcdsaParseDer, Cmd::EcdsaVerifyRaw],
    size: Size::Sampled { floor: 10_000_000 },
    tier: Tier::A,
    generator: gen_panics,
    mix: &[],
    pr_cases: 48,
    doc: "a class whose every tenth case panics in the adapter",
};

fn gen_panics(e: &mut dyn Entropy, index: u64) -> Case {
    if index.is_multiple_of(10) {
        Case {
            variant: Cow::Borrowed("panics"),
            requests: vec![Request {
                cmd: Cmd::EcdsaVerifyRaw,
                data: vec![0xff],
            }],
            intents: vec![Intent::Any],
            consistency: Consistency::None,
            tags: Tags::NONE,
        }
    } else {
        gen_fake(e, index)
    }
}

/// Like [`T_FAKE`], with each case's seven bytes drawn from its entropy
/// rather than taken from its index, so every leaf depends on the case
/// seed: a seed that took anything but (master, class, index), the worker
/// for one, would change them.
static T_DRAWN: ClassSpec = ClassSpec {
    name: "T-drawn",
    family: Family::Der,
    commands: &[Cmd::EcdsaParseDer],
    size: Size::Sampled { floor: 10_000_000 },
    tier: Tier::A,
    generator: gen_drawn,
    mix: &[],
    pr_cases: 48,
    doc: "seven bytes drawn from the case seed",
};

fn gen_drawn(e: &mut dyn Entropy, _: u64) -> Case {
    Case {
        variant: Cow::Borrowed("drawn"),
        requests: vec![cmd::ecdsa_parse_der(&e.next_u64().to_be_bytes()[1..])],
        intents: vec![Intent::RejectKind("ErrSigTooShort")],
        consistency: Consistency::None,
        tags: Tags::NONE,
    }
}

/// The number the fake reads from a request's data, as its triggers match
/// it.
fn number(data: &[u8]) -> u64 {
    data.iter()
        .fold(0u64, |acc, &b| acc.wrapping_shl(8) | u64::from(b))
}

/// A class whose case 3 never finishes building on the producer's side:
/// its generator does not return.
static T_SLOW: ClassSpec = ClassSpec {
    name: "T-slow",
    family: Family::Der,
    commands: &[Cmd::EcdsaParseDer],
    size: Size::Sampled { floor: 10_000_000 },
    tier: Tier::A,
    generator: gen_slow,
    mix: &[],
    pr_cases: 48,
    doc: "a class whose case 3 never finishes building",
};

fn gen_slow(e: &mut dyn Entropy, index: u64) -> Case {
    if index == 3 {
        std::thread::sleep(Duration::from_secs(3_600));
    }
    gen_fake(e, index)
}

const SEED: u64 = 0x5eed_5eed;

/// A run of `cases` cases of `class` against the fake in `mode`, with a
/// hang timeout of 2 s.
fn fake_run_config(
    class: &'static ClassSpec,
    mode: &[&str],
    cases: u64,
    workers: usize,
    out: &Path,
) -> RunConfig {
    let mut cfg = RunConfig::new(SEED, vec![class], Mode::Cases(cases), me());
    cfg.oracle_args = std::iter::once(FAKE)
        .chain(mode.iter().copied())
        .map(OsString::from)
        .collect();
    cfg.workers = workers;
    cfg.hang_timeout = Duration::from_secs(2);
    cfg.out = Some(out.to_path_buf());
    cfg
}

fn fake_run(
    class: &'static ClassSpec,
    mode: &[&str],
    cases: u64,
    workers: usize,
    out: &Path,
) -> Summary {
    run(&fake_run_config(class, mode, cases, workers, out)).expect("the run starts")
}

/// The answer the fake gives every case.
fn too_short() -> Answer {
    Answer::Reject {
        kind: Kind::Dcrd("ErrSigTooShort".to_owned()),
        text: Some(TOO_SHORT.to_owned()),
    }
}

fn leaf_of(class: &ClassSpec, index: u64, theirs: Option<Answer>, status: Status) -> [u8; 32] {
    let case = generate(class, SEED, index);
    leaf(class.name, index, &case.requests, &[theirs], status)
}

/// The leaf sum of a run of `n` cases in which every case agrees but those
/// in `changed`, which have the given answer and status instead.
fn expected_sum(class: &ClassSpec, n: u64, changed: &[(u64, Option<Answer>, Status)]) -> [u8; 32] {
    (0..n).fold([0u8; 32], |acc, i| {
        let leaf = match changed.iter().find(|(k, _, _)| *k == i) {
            Some((_, theirs, status)) => leaf_of(class, i, theirs.clone(), *status),
            None => leaf_of(class, i, Some(too_short()), Status::Agree),
        };
        add_be(&acc, &leaf).0
    })
}

/// Checks a run with one oracle culprit, case 150 of 300: every case
/// completed exactly once (the leaf sum is the expected one), and one
/// disagreement of `category`, recorded with the culprit.
fn assert_one_culprit(
    summary: &Summary,
    category: Category,
    reproduced: Option<bool>,
    go_panic: Option<bool>,
) {
    assert_culprit_of(summary, 300, 150, category, reproduced, go_panic);
}

/// [`assert_one_culprit`] for case `culprit` of `cases`.
fn assert_culprit_of(
    summary: &Summary,
    cases: u64,
    culprit: u64,
    category: Category,
    reproduced: Option<bool>,
    go_panic: Option<bool>,
) {
    let class = &summary.classes[0];
    assert_eq!(
        summary.status,
        RunStatus::Failed,
        "{:?}",
        summary.problems()
    );
    assert_eq!(class.completed, cases);
    assert_eq!(class.statuses, [cases.saturating_sub(1), 0, 1, 0]);
    assert_eq!(
        class.digest.total(),
        expected_sum(&T_FAKE, cases, &[(culprit, None, Status::OracleFailure)]),
        "every case completed exactly once"
    );
    assert_eq!(summary.disagreements, 1);
    let note = &summary.notes[0];
    assert_eq!((note.index, note.category), (culprit, category), "{note:?}");
    assert_eq!(note.reproduced, reproduced);
    assert_eq!(note.go_panic, go_panic);
}

fn events(summary: &Summary, kind: &str) -> Vec<serde_json::Value> {
    summary
        .events
        .iter()
        .filter(|e| e["event"] == kind)
        .cloned()
        .collect()
}

/// A Go panic flushes the answers ahead of it, so the first unanswered
/// case is the culprit, with no isolation; the rest complete on a fresh
/// oracle.
fn a_go_panic_names_its_case() {
    let dir = TempDir::new("sigdiff-fake-panic");
    let out = dir.path().join("run");
    let summary = within(Duration::from_secs(60), "the panic run", {
        let out = out.clone();
        move || fake_run(&T_FAKE, &["panic-at=150"], 300, 1, &out)
    });
    assert_one_culprit(&summary, Category::OracleCrashed, None, Some(true));
    let faults = events(&summary, "oracle-fault");
    assert_eq!(faults.len(), 1, "{:?}", summary.events);
    assert_eq!(faults[0]["culprit"]["how"], "go-panic");
    assert_eq!(faults[0]["culprit"]["index"], 150);
    let stderr = std::fs::read_to_string(out.join("oracle-w0.stderr")).expect("stderr");
    assert!(
        stderr.contains("panic: the fake oracle panics on 150"),
        "{stderr}"
    );
    let records = std::fs::read_to_string(out.join("disagreements.jsonl")).expect("records");
    let record: serde_json::Value =
        serde_json::from_str(records.lines().next().expect("one")).expect("JSON");
    assert_eq!(record["category"], "oracle-crashed");
    assert_eq!(record["go_panic"], true);
    assert!(
        record["replay"]
            .as_str()
            .expect("replay")
            .contains("--class T-fake --case 150")
    );
}

/// A fatal exit loses the answers the oracle held, so the worker isolates:
/// the cases ahead of the culprit complete in serial mode, and the culprit
/// fails again alone.
fn a_fatal_exit_is_isolated() {
    let dir = TempDir::new("sigdiff-fake-fatal");
    let summary = within(Duration::from_secs(60), "the fatal run", {
        let out = dir.path().to_path_buf();
        move || fake_run(&T_FAKE, &["fatal-at=150"], 300, 1, &out)
    });
    assert_one_culprit(&summary, Category::OracleCrashed, Some(true), Some(false));
    let faults = events(&summary, "oracle-fault");
    assert_eq!(faults[0]["culprit"]["how"], "isolation");
    let first = faults[0]["unanswered"][0]["first"]
        .as_u64()
        .expect("a range");
    assert!(
        first < 150,
        "answers held back by the oracle were lost: {first}"
    );
}

/// A hung oracle is killed after the hang timeout and isolated the same
/// way.
fn a_hang_is_killed_and_isolated() {
    let dir = TempDir::new("sigdiff-fake-hang");
    let summary = within(Duration::from_secs(60), "the hang run", {
        let out = dir.path().to_path_buf();
        move || {
            let mut cfg = fake_run_config(&T_FAKE, &["hang-at=150"], 300, 1, &out);
            cfg.hang_timeout = Duration::from_secs(1);
            run(&cfg).expect("the run starts")
        }
    });
    assert_one_culprit(&summary, Category::OracleHung, Some(true), None);
}

/// An oracle that hangs while the producer streams a batch far larger than
/// its writer is still seen to owe answers: the writer never writes out by
/// itself, and every flush counts its requests before it blocks, so the
/// monitor kills the oracle instead of the run waiting for ever.  The
/// requests after the hung one fill the stdin pipe and the writer before
/// any batch ends, so no explicit flush follows the hang.
fn a_hang_behind_a_full_writer_is_killed() {
    let dir = TempDir::new("sigdiff-fake-spill");
    let summary = within(Duration::from_secs(60), "the full-writer hang run", {
        let out = dir.path().to_path_buf();
        move || {
            let mut cfg = fake_run_config(&T_FAKE, &["hang-at=3000"], 10_000, 1, &out);
            cfg.window = 16_384;
            cfg.flush_every = 16_384;
            cfg.hang_timeout = Duration::from_secs(1);
            run(&cfg).expect("the run starts")
        }
    });
    assert_culprit_of(
        &summary,
        10_000,
        3_000,
        Category::OracleHung,
        Some(true),
        None,
    );
}

/// A fault no case reproduces completes every case and leaves an event,
/// not a disagreement: the digest is a clean run's.
fn a_fault_that_does_not_recur_is_an_event() {
    let dir = TempDir::new("sigdiff-fake-once");
    let marker = dir.path().join("marker");
    let summary = within(Duration::from_secs(60), "the fail-once run", {
        let out = dir.path().join("run");
        let marker = marker.display().to_string();
        move || fake_run(&T_FAKE, &["fail-once-at=150", &marker], 300, 1, &out)
    });
    assert!(marker.exists(), "the first oracle failed");
    assert_eq!(
        summary.status,
        RunStatus::Passed,
        "{:?}",
        summary.problems()
    );
    assert_eq!(summary.disagreements, 0);
    assert_eq!(summary.faults_not_reproduced, 1);
    assert_eq!(events(&summary, "oracle-fault-not-reproduced").len(), 1);
    assert_eq!(
        summary.classes[0].digest.total(),
        expected_sum(&T_FAKE, 300, &[])
    );
}

/// A reply with the wrong id is a protocol fault, isolated to its case.
fn a_wrong_id_is_a_protocol_fault() {
    let dir = TempDir::new("sigdiff-fake-id");
    let summary = within(Duration::from_secs(60), "the wrong-id run", {
        let out = dir.path().to_path_buf();
        move || fake_run(&T_FAKE, &["wrong-id=150"], 300, 1, &out)
    });
    assert_one_culprit(&summary, Category::Protocol, Some(true), None);
}

/// A worker handles three faults; a fourth stops it and aborts the run.
fn four_faults_abort_the_worker() {
    let dir = TempDir::new("sigdiff-fake-four");
    let summary = within(Duration::from_secs(60), "the four-fault run", {
        let out = dir.path().to_path_buf();
        move || fake_run(&T_FAKE, &["fatal-at=50,100,150,200"], 300, 1, &out)
    });
    assert_eq!(summary.status, RunStatus::Aborted);
    assert!(
        summary
            .abort_reason
            .as_deref()
            .is_some_and(|r| r.contains("4 oracle faults")),
        "{:?}",
        summary.abort_reason
    );
    assert_eq!(summary.oracle_faults, 4);
    let culprits: Vec<u64> = summary.notes.iter().map(|n| n.index).collect();
    assert_eq!(culprits, [50, 100, 150]);
    assert_eq!(events(&summary, "worker-aborted").len(), 1);
    let text = std::fs::read_to_string(dir.path().join("summary.txt")).expect("summary");
    assert!(text.starts_with("status: aborted"), "{text}");
}

/// A case whose generator does not return within the hang timeout cannot
/// be stopped from outside: the monitor records it, writes the summary as
/// aborted and ends the process with exit code 3.  (A case dcroxide does
/// not finish takes the same path; `run`'s unit tests check its record.)
fn a_hang_while_building_a_case_ends_the_run() {
    let dir = TempDir::new("sigdiff-build-hangs");
    let out = dir.path().join("run");
    let mut child = std::process::Command::new(me())
        .arg(BUILD_HANGS)
        .arg(&out)
        .spawn()
        .expect("run the child");
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(60))
        .expect("a deadline");
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll the child") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the monitor did not end a run whose case never finished building");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(status.code(), Some(3), "{status}");
    let records = std::fs::read_to_string(out.join("disagreements.jsonl")).expect("records");
    let record: serde_json::Value =
        serde_json::from_str(records.lines().next().expect("one")).expect("JSON");
    assert_eq!(record["category"], "ours-hung");
    assert_eq!(record["index"], 3);
    assert_eq!(record["variant"], "generator-hung");
    let text = std::fs::read_to_string(out.join("summary.txt")).expect("summary");
    assert!(text.starts_with("status: aborted"), "{text}");
}

/// A panic in dcroxide's answer is a disagreement of its own, and dcrd's
/// answer to the case is still recorded.
fn a_panic_in_dcroxide_is_recorded() {
    let dir = TempDir::new("sigdiff-fake-ours");
    let summary = within(Duration::from_secs(60), "the dcroxide panic run", {
        let out = dir.path().to_path_buf();
        move || fake_run(&T_PANICS, &["echo"], 100, 2, &out)
    });
    let class = &summary.classes[0];
    assert_eq!(class.completed, 100);
    assert_eq!(class.statuses, [90, 0, 0, 10]);
    assert_eq!(summary.disagreements, 10);
    assert!(
        summary
            .notes
            .iter()
            .all(|n| n.category == Category::OursPanicked && n.index.is_multiple_of(10))
    );
    let counts = std::fs::read_to_string(dir.path().join("counts.tsv")).expect("counts");
    assert!(
        counts.contains("T-panics\tpanics\t0\tecdsa_verify_raw\tpanic\treject:plain\t10"),
        "{counts}"
    );
}

/// Counts and digests are the same with one worker and with four, and are
/// the ones the cases' own seeds give.
fn results_do_not_depend_on_workers() {
    let dir = TempDir::new("sigdiff-fake-workers");
    let one = within(Duration::from_secs(60), "one worker", {
        let out = dir.path().join("one");
        move || fake_run(&T_DRAWN, &["echo"], 1_000, 1, &out)
    });
    let four = within(Duration::from_secs(60), "four workers", {
        let out = dir.path().join("four");
        move || fake_run(&T_DRAWN, &["echo"], 1_000, 4, &out)
    });
    assert_eq!(one.status, RunStatus::Passed, "{:?}", one.problems());
    assert_eq!(one.classes, four.classes);
    assert_eq!(
        one.classes[0].digest.total(),
        expected_sum(&T_DRAWN, 1_000, &[])
    );
    for file in ["counts.tsv", "kinds.tsv", "digests.tsv"] {
        let a = std::fs::read_to_string(dir.path().join("one").join(file)).expect("read");
        let b = std::fs::read_to_string(dir.path().join("four").join(file)).expect("read");
        assert_eq!(a, b, "{file}");
    }
}

/// After a deadline, and after a stop on the first disagreement, the
/// completed cases are exactly a prefix of the class.
fn a_deadline_and_a_stop_leave_a_prefix() {
    let dir = TempDir::new("sigdiff-fake-prefix");
    let summary = within(Duration::from_secs(60), "the budget run", {
        let out = dir.path().join("budget");
        move || {
            let mut cfg = RunConfig::new(
                SEED,
                vec![&T_DRAWN],
                Mode::Budget(Duration::from_millis(300)),
                me(),
            );
            cfg.oracle_args = vec![FAKE.into(), "echo".into()];
            cfg.workers = 3;
            cfg.out = Some(out);
            run(&cfg).expect("runs")
        }
    });
    let n = summary.classes[0].completed;
    assert!(n > 0);
    assert_eq!(
        summary.classes[0].digest.total(),
        expected_sum(&T_DRAWN, n, &[])
    );

    // The fake lies on case 1,000, named by the number its drawn bytes
    // carry.
    let lie_at = number(&generate(&T_DRAWN, SEED, 1_000).requests[0].data);
    let summary = within(Duration::from_secs(60), "the stop run", {
        let out = dir.path().join("stop");
        move || {
            let mut cfg = RunConfig::new(SEED, vec![&T_DRAWN], Mode::Cases(100_000), me());
            cfg.oracle_args = vec![FAKE.into(), format!("lie-at={lie_at}").into()];
            cfg.workers = 3;
            cfg.stop_on_disagreement = true;
            cfg.out = Some(out);
            run(&cfg).expect("runs")
        }
    });
    let n = summary.classes[0].completed;
    assert!((1_001..100_000).contains(&n), "stopped at {n}");
    let lie = Answer::Reject {
        kind: Kind::Dcrd("ErrSigTooLong".to_owned()),
        text: Some(TOO_SHORT.to_owned()),
    };
    assert_eq!(
        summary.classes[0].digest.total(),
        expected_sum(&T_DRAWN, n, &[(1_000, Some(lie), Status::Disagree)])
    );
}

/// The options a workspace run passes on reach the harness as libtest
/// would read them: a flag's value is never a filter, `--skip` and
/// `--exact` apply, and `--ignored` selects nothing.
fn the_harness_reads_libtest_options() {
    let selected = |args: &[&str]| -> Vec<&str> {
        let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
        let options = Options::parse(&args);
        ["stress_without_deadlock", "a_fatal_exit_is_isolated"]
            .into_iter()
            .filter(|name| options.selects(name))
            .collect()
    };
    let both = ["stress_without_deadlock", "a_fatal_exit_is_isolated"];
    assert_eq!(selected(&[]), both);
    assert_eq!(selected(&["--test-threads", "1"]), both);
    assert_eq!(selected(&["--test-threads=1", "--nocapture"]), both);
    assert_eq!(selected(&["--color", "always", "--format", "pretty"]), both);
    assert_eq!(selected(&["--include-ignored", "-q"]), both);
    assert_eq!(
        selected(&["--skip", "stress_without_deadlock"]),
        ["a_fatal_exit_is_isolated"]
    );
    assert_eq!(selected(&["--skip=fatal"]), ["stress_without_deadlock"]);
    assert_eq!(selected(&["fatal"]), ["a_fatal_exit_is_isolated"]);
    assert_eq!(selected(&["--exact", "fatal"]), Vec::<&str>::new());
    assert_eq!(
        selected(&["--exact", "a_fatal_exit_is_isolated"]),
        ["a_fatal_exit_is_isolated"]
    );
    assert_eq!(selected(&["--exact", "--skip", "stress"]), both);
    assert_eq!(selected(&["--ignored"]), Vec::<&str>::new());
    let options = Options::parse(&["--test-threads".to_owned(), "3".to_owned()]);
    assert_eq!(options.threads, Some(3));
    assert!(Options::parse(&["--list".to_owned()]).list);
}
