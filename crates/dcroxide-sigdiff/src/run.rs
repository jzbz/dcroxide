// SPDX-License-Identifier: ISC
//! The soak's run loop: classes spread over workers, one oracle per worker,
//! every case compared and counted, faults pinned on the case that caused
//! them.
//!
//! # Scheduling
//!
//! Each class has a target count and a claim counter.  A worker claims 64
//! consecutive cases from the unfinished class furthest behind its target,
//! generates and submits them, and claims again.  Every claimed case
//! completes, at a deadline and across oracle faults alike, so each class's
//! completed cases are exactly `0..n` and its digest is well defined.
//!
//! # Faults
//!
//! A Go panic flushes the answers ahead of the panicking request, so the
//! first unanswered case is the culprit.  Any other fault (a hang the
//! monitor killed, a Go fatal error, a kill from outside, a broken
//! protocol) may have lost answers the oracle held, so the worker isolates:
//! it resubmits the unanswered cases one at a time to a fresh oracle in
//! serial mode, and the first one that fails is the culprit, run once more
//! alone to see whether it fails the same way again.  A culprit is a
//! disagreement of category `oracle-crashed`, `oracle-hung` or `protocol`
//! and counts as completed; a fault no case reproduces is an event, not a
//! disagreement.  A worker handles at most `max_faults` faults; one more
//! stops it and the run ends `aborted`.
//!
//! dcroxide's answer is computed under `catch_unwind` before the case is
//! submitted, so a panic in the code under test is a disagreement of
//! category `ours-panicked` with dcrd's answer still recorded.  A run may
//! stand a canary in for dcroxide on the canary's commands
//! ([`RunConfig::canary`]); the canary run ([`canary_run`]) does so for the
//! model baseline and each canary in turn.  A case dcroxide does not finish
//! within the hang timeout cannot be stopped from outside: the monitor
//! records it as `ours-hung`, writes the summary as `aborted` and ends the
//! process with exit code 3.
//!
//! [`answer_cases`] runs a few cases of one class the same way, through
//! one oracle, for the witness vectors.  The fuzz entry ([`crate::fuzz`])
//! and `sigsoak` share the loop's answerer ([`ours_answerer`]), its plan of
//! a class's indices ([`class_indices`]) and its printing of a failure and
//! a request ([`failure_line`], [`RequestLines`]).

use std::any::Any;
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::ffi::OsString;
use std::fmt::Write as _;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use dcroxide_testutil::{SplitMix64, hex, oracle_bin_or_skip};
use serde_json::{Value, json};

use crate::answer::{Detail, OursAnswer};
use crate::canary::{CANARY_BOUND, Canary, MODEL_BASELINE, Rule, StandIn, find_stand_in};
use crate::class::{Case, ClassSpec, Family, Intent, find_class, generate};
use crate::cmd::{Cmd, Request};
use crate::compare::{CaseResult, Category, Failure, Status, compare};
use crate::digest::{ClassDigest, class_digest, leaf};
use crate::manifest::check_pin;
use crate::model::{self, ModelOutcome, ModelView};
use crate::ours;
use crate::pipe::{OracleFault, OraclePipe, Payload, PipeConfig, PipeFailure, PipeHealth};
use crate::record::{MixResult, REACHABLE_KINDS, Recorder, Totals, UNREACHABLE, evaluate_mixes};
use crate::reply::Reply;

/// Cases a worker claims at a time.
const CHUNK: u64 = 64;

/// Disagreements a summary keeps in memory, for tests and replay.
const KEPT_NOTES: usize = 1_000;

/// How many cases each class runs.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Mode {
    /// Each sampled class's floor times `scale`; finite classes whole.
    Floors {
        /// The multiplier on the floors.
        scale: f64,
    },
    /// This many cases of each sampled class; finite classes whole.
    Cases(u64),
    /// Until the deadline, finite classes first and whole, the sampled
    /// classes weighted by their floors.
    Budget {
        /// How long the run claims cases.
        duration: Duration,
        /// The share of its floor each sampled class must complete, a
        /// finite class running whole; `None` leaves the floors unjudged.
        min_scale: Option<f64>,
    },
    /// The per-PR tests' counts: each class's `pr_cases` (or `cases` for
    /// every class); a finite class of at most 128 elements whole, a larger
    /// one `pr_cases` elements at an even stride.
    PerPr {
        /// A count overriding every class's `pr_cases`.
        cases: Option<u64>,
    },
}

impl Mode {
    /// The manifest's `mode` object.
    pub fn to_json(&self) -> Value {
        match *self {
            Mode::Floors { scale } => json!({ "kind": "floors", "scale": scale }),
            Mode::Cases(n) => json!({ "kind": "cases", "cases": n }),
            Mode::Budget {
                duration,
                min_scale,
            } => {
                let mut mode = json!({ "kind": "budget", "seconds": duration.as_secs() });
                if let Some(share) = min_scale {
                    mode["min_scale"] = json!(share);
                }
                mode
            }
            Mode::PerPr { cases } => json!({ "kind": "per-pr", "cases": cases }),
        }
    }
}

/// How a run went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunStatus {
    /// Every criterion the run could decide passed.
    Passed,
    /// A criterion failed.
    Failed,
    /// The run stopped early: oracle faults exhausted, an oracle that would
    /// not start, a worker that panicked.
    Aborted,
}

impl RunStatus {
    /// `passed`, `failed` or `aborted`.
    pub fn name(self) -> &'static str {
        match self {
            RunStatus::Passed => "passed",
            RunStatus::Failed => "failed",
            RunStatus::Aborted => "aborted",
        }
    }
}

/// Everything a run takes.
#[derive(Debug, Clone)]
pub struct RunConfig {
    /// The master seed.
    pub master: u64,
    /// The classes to run.
    pub classes: Vec<&'static ClassSpec>,
    /// How many cases of each.
    pub mode: Mode,
    /// Worker threads, one oracle each.
    pub workers: usize,
    /// Cases in flight per oracle.
    pub window: usize,
    /// Requests per flush.
    pub flush_every: usize,
    /// How long an oracle may owe answers, or dcroxide take on one case,
    /// before it counts as hung.
    pub hang_timeout: Duration,
    /// How often to report progress; `None` for never.
    pub progress_every: Option<Duration>,
    /// The oracle binary.
    pub oracle: PathBuf,
    /// Arguments to it.
    pub oracle_args: Vec<OsString>,
    /// `GOMAXPROCS` for each oracle.
    pub gomaxprocs: u32,
    /// The output directory; `None` writes nothing (oracles then inherit
    /// stderr).
    pub out: Option<PathBuf>,
    /// The start manifest, rewritten with the status at the end.
    pub manifest: Option<Value>,
    /// Stop claiming a class once a case of it disagreed (the canary run).
    pub stop_on_disagreement: bool,
    /// Faults a worker handles before it stops.
    pub max_faults: u32,
    /// Whether to decide the kind-coverage criterion (gate-eligible runs).
    pub kind_coverage: bool,
    /// The command a disagreement record's replay line starts with.
    pub replay_program: String,
    /// What answers in dcroxide's place on the commands it covers: a
    /// canary or the model baseline; `None` for dcroxide itself.
    pub canary: Option<StandIn>,
}

impl RunConfig {
    /// A run of `classes` under `master` in `mode` against `oracle`, with
    /// the defaults: [`default_workers`] workers, window 512, flush batch
    /// 64, hang timeout 120 s, no progress, `GOMAXPROCS=2`, no output, 3
    /// faults per worker, dcroxide answering.
    pub fn new(
        master: u64,
        classes: Vec<&'static ClassSpec>,
        mode: Mode,
        oracle: PathBuf,
    ) -> RunConfig {
        RunConfig {
            master,
            classes,
            mode,
            workers: default_workers(),
            window: 512,
            flush_every: 64,
            hang_timeout: Duration::from_secs(120),
            progress_every: None,
            oracle,
            oracle_args: Vec::new(),
            gomaxprocs: 2,
            out: None,
            manifest: None,
            stop_on_disagreement: false,
            max_faults: 3,
            kind_coverage: false,
            replay_program: "sigsoak".to_owned(),
            canary: None,
        }
    }
}

/// One worker per two hardware threads, less one for the monitor and the
/// system: each worker keeps about one core busy in Rust and one in Go.
pub fn default_workers() -> usize {
    let threads = thread::available_parallelism().map_or(2, usize::from);
    (threads / 2).saturating_sub(1).max(1)
}

/// One failed case, kept in memory (the first thousand of a run).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisagreementNote {
    /// The class.
    pub class: &'static str,
    /// The case index.
    pub index: u64,
    /// The case's status.
    pub status: Status,
    /// The first failed check's category.
    pub category: Category,
    /// Every failed check.
    pub failures: Vec<String>,
    /// For an oracle culprit found by isolation, whether a second run alone
    /// failed the same way.
    pub reproduced: Option<bool>,
    /// For an oracle that exited, whether on a Go panic.
    pub go_panic: Option<bool>,
}

/// One class's part of a summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassSummary {
    /// The class name.
    pub name: &'static str,
    /// Its family.
    pub family: Family,
    /// Its floor (a finite class's size).
    pub floor: u64,
    /// The cases the run targeted; `None` for a budget run's sampled class.
    pub target: Option<u64>,
    /// Cases completed.
    pub completed: u64,
    /// Cases per status, by status code.
    pub statuses: [u64; 4],
    /// Requests sent.
    pub requests: u64,
    /// Cases that fell back to fixed values.
    pub fallbacks: u64,
    /// Whether a finite class ran every element.
    pub whole: bool,
    /// The lowest index of a case that disagreed (status 1); with every
    /// completed index below the count, the class's first.
    pub first_disagree: Option<u64>,
    /// Its digest.
    pub digest: ClassDigest,
}

impl ClassSummary {
    /// The class digest at its final count.
    pub fn final_digest(&self) -> [u8; 32] {
        class_digest(self.name, self.completed, &self.digest.total())
    }
}

/// A criterion's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CriterionState {
    /// It held.
    Pass,
    /// It did not.
    Fail,
    /// The run cannot decide it.
    NotEvaluated,
}

/// One done-criterion a single run decides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Criterion {
    /// Its name.
    pub name: &'static str,
    /// Its verdict.
    pub state: CriterionState,
    /// Why.
    pub detail: String,
}

/// The outcome of a run.
#[derive(Debug, Clone)]
pub struct Summary {
    /// How it went.
    pub status: RunStatus,
    /// Its master seed.
    pub master: u64,
    /// Its mode.
    pub mode: Mode,
    /// How long it took.
    pub elapsed: Duration,
    /// Per class, in run order.
    pub classes: Vec<ClassSummary>,
    /// Its counts (`counts.tsv`, `kinds.tsv`).
    pub totals: Totals,
    /// Every mix check.
    pub mixes: Vec<MixResult>,
    /// The criteria.
    pub criteria: Vec<Criterion>,
    /// Cases completed.
    pub cases: u64,
    /// Requests sent.
    pub requests: u64,
    /// Cases that did not agree.
    pub disagreements: u64,
    /// Disagreement lines not written.
    pub disagreements_unwritten: u64,
    /// Failed checks per category, over every disagreement.
    pub categories: BTreeMap<Category, u64>,
    /// The first disagreements.
    pub notes: Vec<DisagreementNote>,
    /// The oracle events.
    pub events: Vec<Value>,
    /// Oracle faults, culprit found or not.
    pub oracle_faults: u64,
    /// Faults no case reproduced.
    pub faults_not_reproduced: u64,
    /// The oracle's `build_info`.
    pub build_info: Option<Reply>,
    /// Why the run stopped early.
    pub abort_reason: Option<String>,
    /// What answered in dcroxide's place, if anything.
    pub canary: Option<StandIn>,
}

impl Summary {
    /// Every failing criterion and the abort reason, one line each; empty
    /// when the run passed.
    pub fn problems(&self) -> Vec<String> {
        let mut problems: Vec<String> = self
            .criteria
            .iter()
            .filter(|c| c.state == CriterionState::Fail)
            .map(|c| format!("{}: {}", c.name, c.detail))
            .collect();
        problems.extend(self.abort_reason.iter().map(|r| format!("aborted: {r}")));
        problems.extend(self.notes.iter().take(10).map(|n| {
            format!(
                "{} case {} ({}): {}",
                n.class,
                n.index,
                n.category.name(),
                n.failures.join("; ")
            )
        }));
        problems
    }

    /// The class named `name`.
    pub fn class(&self, name: &str) -> Option<&ClassSummary> {
        self.classes.iter().find(|c| c.name == name)
    }

    /// `summary.txt`.
    pub fn render(&self) -> String {
        let mut s = String::new();
        let secs = self.elapsed.as_secs_f64();
        let _ = writeln!(s, "status: {}", self.status.name());
        if let Some(reason) = &self.abort_reason {
            let _ = writeln!(s, "aborted: {reason}");
        }
        let _ = writeln!(s, "master seed: {:#018x}", self.master);
        if let Some(canary) = &self.canary {
            let commands: Vec<&str> = canary.commands.iter().map(|c| c.name()).collect();
            let _ = writeln!(
                s,
                "canary: {} answered in dcroxide's place on {}",
                canary.name,
                commands.join(", ")
            );
        }
        let _ = writeln!(s, "mode: {}", self.mode.to_json());
        let _ = writeln!(
            s,
            "elapsed: {secs:.1} s; {} cases, {} requests ({:.0} requests/s)",
            self.cases,
            self.requests,
            if secs > 0.0 {
                self.requests as f64 / secs
            } else {
                0.0
            }
        );
        s.push_str("\ncriteria:\n");
        for c in &self.criteria {
            let state = match c.state {
                CriterionState::Pass => "pass",
                CriterionState::Fail => "FAIL",
                CriterionState::NotEvaluated => "not evaluated",
            };
            let _ = writeln!(s, "  {}: {state} ({})", c.name, c.detail);
        }
        let _ = writeln!(
            s,
            "\ndisagreements: {} ({} not written)",
            self.disagreements, self.disagreements_unwritten
        );
        for (category, n) in &self.categories {
            let _ = writeln!(s, "  {}: {n}", category.name());
        }
        let _ = writeln!(
            s,
            "\noracle events: {} faults, {} not reproduced",
            self.oracle_faults, self.faults_not_reproduced
        );
        for event in &self.events {
            let _ = writeln!(s, "  {event}");
        }
        s.push_str(
            "\nclasses (completed, target, cases/s, statuses agree/disagree/oracle/panic):\n",
        );
        for c in &self.classes {
            let _ = writeln!(
                s,
                "  {}: {}, {}, {:.0}, {:?}{}",
                c.name,
                c.completed,
                c.target
                    .map_or_else(|| "budget".to_owned(), |t| t.to_string()),
                if secs > 0.0 {
                    c.completed as f64 / secs
                } else {
                    0.0
                },
                c.statuses,
                if c.fallbacks > 0 {
                    format!(", {} fallbacks", c.fallbacks)
                } else {
                    String::new()
                }
            );
        }
        if let Mode::Budget { .. } = self.mode {
            let rate = if secs > 0.0 {
                self.requests as f64 / secs
            } else {
                0.0
            };
            let floor_requests: f64 = self
                .classes
                .iter()
                .map(|c| {
                    let per_case = if c.completed > 0 {
                        c.requests as f64 / c.completed as f64
                    } else {
                        1.0
                    };
                    c.floor as f64 * per_case
                })
                .sum();
            if rate > 0.0 {
                let _ = writeln!(
                    s,
                    "\nat {rate:.0} requests/s, a --floors run of these classes ({floor_requests:.0} \
                     requests) would take about {:.0} s",
                    floor_requests / rate
                );
            }
        }
        // Only the families the run selected.
        let unreachable: Vec<&str> = UNREACHABLE
            .iter()
            .filter(|(family, _)| self.classes.iter().any(|c| c.family == *family))
            .map(|&(_, line)| line)
            .collect();
        if unreachable.is_empty() {
            s.push_str("\nunreachable through the oracle: nothing in the families run\n");
        } else {
            s.push_str("\nunreachable through the oracle:\n");
            for line in unreachable {
                let _ = writeln!(s, "  {line}");
            }
        }
        s
    }
}

thread_local! {
    /// Where the last panic on this thread happened, as a panic hook noted
    /// it.
    static PANIC_AT: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Notes where a panic happened, for the record of the case it hit.  The
/// `sigsoak` binary's panic hook calls it; library code installs no hook.
pub fn note_panic(info: &std::panic::PanicHookInfo<'_>) {
    let at = info
        .location()
        .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()));
    PANIC_AT.with(|p| *p.borrow_mut() = at);
}

/// A panic's message, with its place when a panic hook noted one
/// ([`note_panic`]).
pub fn panic_message(payload: &(dyn Any + Send)) -> String {
    let message = payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "a panic with a payload that is not text".to_owned());
    match PANIC_AT.with(|p| p.borrow_mut().take()) {
        Some(at) => format!("{message} (at {at})"),
        None => message,
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// How a class is run: how many cases (ordinals), which index each ordinal
/// is, and its weight among the classes.
#[derive(Debug, Clone)]
struct ClassPlan {
    spec: &'static ClassSpec,
    /// Ordinals to run; `u64::MAX` for a budget run's sampled class.
    target: u64,
    /// The scheduler's divisor: the class furthest behind its weight goes
    /// next.
    weight: u64,
    /// Ordinal `k` is case `k * stride`.
    stride: u64,
}

/// The cases each class runs under `mode`, as a manifest records them:
/// `None` for a budget run's sampled classes, which run until the deadline.
pub fn class_targets(classes: &[&'static ClassSpec], mode: Mode) -> Vec<Option<u64>> {
    plans(classes, mode)
        .iter()
        .map(|p| (p.target != u64::MAX).then_some(p.target))
        .collect()
}

/// The indices of `class` a run in `mode` takes, in order, from the plan
/// the run loop claims from: ordinal `k` is case `k × stride`.  Unbounded,
/// in effect, for a budget run's sampled class.
pub fn class_indices(class: &'static ClassSpec, mode: Mode) -> impl Iterator<Item = u64> {
    let plan = plans(&[class], mode).pop().expect("one plan per class");
    (0..plan.target).map_while(move |k| k.checked_mul(plan.stride))
}

/// A sampled class's floor times `scale`, rounded, and at least one case:
/// what a `--floors` run at that scale runs, and what a budget run with
/// that minimum share requires.
fn scaled_floor(floor: u64, scale: f64) -> u64 {
    ((floor as f64) * scale).round().max(1.0) as u64
}

fn plans(classes: &[&'static ClassSpec], mode: Mode) -> Vec<ClassPlan> {
    classes
        .iter()
        .map(|&spec| {
            let floor = spec.size.floor();
            let finite = spec.size.finite();
            let (target, stride) = match (mode, finite) {
                (Mode::PerPr { cases }, Some(size)) if size > 128 => {
                    let count = cases.unwrap_or(spec.pr_cases).clamp(1, size);
                    (count, size.checked_div(count).unwrap_or(1).max(1))
                }
                (_, Some(size)) => (size, 1),
                (Mode::Floors { scale }, None) => (scaled_floor(floor, scale), 1),
                (Mode::Cases(n), None) => (n, 1),
                (Mode::Budget { .. }, None) => (u64::MAX, 1),
                (Mode::PerPr { cases }, None) => (cases.unwrap_or(spec.pr_cases), 1),
            };
            let weight = if target == u64::MAX { floor } else { target }.max(1);
            ClassPlan {
                spec,
                target,
                weight,
                stride,
            }
        })
        .collect()
}

/// A worker's producer is building no case.
const IDLE: u8 = 0;
/// A worker's producer is generating a case.
const GENERATING: u8 = 1;
/// A worker's producer is computing dcroxide's answers and the models' view
/// of a case it generated.
const ANSWERING: u8 = 2;

/// What a worker shows the monitor.
struct Slot {
    health: Mutex<Option<Arc<PipeHealth>>>,
    /// When the producer started on the current case (ms since the run
    /// began, plus one), or 0 when it is not building one.
    busy_since: AtomicU64,
    /// [`IDLE`], [`GENERATING`] or [`ANSWERING`].
    phase: AtomicU8,
    class: AtomicUsize,
    index: AtomicU64,
    totals: Mutex<Totals>,
}

struct Shared {
    master: u64,
    mode: Mode,
    plans: Vec<ClassPlan>,
    claimed: Vec<AtomicU64>,
    completed: Vec<AtomicU64>,
    stopped: Vec<AtomicBool>,
    start: Instant,
    deadline: Option<Instant>,
    halt: AtomicBool,
    abort_reason: Mutex<Option<String>>,
    recorder: Recorder,
    slots: Vec<Slot>,
    build_info: OnceLock<Reply>,
    pipe: PipeConfig,
    max_faults: u32,
    hang_timeout: Duration,
    stop_on_disagreement: bool,
    kind_coverage: bool,
    replay_program: String,
    canary: Option<StandIn>,
    cases: AtomicU64,
    requests: AtomicU64,
    disagreements: AtomicU64,
    faults: AtomicU64,
    not_reproduced: AtomicU64,
    categories: Mutex<BTreeMap<Category, u64>>,
    notes: Mutex<Vec<DisagreementNote>>,
    events: Mutex<Vec<Value>>,
}

impl Shared {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn abort(&self, reason: String) {
        self.halt.store(true, Ordering::SeqCst);
        lock(&self.abort_reason).get_or_insert(reason);
    }

    /// Claims the next chunk: from the unfinished class furthest behind
    /// (finite classes first in a budget run), at most [`CHUNK`] ordinals.
    fn claim(&self) -> Option<(usize, Range<u64>)> {
        loop {
            if self.halt.load(Ordering::SeqCst)
                || self.deadline.is_some_and(|d| Instant::now() >= d)
            {
                return None;
            }
            let budget = matches!(self.mode, Mode::Budget { .. });
            let mut best: Option<(usize, (bool, f64))> = None;
            for (k, plan) in self.plans.iter().enumerate() {
                let claimed = self.claimed[k].load(Ordering::SeqCst);
                if claimed >= plan.target || self.stopped[k].load(Ordering::SeqCst) {
                    continue;
                }
                let rank = (
                    !(budget && plan.spec.size.finite().is_some()),
                    claimed as f64 / plan.weight as f64,
                );
                if best.is_none_or(|(_, b)| rank < b) {
                    best = Some((k, rank));
                }
            }
            let (k, _) = best?;
            let target = self.plans[k].target;
            let from = self.claimed[k].load(Ordering::SeqCst);
            if from >= target {
                continue;
            }
            let to = from.saturating_add(CHUNK).min(target);
            if self.claimed[k]
                .compare_exchange(from, to, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Some((k, from..to));
            }
        }
    }

    fn pipe_config(&self, worker: usize, window: usize, flush_every: usize) -> PipeConfig {
        PipeConfig {
            window,
            flush_every,
            stderr: self.recorder.stderr_path(worker),
            ..self.pipe.clone()
        }
    }

    /// Requires a new oracle's `build_info` to keep the pin rule and to
    /// equal the first oracle's.
    fn check_build_info(&self, reply: &Reply) -> Result<(), String> {
        let first = self.build_info.get_or_init(|| reply.clone());
        let pin = check_pin(first);
        if !pin.consistent() {
            return Err(format!(
                "the oracle's pin check failed: {}",
                pin.problems().join("; ")
            ));
        }
        if first.go_version != reply.go_version || first.modules != reply.modules {
            return Err(format!(
                "an oracle answered build_info with {}, where the first answered {}",
                reply.raw, first.raw
            ));
        }
        Ok(())
    }

    fn event(&self, value: Value) {
        self.recorder.event(&value);
        lock(&self.events).push(value);
    }

    fn replay_line(&self, class: &str, index: u64) -> String {
        let canary = self
            .canary
            .map(|c| format!(" --canary {}", c.name))
            .unwrap_or_default();
        format!(
            "{} replay --seed {:#018x} --class {class} --case {index}{canary}",
            self.replay_program, self.master
        )
    }

    /// Counts a completed case and records it if it did not agree.
    fn account(
        &self,
        worker: usize,
        totals: &mut Totals,
        work: &Work,
        result: &CaseResult,
        replies: Option<&[Reply]>,
        fault: Option<(&OracleFault, Option<bool>)>,
    ) {
        let spec = self.plans[work.class].spec;
        let leaf = leaf(
            spec.name,
            work.index,
            &work.case.requests,
            &result.theirs,
            result.status,
        );
        totals.record(
            work.class, work.index, &work.case, &work.ours, result, &leaf,
        );
        let n = u64::try_from(work.case.requests.len()).unwrap_or(u64::MAX);
        self.completed[work.class].fetch_add(1, Ordering::SeqCst);
        self.cases.fetch_add(1, Ordering::SeqCst);
        self.requests.fetch_add(n, Ordering::SeqCst);
        if result.status == Status::Agree {
            return;
        }
        self.disagreements.fetch_add(1, Ordering::SeqCst);
        if self.stop_on_disagreement {
            self.stopped[work.class].store(true, Ordering::SeqCst);
        }
        {
            let mut categories = lock(&self.categories);
            for failure in &result.failures {
                let n = categories.entry(failure.category).or_insert(0);
                *n = n.saturating_add(1);
            }
        }
        let first = result.failures.first();
        let category = first.map_or(Category::Verdict, |f| f.category);
        let reproduced = fault.and_then(|(_, r)| r);
        let go_panic = fault.and_then(|(f, _)| match f {
            OracleFault::Exited { go_panic, .. } => Some(*go_panic),
            _ => None,
        });
        {
            let mut notes = lock(&self.notes);
            if notes.len() < KEPT_NOTES {
                notes.push(DisagreementNote {
                    class: spec.name,
                    index: work.index,
                    status: result.status,
                    category,
                    failures: result.failures.iter().map(failure_line).collect(),
                    reproduced,
                    go_panic,
                });
            }
        }
        let panic = work.ours.iter().find_map(|o| o.as_ref().err().cloned());
        let record = json!({
            "class": spec.name,
            "variant": work.case.variant,
            "index": work.index,
            "master_seed": format!("{:#018x}", self.master),
            "case_seed": format!("{:#018x}", crate::class::case_seed(self.master, spec.name, work.index)),
            "worker": worker,
            "category": category.name(),
            "status": result.status.code(),
            "canary": self.canary.map(|c| c.name),
            "request": first.and_then(|f| f.request),
            "detail": first.map(|f| f.detail.clone()),
            "failures": result.failures.iter().map(|f| json!({
                "category": f.category.name(), "request": f.request, "detail": f.detail,
            })).collect::<Vec<_>>(),
            "requests": work.case.requests.iter().map(|r| json!({
                "cmd": r.cmd.name(), "data": hex(&r.data),
            })).collect::<Vec<_>>(),
            "theirs": replies.map(|rs| rs.iter().map(Reply::to_json).collect::<Vec<_>>()),
            "ours": work.ours.iter().map(|o| match o {
                Ok(o) => o.answer.describe(),
                Err(message) => format!("panic: {message}"),
            }).collect::<Vec<_>>(),
            "ours_detail": work.ours.iter().map(|o| o.as_ref().ok().map(|o| format!("{:?}", o.detail))).collect::<Vec<_>>(),
            "intent": work.case.intents.iter().map(|i| format!("{i:?}")).collect::<Vec<_>>(),
            "panic": panic,
            "oracle_exit": fault.and_then(|(f, _)| f.exit_status()).map(|s| s.to_string()),
            "go_panic": go_panic,
            "reproduced": reproduced,
            "oracle_stderr_tail": fault.and_then(|(f, _)| f.stderr_tail().map(str::to_owned)),
            "replay": self.replay_line(spec.name, work.index),
        });
        self.recorder.disagreement(&record);
    }
}

/// A case on its way through a pipe: its requests, dcroxide's answers
/// and the models' view, computed before it was submitted.
struct Work {
    class: usize,
    index: u64,
    case: Case,
    ours: Vec<Result<OursAnswer, String>>,
    model: ModelView,
}

impl Payload for Work {
    fn requests(&self) -> &[Request] {
        &self.case.requests
    }
}

/// A culprit's requests, sent once more alone to see whether it fails the
/// same way again.
struct Probe(Vec<Request>);

impl Payload for Probe {
    fn requests(&self) -> &[Request] {
        &self.0
    }
}

/// dcroxide's answerer, as the run loop calls it: each request under
/// `catch_unwind`, a panic as `Err` with its message (and its place, when
/// the binary's hook noted one), and `canary`'s answer on the commands it
/// covers, when one stands in.
pub fn ours_answerer(canary: Option<StandIn>) -> impl Fn(Cmd, &[u8]) -> Result<OursAnswer, String> {
    move |cmd: Cmd, data: &[u8]| {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match canary {
            Some(canary) if canary.covers(cmd) => canary.answer(cmd, data),
            _ => ours::answer(cmd, data),
        }))
        .map_err(|payload| panic_message(payload.as_ref()))
    }
}

/// dcroxide's answers to `case` ([`ours_answerer`]).
fn ours_answers(case: &Case, canary: Option<StandIn>) -> Vec<Result<OursAnswer, String>> {
    let answer = ours_answerer(canary);
    case.requests
        .iter()
        .map(|r| answer(r.cmd, &r.data))
        .collect()
}

/// One failed check as a run's notes print it: `<category> on request
/// <j>: <detail>`, or `<category>: <detail>` for a check across requests.
pub fn failure_line(failure: &Failure) -> String {
    match failure.request {
        Some(j) => format!(
            "{} on request {j}: {}",
            failure.category.name(),
            failure.detail
        ),
        None => format!("{}: {}", failure.category.name(), failure.detail),
    }
}

/// One request's block, as `sigsoak replay`, `sigsoak fuzz-replay` and a
/// fuzz target's report print it: `request <j>: <cmd> <hex>`, then,
/// indented, the intent (and the intent checked, when given), each side's
/// answer under its label (`no answer` where it has none, `panic: ..`
/// where dcroxide panicked) and the models' outcome, when there is one.
/// Lines are separated by newlines, with none after the last.
#[derive(Debug, Clone, Copy)]
pub struct RequestLines<'a> {
    /// The request's place in its case.
    pub j: usize,
    /// The request.
    pub request: &'a Request,
    /// The intent it was built for.
    pub intent: &'a Intent,
    /// The intent a fuzz target held it to ([`crate::fuzz::rebase`]);
    /// `None` where the intent it was built for is the one held.
    pub checked: Option<&'a Intent>,
    /// What dcroxide's answer is called.
    pub ours_label: &'a str,
    /// dcroxide's answer.
    pub ours: Option<&'a Result<OursAnswer, String>>,
    /// What the other side's answer is called.
    pub theirs_label: &'a str,
    /// The other side's reply, printed as received.
    pub theirs: Option<&'a Reply>,
    /// The models' outcome.
    pub model: Option<ModelOutcome>,
}

impl std::fmt::Display for RequestLines<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "request {}: {} {}\n  intent: {:?}",
            self.j,
            self.request.cmd.name(),
            hex(&self.request.data),
            self.intent
        )?;
        if let Some(checked) = self.checked {
            write!(f, ", checked: {checked:?}")?;
        }
        match self.ours {
            Some(Ok(o)) if o.detail == Detail::None => {
                write!(f, "\n  {}: {}", self.ours_label, o.answer.describe())?;
            }
            Some(Ok(o)) => write!(
                f,
                "\n  {}: {} ({:?})",
                self.ours_label,
                o.answer.describe(),
                o.detail
            )?,
            Some(Err(message)) => write!(f, "\n  {}: panic: {message}", self.ours_label)?,
            None => write!(f, "\n  {}: no answer", self.ours_label)?,
        }
        match self.theirs {
            Some(reply) => write!(f, "\n  {}: {}", self.theirs_label, reply.raw)?,
            None => write!(f, "\n  {}: no answer", self.theirs_label)?,
        }
        if let Some(model) = self.model {
            write!(f, "\n  model: {model:?}")?;
        }
        Ok(())
    }
}

fn category_of(fault: &OracleFault) -> Category {
    match fault {
        OracleFault::Exited { .. } => Category::OracleCrashed,
        OracleFault::Hung { .. } => Category::OracleHung,
        OracleFault::Protocol { .. } => Category::Protocol,
    }
}

/// The first and last index and the count of each class's unanswered
/// cases, for an event.
fn index_ranges(shared: &Shared, works: &[Work]) -> Vec<Value> {
    let mut ranges: BTreeMap<usize, (u64, u64, u64)> = BTreeMap::new();
    for w in works {
        let r = ranges.entry(w.class).or_insert((w.index, w.index, 0));
        r.0 = r.0.min(w.index);
        r.1 = r.1.max(w.index);
        r.2 = r.2.saturating_add(1);
    }
    ranges
        .into_iter()
        .map(|(k, (first, last, n))| {
            json!({ "class": shared.plans[k].spec.name, "first": first, "last": last, "n": n })
        })
        .collect()
}

struct Worker {
    id: usize,
    shared: Arc<Shared>,
    pipe: Option<OraclePipe<Work>>,
    faults: u32,
}

impl Worker {
    fn run(mut self) {
        if let Err(reason) = self.work() {
            self.shared.abort(reason);
        }
        // A pipe left over by an abort is dropped here, killing its oracle.
        self.pipe = None;
        *lock(&self.shared.slots[self.id].health) = None;
    }

    fn work(&mut self) -> Result<(), String> {
        while let Some((class, ordinals)) = self.shared.claim() {
            for ordinal in ordinals {
                let work = self.prepare(class, ordinal);
                self.submit(work)?;
            }
        }
        while let Some(pipe) = self.pipe.take() {
            if let Err(failure) = pipe.finish() {
                self.handle(failure)?;
            }
        }
        Ok(())
    }

    /// Generates a case and computes dcroxide's answers and the models'
    /// view, with the monitor watching how long it takes.
    fn prepare(&self, class: usize, ordinal: u64) -> Work {
        let plan = &self.shared.plans[class];
        let index = ordinal
            .checked_mul(plan.stride)
            .expect("a case index below 2^64");
        let slot = &self.shared.slots[self.id];
        slot.class.store(class, Ordering::SeqCst);
        slot.index.store(index, Ordering::SeqCst);
        slot.phase.store(GENERATING, Ordering::SeqCst);
        slot.busy_since
            .store(self.shared.now_ms().saturating_add(1), Ordering::SeqCst);
        let case = generate(plan.spec, self.shared.master, index);
        slot.phase.store(ANSWERING, Ordering::SeqCst);
        let ours = ours_answers(&case, self.shared.canary);
        let model = model::view(&case);
        slot.busy_since.store(0, Ordering::SeqCst);
        slot.phase.store(IDLE, Ordering::SeqCst);
        Work {
            class,
            index,
            case,
            ours,
            model,
        }
    }

    /// A new oracle for this worker, its `build_info` checked and its
    /// health shown to the monitor.
    fn spawn<T: Payload>(
        &self,
        window: usize,
        flush_every: usize,
        on_case: impl FnMut(T, Vec<Reply>) + Send + 'static,
    ) -> Result<OraclePipe<T>, String> {
        let cfg = self.shared.pipe_config(self.id, window, flush_every);
        let pipe = match OraclePipe::spawn(&cfg, on_case) {
            Ok(pipe) => pipe,
            Err(PipeFailure::Spawn(e)) => {
                return Err(format!("worker {}: the oracle did not start: {e}", self.id));
            }
            Err(PipeFailure::Oracle { fault, .. }) => {
                return Err(format!(
                    "worker {}: the oracle failed at start: {fault}",
                    self.id
                ));
            }
        };
        self.shared.check_build_info(pipe.build_info())?;
        *lock(&self.shared.slots[self.id].health) = Some(pipe.health());
        Ok(pipe)
    }

    /// The `on_case` of this worker's pipes: compare and count.
    fn on_case(&self) -> impl FnMut(Work, Vec<Reply>) + Send + 'static {
        let shared = Arc::clone(&self.shared);
        let id = self.id;
        move |work: Work, replies: Vec<Reply>| {
            let result = compare(&work.case, &work.ours, &replies, &work.model);
            let mut totals = lock(&shared.slots[id].totals);
            shared.account(id, &mut totals, &work, &result, Some(&replies), None);
        }
    }

    fn submit(&mut self, work: Work) -> Result<(), String> {
        if self.pipe.is_none() {
            let on_case = self.on_case();
            self.pipe = Some(self.spawn(
                self.shared.pipe.window,
                self.shared.pipe.flush_every,
                on_case,
            )?);
        }
        let pipe = self.pipe.as_mut().expect("spawned above");
        match pipe.submit(work) {
            Ok(()) => Ok(()),
            Err(failure) => {
                self.pipe = None;
                self.handle(failure)
            }
        }
    }

    /// Handles a failed pipe: finds the culprit, records it, and sends the
    /// cases after it to a fresh pipe.
    fn handle(&mut self, failure: PipeFailure<Work>) -> Result<(), String> {
        let (fault, unanswered) = match failure {
            PipeFailure::Spawn(e) => {
                return Err(format!("worker {}: the oracle did not start: {e}", self.id));
            }
            PipeFailure::Oracle { fault, unanswered } => (fault, unanswered),
        };
        self.faults = self.faults.saturating_add(1);
        self.shared.faults.fetch_add(1, Ordering::SeqCst);
        let ranges = index_ranges(&self.shared, &unanswered);
        if self.faults > self.shared.max_faults {
            self.shared.event(json!({
                "worker": self.id, "event": "worker-aborted", "fault": fault.to_string(),
                "stderr_tail": fault.stderr_tail(), "unanswered": ranges,
                "restarts": self.faults,
            }));
            return Err(format!(
                "worker {}: {} oracle faults, more than the {} a worker handles; the last: {fault}",
                self.id, self.faults, self.shared.max_faults
            ));
        }
        let rest = if fault.go_panic() && !unanswered.is_empty() {
            let mut unanswered = unanswered.into_iter();
            let culprit = unanswered.next().expect("checked non-empty");
            self.shared.event(json!({
                "worker": self.id, "event": "oracle-fault", "fault": fault.to_string(),
                "stderr_tail": fault.stderr_tail(), "unanswered": ranges,
                "culprit": { "class": self.shared.plans[culprit.class].spec.name, "index": culprit.index, "how": "go-panic" },
                "restarts": self.faults,
            }));
            self.record_culprit(&culprit, &fault, None);
            unanswered.collect()
        } else {
            self.isolate(&fault, unanswered, ranges)?
        };
        for work in rest {
            self.submit(work)?;
        }
        Ok(())
    }

    /// Resubmits `unanswered` one case at a time to a fresh oracle; the
    /// first that fails is the culprit, confirmed alone.  Returns the cases
    /// after it.
    fn isolate(
        &mut self,
        fault: &OracleFault,
        unanswered: Vec<Work>,
        ranges: Vec<Value>,
    ) -> Result<Vec<Work>, String> {
        let mut queue: VecDeque<Work> = unanswered.into();
        let on_case = self.on_case();
        let mut serial = Some(self.spawn(0, 1, on_case)?);
        let failure = loop {
            let Some(work) = queue.pop_front() else {
                break serial.take().expect("live").finish().err();
            };
            if let Err(failure) = serial.as_mut().expect("live").submit(work) {
                break Some(failure);
            }
        };
        drop(serial);
        match failure {
            None => {
                self.shared.not_reproduced.fetch_add(1, Ordering::SeqCst);
                self.shared.event(json!({
                    "worker": self.id, "event": "oracle-fault-not-reproduced",
                    "fault": fault.to_string(), "stderr_tail": fault.stderr_tail(),
                    "unanswered": ranges, "culprit": null, "restarts": self.faults,
                }));
                Ok(Vec::new())
            }
            Some(PipeFailure::Spawn(e)) => Err(format!(
                "worker {}: the isolation oracle did not start: {e}",
                self.id
            )),
            Some(PipeFailure::Oracle {
                fault: found,
                unanswered,
            }) => {
                let mut unanswered = unanswered.into_iter();
                let culprit = unanswered
                    .next()
                    .expect("a serial pipe fails holding the case it was answering");
                let mut rest: Vec<Work> = unanswered.collect();
                rest.extend(queue);
                let reproduced = self.confirm(&culprit, &found)?;
                self.shared.event(json!({
                    "worker": self.id, "event": "oracle-fault", "fault": fault.to_string(),
                    "stderr_tail": fault.stderr_tail(), "unanswered": ranges,
                    "culprit": {
                        "class": self.shared.plans[culprit.class].spec.name, "index": culprit.index,
                        "how": "isolation", "fault": found.to_string(), "reproduced": reproduced,
                    },
                    "restarts": self.faults,
                }));
                self.record_culprit(&culprit, &found, Some(reproduced));
                Ok(rest)
            }
        }
    }

    /// Runs the culprit alone on another fresh oracle: whether it fails the
    /// same way.
    fn confirm(&self, culprit: &Work, fault: &OracleFault) -> Result<bool, String> {
        let mut pipe = self.spawn(0, 1, |_: Probe, _: Vec<Reply>| {})?;
        let failure = match pipe.submit(Probe(culprit.case.requests.clone())) {
            Ok(()) => pipe.finish().err(),
            Err(failure) => Some(failure),
        };
        match failure {
            None => Ok(false),
            Some(PipeFailure::Oracle { fault: again, .. }) => Ok(again.same_kind(fault)),
            Some(PipeFailure::Spawn(e)) => Err(format!(
                "worker {}: the confirmation oracle did not start: {e}",
                self.id
            )),
        }
    }

    fn record_culprit(&self, culprit: &Work, fault: &OracleFault, reproduced: Option<bool>) {
        let result = CaseResult::oracle_failure(
            culprit.case.requests.len(),
            &culprit.ours,
            category_of(fault),
            fault.to_string(),
        );
        let mut totals = lock(&self.shared.slots[self.id].totals);
        self.shared.account(
            self.id,
            &mut totals,
            culprit,
            &result,
            None,
            Some((fault, reproduced)),
        );
    }
}

/// Watches the workers: kills an oracle that owes answers for longer than
/// the hang timeout, ends the run on a case dcroxide does not finish within
/// it, and reports progress.
fn monitor(shared: &Shared, done: &mpsc::Receiver<()>, progress_every: Option<Duration>) {
    let tick = shared
        .hang_timeout
        .checked_div(4)
        .unwrap_or_default()
        .clamp(Duration::from_millis(50), Duration::from_secs(1));
    let mut last_progress = (Instant::now(), 0u64);
    loop {
        match done.recv_timeout(tick) {
            Err(RecvTimeoutError::Timeout) => {}
            Ok(()) | Err(RecvTimeoutError::Disconnected) => return,
        }
        let now = shared.now_ms();
        let timeout = u64::try_from(shared.hang_timeout.as_millis()).unwrap_or(u64::MAX);
        for (k, slot) in shared.slots.iter().enumerate() {
            let health = lock(&slot.health).clone();
            if let Some(health) = health
                && health
                    .stalled_for()
                    .is_some_and(|d| d >= shared.hang_timeout)
            {
                health.kill_hung();
            }
            let busy = slot.busy_since.load(Ordering::SeqCst);
            if busy != 0 && now.saturating_sub(busy.saturating_sub(1)) >= timeout {
                ours_hung(shared, k);
            }
        }
        if let Some(every) = progress_every
            && last_progress.0.elapsed() >= every
        {
            last_progress = progress(shared, last_progress);
        }
    }
}

/// One progress report; returns when it was made and the requests then.
fn progress(shared: &Shared, (then, requests_then): (Instant, u64)) -> (Instant, u64) {
    let now = Instant::now();
    let elapsed = shared.start.elapsed().as_secs();
    let cases = shared.cases.load(Ordering::SeqCst);
    let requests = shared.requests.load(Ordering::SeqCst);
    let interval = now.duration_since(then).as_secs_f64();
    let rate = if interval > 0.0 {
        requests.saturating_sub(requests_then) as f64 / interval
    } else {
        0.0
    };
    let disagreements = shared.disagreements.load(Ordering::SeqCst);
    let faults = shared.faults.load(Ordering::SeqCst);
    let behind = shared
        .plans
        .iter()
        .zip(&shared.completed)
        .map(|(plan, done)| (plan, done.load(Ordering::SeqCst)))
        .filter(|(plan, done)| *done < plan.target)
        .min_by(|(a, x), (b, y)| {
            (*x as f64 / a.weight as f64).total_cmp(&(*y as f64 / b.weight as f64))
        })
        .map(|(plan, done)| {
            let of = if plan.target == u64::MAX {
                plan.weight
            } else {
                plan.target
            };
            format!(
                "; furthest behind: {} {}/{}",
                plan.spec.name,
                thousands(done),
                thousands(of)
            )
        })
        .unwrap_or_default();
    eprintln!(
        "[{elapsed:>5}s] {} cases, {} req/s, {disagreements} disagreements, {faults} oracle faults{behind}",
        thousands(cases),
        thousands(rate.round() as u64),
    );
    let mut row = format!("{elapsed}\t{cases}\t{requests}\t{rate:.0}\t{disagreements}\t{faults}");
    for done in &shared.completed {
        let _ = write!(row, "\t{}", done.load(Ordering::SeqCst));
    }
    row.push('\n');
    shared.recorder.progress(&row);
    (now, requests)
}

/// `n` with commas between thousands.
pub fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len().saturating_add(digits.len() / 3));
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len().saturating_sub(i)).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// dcroxide has not returned from a case within the hang timeout: record
/// it ([`hung_case`]), write the summary as aborted, and end the process
/// with exit code 3, since a thread stuck in a loop cannot be stopped from
/// outside.
fn ours_hung(shared: &Shared, worker: usize) -> ! {
    let (work, result) = hung_case(shared, &shared.slots[worker]);
    let detail = result
        .failures
        .first()
        .map(|f| f.detail.clone())
        .unwrap_or_default();
    eprintln!("sigsoak: {detail}; aborting");
    let mut scratch = Totals::new(shared.plans.len());
    shared.account(worker, &mut scratch, &work, &result, None, None);
    shared.abort(detail);
    let summary = summarize(shared);
    let _ = shared.recorder.write_final(&summary);
    std::process::exit(3);
}

/// The record of the case `slot`'s producer has not finished within the
/// hang timeout, a disagreement of category `ours-hung`.  When dcroxide
/// was answering it (the generator had returned), the case is regenerated,
/// which returns again since it is deterministic, and every answer of
/// dcroxide's is missing; when the generator had not returned, it is a case
/// of variant `generator-hung` with no requests.
fn hung_case(shared: &Shared, slot: &Slot) -> (Work, CaseResult) {
    let class = slot.class.load(Ordering::SeqCst);
    let index = slot.index.load(Ordering::SeqCst);
    let spec = shared.plans[class].spec;
    let generated = slot.phase.load(Ordering::SeqCst) == ANSWERING;
    let case = if generated {
        generate(spec, shared.master, index)
    } else {
        Case {
            variant: Cow::Borrowed("generator-hung"),
            requests: Vec::new(),
            intents: Vec::new(),
            consistency: crate::class::Consistency::None,
            tags: crate::class::Tags::NONE,
        }
    };
    let detail = format!(
        "{} did not finish {} case {index} within {:?}",
        if generated {
            "dcroxide"
        } else {
            "the generator"
        },
        spec.name,
        shared.hang_timeout
    );
    let n = case.requests.len();
    let work = Work {
        class,
        index,
        ours: vec![Err("did not return".to_owned()); n],
        model: ModelView::default(),
        case,
    };
    let result = CaseResult {
        status: Status::Disagree,
        failures: vec![Failure {
            category: Category::OursHung,
            request: None,
            detail,
        }],
        theirs: vec![None; n],
        kind_compared: vec![false; n],
    };
    (work, result)
}

/// Runs `cfg` to completion and returns its summary, having written its
/// record when it has an output directory.  An error is a configuration
/// that cannot run, or an output directory that cannot be written.
pub fn run(cfg: &RunConfig) -> Result<Summary, String> {
    if cfg.classes.is_empty() {
        return Err("no class selected".to_owned());
    }
    if cfg.workers == 0 || cfg.flush_every == 0 {
        return Err("workers and flush batch must be at least 1".to_owned());
    }
    let names: Vec<&str> = cfg.classes.iter().map(|c| c.name).collect();
    let recorder = Recorder::create(cfg.out.as_deref(), cfg.manifest.clone(), &names)
        .map_err(|e| format!("cannot write the output directory: {e}"))?;
    let plans = plans(&cfg.classes, cfg.mode);
    let n = plans.len();
    let start = Instant::now();
    let deadline = match cfg.mode {
        Mode::Budget { duration, .. } => start.checked_add(duration),
        _ => None,
    };
    let shared = Arc::new(Shared {
        master: cfg.master,
        mode: cfg.mode,
        claimed: (0..n).map(|_| AtomicU64::new(0)).collect(),
        completed: (0..n).map(|_| AtomicU64::new(0)).collect(),
        stopped: (0..n).map(|_| AtomicBool::new(false)).collect(),
        plans,
        start,
        deadline,
        halt: AtomicBool::new(false),
        abort_reason: Mutex::new(None),
        recorder,
        slots: (0..cfg.workers)
            .map(|_| Slot {
                health: Mutex::new(None),
                busy_since: AtomicU64::new(0),
                phase: AtomicU8::new(IDLE),
                class: AtomicUsize::new(0),
                index: AtomicU64::new(0),
                totals: Mutex::new(Totals::new(n)),
            })
            .collect(),
        build_info: OnceLock::new(),
        pipe: PipeConfig {
            args: cfg.oracle_args.clone(),
            window: cfg.window,
            flush_every: cfg.flush_every,
            gomaxprocs: cfg.gomaxprocs,
            spawn_timeout: cfg.hang_timeout,
            ..PipeConfig::new(cfg.oracle.clone())
        },
        max_faults: cfg.max_faults,
        hang_timeout: cfg.hang_timeout,
        stop_on_disagreement: cfg.stop_on_disagreement,
        kind_coverage: cfg.kind_coverage,
        replay_program: cfg.replay_program.clone(),
        canary: cfg.canary,
        cases: AtomicU64::new(0),
        requests: AtomicU64::new(0),
        disagreements: AtomicU64::new(0),
        faults: AtomicU64::new(0),
        not_reproduced: AtomicU64::new(0),
        categories: Mutex::new(BTreeMap::new()),
        notes: Mutex::new(Vec::new()),
        events: Mutex::new(Vec::new()),
    });

    let (done_tx, done_rx) = mpsc::channel();
    let watcher = {
        let shared = Arc::clone(&shared);
        let every = cfg.progress_every;
        thread::Builder::new()
            .name("sigsoak-monitor".to_owned())
            .spawn(move || monitor(&shared, &done_rx, every))
            .map_err(|e| format!("cannot start the monitor: {e}"))?
    };
    let mut workers = Vec::with_capacity(cfg.workers);
    for id in 0..cfg.workers {
        let worker = Worker {
            id,
            shared: Arc::clone(&shared),
            pipe: None,
            faults: 0,
        };
        match thread::Builder::new()
            .name(format!("sigsoak-w{id}"))
            .spawn(move || worker.run())
        {
            Ok(handle) => workers.push(handle),
            Err(e) => shared.abort(format!("cannot start worker {id}: {e}")),
        }
    }
    for (id, handle) in workers.into_iter().enumerate() {
        if let Err(panic) = handle.join() {
            shared.abort(format!(
                "worker {id} panicked: {}",
                panic_message(panic.as_ref())
            ));
        }
    }
    drop(done_tx);
    let _ = watcher.join();
    if cfg.progress_every.is_some() {
        progress(&shared, (shared.start, 0));
    }
    let summary = summarize(&shared);
    shared
        .recorder
        .write_final(&summary)
        .map_err(|e| format!("cannot write the run's record: {e}"))?;
    Ok(summary)
}

/// The summary of what `shared` holds now.
fn summarize(shared: &Shared) -> Summary {
    let mut totals = Totals::new(shared.plans.len());
    for slot in &shared.slots {
        totals.merge(lock(&slot.totals).clone());
    }
    let aborted = shared.halt.load(Ordering::SeqCst);
    if !aborted {
        for (k, plan) in shared.plans.iter().enumerate() {
            let claimed = shared.claimed[k].load(Ordering::SeqCst);
            let completed = totals.classes[k].completed;
            if claimed != completed {
                shared.abort(format!(
                    "{}: {completed} cases completed of {claimed} claimed",
                    plan.spec.name
                ));
            }
        }
    }
    let classes: Vec<ClassSummary> = shared
        .plans
        .iter()
        .zip(&totals.classes)
        .map(|(plan, t)| ClassSummary {
            name: plan.spec.name,
            family: plan.spec.family,
            floor: plan.spec.size.floor(),
            target: (plan.target != u64::MAX).then_some(plan.target),
            completed: t.completed,
            statuses: t.statuses,
            requests: t.requests,
            fallbacks: t.fallbacks,
            whole: plan
                .spec
                .size
                .finite()
                .is_some_and(|size| plan.stride == 1 && t.completed == size),
            first_disagree: t.first_disagree,
            digest: t.digest.clone(),
        })
        .collect();
    let mixes: Vec<MixResult> = shared
        .plans
        .iter()
        .zip(&totals.classes)
        .zip(&classes)
        .flat_map(|((plan, t), c)| evaluate_mixes(plan.spec, t, c.whole))
        .collect();
    let categories = lock(&shared.categories).clone();
    let disagreements = shared.disagreements.load(Ordering::SeqCst);
    let cases: u64 = classes.iter().map(|c| c.completed).sum();
    let mut criteria = Vec::new();
    // A run that completed no case compared nothing: it cannot pass.
    criteria.push(Criterion {
        name: "1 disagreements and panics",
        state: if disagreements == 0 && cases > 0 {
            CriterionState::Pass
        } else {
            CriterionState::Fail
        },
        detail: if cases == 0 {
            "no case completed, so nothing was compared".to_owned()
        } else {
            format!("{disagreements} cases disagreed")
        },
    });
    // The floors are judged in a --floors run at scale 1, and in a budget
    // run at the share of them its min_scale names, finite classes whole.
    let floors = match shared.mode {
        Mode::Floors { scale: 1.0 } => Some((
            classes.iter().map(|c| c.floor).collect::<Vec<u64>>(),
            "every class reached its floor".to_owned(),
            "below the floor".to_owned(),
        )),
        Mode::Budget {
            min_scale: Some(share),
            ..
        } => Some((
            shared
                .plans
                .iter()
                .map(|p| {
                    p.spec
                        .size
                        .finite()
                        .unwrap_or_else(|| scaled_floor(p.spec.size.floor(), share))
                })
                .collect(),
            format!("every class reached its floor times {share} (finite classes whole)"),
            format!("below its floor times {share}"),
        )),
        _ => None,
    };
    criteria.push(match floors {
        Some((required, reached, below)) => {
            let short: Vec<String> = classes
                .iter()
                .zip(required)
                .filter(|&(c, n)| c.completed < n)
                .map(|(c, n)| format!("{} {}/{n}", c.name, c.completed))
                .collect();
            Criterion {
                name: "2 floors",
                state: if short.is_empty() {
                    CriterionState::Pass
                } else {
                    CriterionState::Fail
                },
                detail: if short.is_empty() {
                    reached
                } else {
                    format!("{below}: {}", short.join(", "))
                },
            }
        }
        None => Criterion {
            name: "2 floors",
            state: CriterionState::NotEvaluated,
            detail: "neither a --floors run at scale 1 nor a --budget run with --min-scale"
                .to_owned(),
        },
    });
    let intent_failures = categories.get(&Category::Intent).copied().unwrap_or(0);
    let mix_failures: Vec<String> = mixes
        .iter()
        .filter(|m| m.pass == Some(false))
        .map(|m| format!("{} {} {}", m.class, m.check, m.observed))
        .collect();
    criteria.push(Criterion {
        name: "3 intents and mixes",
        state: if intent_failures == 0 && mix_failures.is_empty() {
            CriterionState::Pass
        } else {
            CriterionState::Fail
        },
        detail: format!(
            "{intent_failures} intent failures; {} mix checks failed{}",
            mix_failures.len(),
            if mix_failures.is_empty() {
                String::new()
            } else {
                format!(": {}", mix_failures.join(", "))
            }
        ),
    });
    criteria.push(if shared.kind_coverage {
        let families: Vec<Family> = classes.iter().map(|c| c.family).collect();
        let short: Vec<String> = REACHABLE_KINDS
            .iter()
            .filter(|(family, _, _)| families.contains(family))
            .filter_map(|&(_, cmd, kind)| {
                let seen = totals
                    .kinds
                    .get(&(cmd, kind.to_owned()))
                    .map_or(0, |k| k.theirs);
                (seen < 10_000).then(|| format!("{} {kind} {seen}", cmd.name()))
            })
            .collect();
        Criterion {
            name: "4 kind coverage",
            state: if short.is_empty() {
                CriterionState::Pass
            } else {
                CriterionState::Fail
            },
            detail: if short.is_empty() {
                "every reachable kind seen at least 10^4 times".to_owned()
            } else {
                format!("seen fewer than 10^4 times: {}", short.join(", "))
            },
        }
    } else {
        Criterion {
            name: "4 kind coverage",
            state: CriterionState::NotEvaluated,
            detail: "decided in gate-eligible runs only".to_owned(),
        }
    });
    let abort_reason = lock(&shared.abort_reason).clone();
    let status = if abort_reason.is_some() {
        RunStatus::Aborted
    } else if criteria.iter().any(|c| c.state == CriterionState::Fail) {
        RunStatus::Failed
    } else {
        RunStatus::Passed
    };
    Summary {
        status,
        master: shared.master,
        mode: shared.mode,
        elapsed: shared.start.elapsed(),
        cases,
        requests: classes.iter().map(|c| c.requests).sum(),
        classes,
        mixes,
        criteria,
        disagreements,
        disagreements_unwritten: shared.recorder.unwritten(),
        categories,
        notes: lock(&shared.notes).clone(),
        events: lock(&shared.events).clone(),
        oracle_faults: shared.faults.load(Ordering::SeqCst),
        faults_not_reproduced: shared.not_reproduced.load(Ordering::SeqCst),
        build_info: shared.build_info.get().cloned(),
        abort_reason,
        canary: shared.canary,
        totals,
    }
}

/// Everything about one case, replayed.
#[derive(Debug, Clone)]
pub struct ReplayReport {
    /// The class.
    pub class: &'static str,
    /// The case index.
    pub index: u64,
    /// The master seed.
    pub master: u64,
    /// The case's seed.
    pub case_seed: u64,
    /// The case.
    pub case: Case,
    /// dcroxide's answers.
    pub ours: Vec<Result<OursAnswer, String>>,
    /// The models' view.
    pub model: ModelView,
    /// The oracle's replies; empty when it failed on the case.
    pub replies: Vec<Reply>,
    /// The oracle's fault, when it failed on the case.
    pub fault: Option<OracleFault>,
    /// The comparison.
    pub result: CaseResult,
    /// The case's digest leaf.
    pub leaf: [u8; 32],
    /// What answered in dcroxide's place, if anything.
    pub canary: Option<StandIn>,
}

/// Regenerates case `index` of `class` under `seed`, answers it on both
/// sides with a fresh oracle, and compares.  `canary` names a canary (by
/// name or id) or the model baseline to stand in for dcroxide on the
/// commands it covers.
pub fn replay(
    seed: u64,
    class: &str,
    index: u64,
    canary: Option<&str>,
    oracle: &Path,
) -> Result<ReplayReport, String> {
    let canary = canary
        .map(|name| {
            find_stand_in(name)
                .ok_or_else(|| format!("no canary {name} (sigsoak list --canaries prints them)"))
        })
        .transpose()?;
    let spec =
        find_class(class).ok_or_else(|| format!("no class {class} (sigsoak list prints them)"))?;
    if let Some(size) = spec.size.finite()
        && index >= size
    {
        return Err(format!("{class} has {size} cases; {index} is past its end"));
    }
    let case = generate(spec, seed, index);
    let ours = ours_answers(&case, canary);
    let model = model::view(&case);
    let replies: Arc<Mutex<Option<Vec<Reply>>>> = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&replies);
    let cfg = PipeConfig {
        window: 0,
        flush_every: 1,
        ..PipeConfig::new(oracle.to_path_buf())
    };
    let mut pipe = spawn_pinned(&cfg, move |_: Probe, r: Vec<Reply>| {
        *lock(&slot) = Some(r);
    })?;
    let failure = match pipe.submit(Probe(case.requests.clone())) {
        Ok(()) => pipe.finish().err(),
        Err(failure) => Some(failure),
    };
    let (replies, fault, result) = match failure {
        None => {
            let replies = lock(&replies).take().unwrap_or_default();
            let result = compare(&case, &ours, &replies, &model);
            (replies, None, result)
        }
        Some(PipeFailure::Oracle { fault, .. }) => {
            let result = CaseResult::oracle_failure(
                case.requests.len(),
                &ours,
                category_of(&fault),
                fault.to_string(),
            );
            (Vec::new(), Some(fault), result)
        }
        Some(PipeFailure::Spawn(e)) => return Err(format!("the oracle did not start: {e}")),
    };
    let leaf = leaf(
        spec.name,
        index,
        &case.requests,
        &result.theirs,
        result.status,
    );
    Ok(ReplayReport {
        class: spec.name,
        index,
        master: seed,
        case_seed: crate::class::case_seed(seed, spec.name, index),
        case,
        ours,
        model,
        replies,
        fault,
        result,
        leaf,
        canary,
    })
}

/// One case run as a run's worker runs it, with the oracle's replies.
#[derive(Debug, Clone)]
pub struct AnsweredCase {
    /// The case index.
    pub index: u64,
    /// The case.
    pub case: Case,
    /// The oracle's reply to each request.
    pub replies: Vec<Reply>,
    /// dcroxide's answers held against the replies and the intents.
    pub result: CaseResult,
}

/// A fresh oracle run as `cfg` says, its pin check passed, calling
/// `on_case` as [`OraclePipe::spawn`] does: replay's and
/// [`answer_cases`]'s start, each failure as text.
fn spawn_pinned<T: Payload>(
    cfg: &PipeConfig,
    on_case: impl FnMut(T, Vec<Reply>) + Send + 'static,
) -> Result<OraclePipe<T>, String> {
    let pipe = OraclePipe::spawn(cfg, on_case).map_err(|f| match f {
        PipeFailure::Spawn(e) => format!("the oracle did not start: {e}"),
        PipeFailure::Oracle { fault, .. } => format!("the oracle failed at start: {fault}"),
    })?;
    let pin = check_pin(pipe.build_info());
    if !pin.consistent() {
        return Err(format!(
            "the oracle's pin check failed: {}",
            pin.problems().join("; ")
        ));
    }
    Ok(pipe)
}

/// Cases `indices` of `class` under `master`, in index order, each run as
/// a run's worker runs it: generated, answered by dcroxide (each request
/// under `catch_unwind`) and by the models, sent to one fresh oracle run
/// as `pipe` says, and compared.  An oracle that does not start, links
/// another specification or fails on a case is an error that names the
/// class, and nothing is isolated: this answers a few cases for a record,
/// not a soak.
pub fn answer_cases(
    class: &'static ClassSpec,
    master: u64,
    indices: Range<u64>,
    pipe: &PipeConfig,
) -> Result<Vec<AnsweredCase>, String> {
    let answered: Arc<Mutex<Vec<AnsweredCase>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&answered);
    let mut pipe = spawn_pinned(pipe, move |work: Work, replies: Vec<Reply>| {
        let result = compare(&work.case, &work.ours, &replies, &work.model);
        lock(&sink).push(AnsweredCase {
            index: work.index,
            case: work.case,
            replies,
            result,
        });
    })
    .map_err(|e| format!("{}: {e}", class.name))?;
    let failed = |failure: PipeFailure<Work>| match failure {
        PipeFailure::Spawn(e) => format!("{}: the oracle did not start: {e}", class.name),
        PipeFailure::Oracle { fault, unanswered } => format!(
            "{}: the oracle failed with {} cases unanswered{}: {fault}",
            class.name,
            unanswered.len(),
            unanswered
                .first()
                .map(|w| format!(" from case {}", w.index))
                .unwrap_or_default()
        ),
    };
    for index in indices {
        let case = generate(class, master, index);
        let ours = ours_answers(&case, None);
        let model = model::view(&case);
        // A worker's `class` numbers the class among a run's; here there is
        // one.
        pipe.submit(Work {
            class: 0,
            index,
            case,
            ours,
            model,
        })
        .map_err(failed)?;
    }
    pipe.finish().map_err(failed)?;
    let mut answered = std::mem::take(&mut *lock(&answered));
    answered.sort_by_key(|a| a.index);
    Ok(answered)
}

/// The variable that overrides every class's per-PR case count.
pub const CASES_VAR: &str = "DCROXIDE_SIGDIFF_CASES";

/// The configuration the per-PR tests run under: one worker, window 64,
/// flush batch 16, hang timeout 60 s, a master seed printed for replay
/// under `label` (and taken from `DCROXIDE_TEST_SEED` when set), no output
/// files, dcroxide answering; no class yet, each at its per-PR count.
/// `None` when the oracle is unavailable and the policy says skip.
pub fn test_config(label: &str) -> Option<RunConfig> {
    let oracle = oracle_bin_or_skip()?;
    let master = SplitMix64::from_entropy(&format!("sigdiff {label}")).0;
    let mut cfg = RunConfig::new(master, Vec::new(), Mode::PerPr { cases: None }, oracle);
    cfg.workers = 1;
    cfg.window = 64;
    cfg.flush_every = 16;
    cfg.hang_timeout = Duration::from_secs(60);
    Some(cfg)
}

/// Runs class `name` as the per-PR tests do ([`test_config`]), at its
/// `pr_cases` cases (or `DCROXIDE_SIGDIFF_CASES`).  `None` when the oracle
/// is unavailable and the policy says skip.  Panics on an unknown class or
/// a run that cannot start.
pub fn run_class_for_test(name: &str) -> Option<Summary> {
    let spec = find_class(name).unwrap_or_else(|| panic!("no class {name}"));
    let mut cfg = test_config(name)?;
    let cases = std::env::var(CASES_VAR).ok().map(|v| {
        v.trim()
            .parse::<u64>()
            .unwrap_or_else(|_| panic!("{CASES_VAR}={v:?} is not a count"))
    });
    cfg.classes = vec![spec];
    cfg.mode = Mode::PerPr { cases };
    Some(run(&cfg).unwrap_or_else(|e| panic!("{name}: {e}")))
}

/// How many cases each part of a canary run takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanaryVolume {
    /// The soak's canary run: `cases` of every class the model baseline
    /// covers, at most [`CANARY_BOUND`] of each primary, whatever `cases`
    /// is, and `cases` of every other class of a canary's commands; finite
    /// classes whole.
    Soak {
        /// Cases per class.
        cases: u64,
    },
    /// The per-PR test's: 16 cases of every class the model baseline
    /// covers, each canary's per-PR count of its primary, and 4 cases of
    /// every other class of its commands; finite classes of at most 128
    /// elements whole, as in every per-PR run.
    PerPr,
}

impl CanaryVolume {
    fn baseline(self) -> Mode {
        match self {
            CanaryVolume::Soak { cases } => Mode::Cases(cases),
            CanaryVolume::PerPr => Mode::PerPr { cases: Some(16) },
        }
    }

    fn primary(self, canary: &Canary) -> Mode {
        match self {
            CanaryVolume::Soak { .. } => Mode::Cases(CANARY_BOUND),
            CanaryVolume::PerPr => Mode::PerPr {
                cases: Some(canary.primary_pr_cases()),
            },
        }
    }

    fn others(self) -> Mode {
        match self {
            CanaryVolume::Soak { cases } => Mode::Cases(cases),
            CanaryVolume::PerPr => Mode::PerPr { cases: Some(4) },
        }
    }
}

/// What one canary did in a canary run.
#[derive(Debug, Clone)]
pub struct CanaryOutcome {
    /// The canary.
    pub canary: &'static Canary,
    /// Cases of its primary completed.
    pub primary_cases: u64,
    /// The lowest index of its primary at which it disagreed with dcrd;
    /// the primary's completed cases are a prefix, so it is the first,
    /// whatever the worker count.  `None` when it never did.
    pub first_index: Option<u64>,
    /// Every class it disagreed with dcrd in, with how many cases, its
    /// primary first.
    pub fired: Vec<(&'static str, u64)>,
    /// Of those, the classes outside its primary and footprint.
    pub unexpected: Vec<(&'static str, u64)>,
    /// The first disagreement kept of each unexpected class.
    pub notes: Vec<String>,
    /// Anything else that went wrong: a case that panicked, an oracle
    /// failure, a class that completed nothing, a part that stopped early.
    pub problems: Vec<String>,
    /// Whether a part of it stopped early.
    pub aborted: bool,
}

impl CanaryOutcome {
    /// Whether it fired in its primary at an index below [`CANARY_BOUND`],
    /// nowhere outside its footprint, and nothing else went wrong.
    pub fn pass(&self) -> bool {
        self.first_index.is_some_and(|i| i < CANARY_BOUND)
            && self.unexpected.is_empty()
            && self.problems.is_empty()
    }
}

/// What a canary run found.
#[derive(Debug, Clone)]
pub struct CanaryReport {
    /// The master seed.
    pub master: u64,
    /// The model baseline's run; `None` when no canary selected breaks a
    /// model.
    pub baseline: Option<Summary>,
    /// Each canary's outcome, in registry order.
    pub outcomes: Vec<CanaryOutcome>,
}

impl CanaryReport {
    /// Whether the model baseline agreed with dcrd everywhere, held every
    /// intent and mix, and ran to the end (or did not run).
    pub fn baseline_pass(&self) -> bool {
        self.baseline
            .as_ref()
            .is_none_or(|s| s.status == RunStatus::Passed)
    }

    /// Whether the baseline passed and every canary passed.
    pub fn pass(&self) -> bool {
        self.baseline_pass() && self.outcomes.iter().all(CanaryOutcome::pass)
    }

    /// Whether any part stopped early.
    pub fn aborted(&self) -> bool {
        self.baseline
            .as_ref()
            .is_some_and(|s| s.status == RunStatus::Aborted)
            || self.outcomes.iter().any(|o| o.aborted)
    }

    /// `passed`, `failed` or `aborted`.
    pub fn status(&self) -> RunStatus {
        if self.aborted() {
            RunStatus::Aborted
        } else if self.pass() {
            RunStatus::Passed
        } else {
            RunStatus::Failed
        }
    }

    /// `summary.tsv`: per canary its primary, the first index it was
    /// caught at, the classes it fired in and those outside its footprint,
    /// with counts, and whether it passed; the model baseline first, with
    /// the classes it disagreed in.
    pub fn summary_tsv(&self) -> String {
        let verdict = |pass: bool| if pass { "pass" } else { "fail" };
        let mut s = String::from(
            "id\tcanary\tprimary\tfirst_index\tprimary_cases\tfired\tunexpected\tpass\tproblems\n",
        );
        if let Some(baseline) = &self.baseline {
            let fired: Vec<(&str, u64)> = baseline
                .classes
                .iter()
                .filter(|c| c.statuses[1..].iter().any(|&n| n > 0))
                .map(|c| (c.name, c.statuses[1..].iter().sum()))
                .collect();
            let _ = writeln!(
                s,
                "-\t{}\t-\t-\t-\t{}\t{}\t{}\t{}",
                MODEL_BASELINE.name,
                classes(&fired),
                classes(&fired),
                verdict(self.baseline_pass()),
                baseline.problems().join("; ")
            );
        }
        for o in &self.outcomes {
            let _ = writeln!(
                s,
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                o.canary.id,
                o.canary.name,
                o.canary.primary,
                o.first_index
                    .map_or_else(|| "-".to_owned(), |i| i.to_string()),
                o.primary_cases,
                classes(&o.fired),
                classes(&o.unexpected),
                verdict(o.pass()),
                o.problems.join("; ")
            );
        }
        s
    }

    /// The report for a reader: the baseline's verdict, then one line per
    /// canary, then whatever failed.
    pub fn render(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "canary run: {}", self.status().name());
        let _ = writeln!(s, "master seed: {:#018x}", self.master);
        match &self.baseline {
            Some(b) => {
                let _ = writeln!(
                    s,
                    "{}: {} ({} cases of {} classes, {} disagreements)",
                    MODEL_BASELINE.name,
                    if self.baseline_pass() { "pass" } else { "FAIL" },
                    b.cases,
                    b.classes.len(),
                    b.disagreements
                );
                for problem in b.problems() {
                    let _ = writeln!(s, "  {problem}");
                }
            }
            None => {
                let _ = writeln!(s, "{}: not run", MODEL_BASELINE.name);
            }
        }
        for o in &self.outcomes {
            let caught = match o.first_index {
                None => format!(
                    "never caught in {} cases of {}",
                    o.primary_cases, o.canary.primary
                ),
                Some(i) if i >= CANARY_BOUND => format!(
                    "caught at {} case {i}, not within {} cases",
                    o.canary.primary,
                    thousands(CANARY_BOUND)
                ),
                Some(i) => format!("caught at {} case {i}", o.canary.primary),
            };
            let _ = writeln!(
                s,
                "{} {}: {} ({caught}; fired in {})",
                o.canary.id,
                o.canary.name,
                if o.pass() { "pass" } else { "FAIL" },
                classes(&o.fired)
            );
            for (class, n) in &o.unexpected {
                let _ = writeln!(s, "  outside its footprint: {class}, {n} cases");
            }
            for line in o.notes.iter().chain(&o.problems) {
                let _ = writeln!(s, "  {line}");
            }
        }
        s
    }
}

/// Classes with counts, `name:n` comma-separated, or `none`.
fn classes(list: &[(&str, u64)]) -> String {
    if list.is_empty() {
        return "none".to_owned();
    }
    list.iter()
        .map(|(class, n)| format!("{class}:{n}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// The classes the model baseline runs for `canaries`: every class that
/// sends a command one of the model canaries among them answers, in
/// registry order.
pub fn baseline_classes(canaries: &[&'static Canary]) -> Vec<&'static ClassSpec> {
    MODEL_BASELINE
        .classes()
        .into_iter()
        .filter(|class| {
            canaries.iter().any(|canary| {
                matches!(canary.rule, Rule::Model(_))
                    && class
                        .commands
                        .iter()
                        .any(|&cmd| canary.stand_in().covers(cmd))
            })
        })
        .collect()
}

/// `base` with `canary` standing in for dcroxide on `classes` in `mode`,
/// its record (if any) in the `part` subdirectory of `base.out`, its
/// manifest `base`'s with the part, the stand-in, the mode and the
/// classes.
fn canary_part(
    base: &RunConfig,
    canary: StandIn,
    classes: Vec<&'static ClassSpec>,
    mode: Mode,
    part: &str,
    stop_on_disagreement: bool,
) -> RunConfig {
    let mut cfg = base.clone();
    cfg.manifest = base.manifest.as_ref().map(|manifest| {
        let mut manifest = manifest.clone();
        manifest["part"] = json!(part);
        manifest["canary"] = json!(canary.name);
        manifest["mode"] = mode.to_json();
        manifest["classes"] = json!(
            classes
                .iter()
                .zip(class_targets(&classes, mode))
                .map(|(c, target)| json!({ "name": c.name, "target": target }))
                .collect::<Vec<_>>()
        );
        manifest
    });
    cfg.canary = Some(canary);
    cfg.classes = classes;
    cfg.mode = mode;
    cfg.out = base.out.as_ref().map(|out| out.join(part));
    cfg.stop_on_disagreement = stop_on_disagreement;
    cfg.kind_coverage = false;
    cfg
}

/// Runs the model baseline over `classes` as `volume` says: every model,
/// with no break, in dcroxide's place.  It must agree with dcrd everywhere
/// ([`CanaryReport::baseline_pass`]).
pub fn baseline_check(
    base: &RunConfig,
    classes: Vec<&'static ClassSpec>,
    volume: CanaryVolume,
) -> Result<Summary, String> {
    run(&canary_part(
        base,
        MODEL_BASELINE,
        classes,
        volume.baseline(),
        MODEL_BASELINE.name,
        false,
    ))
}

/// Runs `canary` as the canary run does: its primary until the first
/// disagreement, under the stop condition, then every other class of its
/// commands, each as `volume` says; and finds where it fired.
pub fn canary_check(
    base: &RunConfig,
    canary: &'static Canary,
    volume: CanaryVolume,
) -> Result<CanaryOutcome, String> {
    let stand_in = canary.stand_in();
    let primary = run(&canary_part(
        base,
        stand_in,
        vec![canary.primary_class()],
        volume.primary(canary),
        &format!("{}/primary", canary.name),
        true,
    ))?;
    let others = canary.others();
    let others = if others.is_empty() {
        None
    } else {
        Some(run(&canary_part(
            base,
            stand_in,
            others,
            volume.others(),
            &format!("{}/others", canary.name),
            false,
        ))?)
    };
    let mut outcome = CanaryOutcome {
        canary,
        primary_cases: 0,
        first_index: None,
        fired: Vec::new(),
        unexpected: Vec::new(),
        notes: Vec::new(),
        problems: Vec::new(),
        aborted: false,
    };
    for (part, summary) in [("primary", Some(&primary)), ("others", others.as_ref())] {
        let Some(summary) = summary else {
            continue;
        };
        if let Some(reason) = &summary.abort_reason {
            outcome.aborted = true;
            outcome
                .problems
                .push(format!("{part}: stopped early: {reason}"));
        }
        for class in &summary.classes {
            let [_, disagreed, oracle, panicked] = class.statuses;
            if disagreed > 0 {
                outcome.fired.push((class.name, disagreed));
                if !canary.may_fire_in(class.name) {
                    outcome.unexpected.push((class.name, disagreed));
                    outcome.notes.extend(
                        summary
                            .notes
                            .iter()
                            .filter(|n| n.class == class.name)
                            .take(1)
                            .map(|n| {
                                format!("{} case {}: {}", n.class, n.index, n.failures.join("; "))
                            }),
                    );
                }
            }
            if oracle > 0 {
                outcome.problems.push(format!(
                    "{}: the oracle failed on {oracle} cases",
                    class.name
                ));
            }
            if panicked > 0 {
                outcome
                    .problems
                    .push(format!("{}: {panicked} cases panicked", class.name));
            }
            if class.completed == 0 {
                outcome
                    .problems
                    .push(format!("{}: no case completed", class.name));
            }
        }
    }
    let primary = primary.class(canary.primary).expect("the primary ran");
    outcome.primary_cases = primary.completed;
    outcome.first_index = primary.first_disagree;
    Ok(outcome)
}

/// The canary run: the model baseline over the classes of the model
/// canaries among `canaries` ([`baseline_classes`]), then each canary in
/// turn ([`canary_check`]), each part with its own record under
/// `base.out` when there is one.
pub fn canary_run(
    base: &RunConfig,
    canaries: &[&'static Canary],
    volume: CanaryVolume,
) -> Result<CanaryReport, String> {
    let classes = baseline_classes(canaries);
    let baseline = if classes.is_empty() {
        None
    } else {
        Some(baseline_check(base, classes, volume)?)
    };
    let outcomes = canaries
        .iter()
        .map(|&canary| canary_check(base, canary, volume))
        .collect::<Result<Vec<_>, String>>()?;
    Ok(CanaryReport {
        master: base.master,
        baseline,
        outcomes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::class::{Consistency, Intent, Size, Tags, Tier};
    use crate::cmd::{self, Cmd};
    use std::borrow::Cow;

    fn fixed(_: &mut dyn crate::entropy::Entropy, _: u64) -> Case {
        Case {
            variant: Cow::Borrowed("v"),
            requests: vec![cmd::ecdsa_parse_der(&[])],
            intents: vec![Intent::Any],
            consistency: Consistency::None,
            tags: Tags::NONE,
        }
    }

    static SAMPLED: ClassSpec = ClassSpec {
        name: "T-sampled",
        family: Family::Der,
        commands: &[Cmd::EcdsaParseDer],
        size: Size::Sampled { floor: 10_000_000 },
        tier: Tier::A,
        generator: fixed,
        mix: &[],
        pr_cases: 48,
        doc: "",
    };

    static SMALL: ClassSpec = ClassSpec {
        name: "T-small",
        family: Family::Der,
        commands: &[Cmd::EcdsaParseDer],
        size: Size::Finite { size: 100 },
        tier: Tier::Finite,
        generator: fixed,
        mix: &[],
        pr_cases: 100,
        doc: "",
    };

    static LARGE: ClassSpec = ClassSpec {
        name: "T-large",
        family: Family::Der,
        commands: &[Cmd::EcdsaParseDer],
        size: Size::Finite { size: 2_050 },
        tier: Tier::Finite,
        generator: fixed,
        mix: &[],
        pr_cases: 64,
        doc: "",
    };

    /// A budget run of `duration` that leaves the floors unjudged.
    fn budget(duration: Duration) -> Mode {
        Mode::Budget {
            duration,
            min_scale: None,
        }
    }

    fn shared_for(classes: &[&'static ClassSpec], mode: Mode) -> Shared {
        let plans = plans(classes, mode);
        let n = plans.len();
        let start = Instant::now();
        Shared {
            master: 1,
            mode,
            claimed: (0..n).map(|_| AtomicU64::new(0)).collect(),
            completed: (0..n).map(|_| AtomicU64::new(0)).collect(),
            stopped: (0..n).map(|_| AtomicBool::new(false)).collect(),
            plans,
            start,
            deadline: match mode {
                Mode::Budget { duration, .. } => start.checked_add(duration),
                _ => None,
            },
            halt: AtomicBool::new(false),
            abort_reason: Mutex::new(None),
            recorder: Recorder::create(None, None, &[]).expect("no directory"),
            slots: Vec::new(),
            build_info: OnceLock::new(),
            pipe: PipeConfig::new(PathBuf::new()),
            max_faults: 3,
            hang_timeout: Duration::from_secs(1),
            stop_on_disagreement: false,
            kind_coverage: false,
            replay_program: "sigsoak".to_owned(),
            canary: None,
            cases: AtomicU64::new(0),
            requests: AtomicU64::new(0),
            disagreements: AtomicU64::new(0),
            faults: AtomicU64::new(0),
            not_reproduced: AtomicU64::new(0),
            categories: Mutex::new(BTreeMap::new()),
            notes: Mutex::new(Vec::new()),
            events: Mutex::new(Vec::new()),
        }
    }

    #[test]
    fn plans_follow_the_mode() {
        let classes = [&SAMPLED, &SMALL, &LARGE];
        let get = |mode| -> Vec<(u64, u64)> {
            plans(&classes, mode)
                .iter()
                .map(|p| (p.target, p.stride))
                .collect()
        };
        assert_eq!(
            get(Mode::Floors { scale: 1.0 }),
            [(10_000_000, 1), (100, 1), (2_050, 1)]
        );
        assert_eq!(
            get(Mode::Floors { scale: 0.001 }),
            [(10_000, 1), (100, 1), (2_050, 1)]
        );
        assert_eq!(get(Mode::Cases(32)), [(32, 1), (100, 1), (2_050, 1)]);
        assert_eq!(
            get(budget(Duration::ZERO)),
            [(u64::MAX, 1), (100, 1), (2_050, 1)]
        );
        assert_eq!(
            get(Mode::PerPr { cases: None }),
            [(48, 1), (100, 1), (64, 32)]
        );
        assert_eq!(
            get(Mode::PerPr { cases: Some(8) }),
            [(8, 1), (100, 1), (8, 256)]
        );
    }

    /// Claims cover each class's ordinals exactly once, in chunks, the
    /// class furthest behind first, whatever the interleaving; a stopped
    /// class and a halted run claim nothing more.
    #[test]
    fn claims_cover_every_ordinal_once() {
        let shared = shared_for(&[&SAMPLED, &SMALL, &LARGE], Mode::Cases(1_000));
        let seen: Vec<Mutex<Vec<bool>>> = shared
            .plans
            .iter()
            .map(|p| Mutex::new(vec![false; usize::try_from(p.target).expect("small")]))
            .collect();
        thread::scope(|s| {
            for _ in 0..4 {
                s.spawn(|| {
                    while let Some((k, range)) = shared.claim() {
                        assert!(range.end - range.start <= CHUNK);
                        let mut seen = lock(&seen[k]);
                        for i in range {
                            let i = usize::try_from(i).expect("small");
                            assert!(!seen[i], "ordinal {i} of class {k} claimed twice");
                            seen[i] = true;
                        }
                    }
                });
            }
        });
        for (k, seen) in seen.iter().enumerate() {
            assert!(
                lock(seen).iter().all(|&s| s),
                "class {k} has unclaimed ordinals"
            );
        }

        let shared = shared_for(&[&SAMPLED, &SMALL], Mode::Cases(1_000));
        assert_eq!(shared.claim(), Some((0, 0..64)), "both at 0: the first");
        assert_eq!(
            shared.claim(),
            Some((1, 0..64)),
            "then the one furthest behind"
        );
        shared.stopped[1].store(true, Ordering::SeqCst);
        for _ in 0..100 {
            if let Some((k, _)) = shared.claim() {
                assert_eq!(k, 0, "a stopped class is not claimed");
            }
        }
        shared.abort("test".to_owned());
        assert_eq!(shared.claim(), None);

        // A budget run takes the finite classes first, and stops at its
        // deadline.
        let shared = shared_for(&[&SAMPLED, &SMALL], budget(Duration::from_secs(3_600)));
        assert_eq!(shared.claim(), Some((1, 0..64)));
        assert_eq!(shared.claim(), Some((1, 64..100)));
        assert_eq!(shared.claim().map(|(k, _)| k), Some(0));
        let shared = shared_for(&[&SAMPLED], budget(Duration::ZERO));
        assert_eq!(shared.claim(), None);
    }

    /// A case its producer did not finish is recorded as the monitor saw
    /// it: regenerated, with every dcroxide answer missing, when dcroxide
    /// was answering it; without requests when the generator had not
    /// returned.
    #[test]
    fn a_hung_case_is_recorded_by_its_phase() {
        let shared = shared_for(&[&SAMPLED], Mode::Cases(10));
        let slot = Slot {
            health: Mutex::new(None),
            busy_since: AtomicU64::new(1),
            phase: AtomicU8::new(ANSWERING),
            class: AtomicUsize::new(0),
            index: AtomicU64::new(5),
            totals: Mutex::new(Totals::new(1)),
        };
        let (work, result) = hung_case(&shared, &slot);
        assert_eq!((work.class, work.index), (0, 5));
        assert_eq!(work.case, generate(&SAMPLED, shared.master, 5));
        assert_eq!(work.ours, [Err("did not return".to_owned())]);
        assert_eq!(result.status, Status::Disagree);
        assert_eq!(result.theirs, [None]);
        assert_eq!(result.failures.len(), 1);
        assert_eq!(result.failures[0].category, Category::OursHung);
        assert!(
            result.failures[0]
                .detail
                .starts_with("dcroxide did not finish T-sampled case 5 within"),
            "{:?}",
            result.failures[0]
        );

        slot.phase.store(GENERATING, Ordering::SeqCst);
        let (work, result) = hung_case(&shared, &slot);
        assert_eq!(work.case.variant, "generator-hung");
        assert!(work.case.requests.is_empty() && work.ours.is_empty());
        assert_eq!(result.failures[0].category, Category::OursHung);
        assert!(
            result.failures[0]
                .detail
                .starts_with("the generator did not finish T-sampled case 5 within"),
            "{:?}",
            result.failures[0]
        );
    }

    /// A run that completed no case compared nothing, and fails.
    #[test]
    fn a_run_that_completes_nothing_fails() {
        let shared = shared_for(&[&SAMPLED, &SMALL], budget(Duration::ZERO));
        assert_eq!(shared.claim(), None);
        let summary = summarize(&shared);
        assert_eq!(summary.cases, 0);
        assert_eq!(summary.status, RunStatus::Failed);
        assert_eq!(summary.criteria[0].state, CriterionState::Fail);
        assert_eq!(
            summary.criteria[0].detail,
            "no case completed, so nothing was compared"
        );
    }

    /// The floors are judged in a `--floors` run at scale 1, each class at
    /// its floor, and in a budget run that names a minimum share, each
    /// sampled class at its floor times the share (at least one case) and
    /// each finite class whole; any other run leaves them unjudged.  The
    /// manifest's mode carries the share.
    #[test]
    fn the_floors_are_judged_at_a_budget_runs_share() {
        let judge = |mode: Mode, completed: [u64; 2]| {
            let mut shared = shared_for(&[&SAMPLED, &SMALL], mode);
            let mut totals = Totals::new(2);
            for (k, n) in completed.into_iter().enumerate() {
                totals.classes[k].completed = n;
                shared.claimed[k].store(n, Ordering::SeqCst);
            }
            shared.slots.push(Slot {
                health: Mutex::new(None),
                busy_since: AtomicU64::new(0),
                phase: AtomicU8::new(IDLE),
                class: AtomicUsize::new(0),
                index: AtomicU64::new(0),
                totals: Mutex::new(totals),
            });
            let floors = summarize(&shared).criteria.swap_remove(1);
            assert_eq!(floors.name, "2 floors");
            (floors.state, floors.detail)
        };
        let share = |min_scale| Mode::Budget {
            duration: Duration::from_secs(60),
            min_scale: Some(min_scale),
        };

        assert_eq!(
            judge(share(0.5), [5_000_000, 100]),
            (
                CriterionState::Pass,
                "every class reached its floor times 0.5 (finite classes whole)".to_owned()
            )
        );
        assert_eq!(
            judge(share(0.5), [4_999_999, 99]),
            (
                CriterionState::Fail,
                "below its floor times 0.5: T-sampled 4999999/5000000, T-small 99/100".to_owned()
            )
        );
        // A share too small to round to a case still requires one.
        assert_eq!(
            judge(share(1e-9), [0, 100]),
            (
                CriterionState::Fail,
                "below its floor times 0.000000001: T-sampled 0/1".to_owned()
            )
        );
        assert_eq!(judge(share(1e-9), [1, 100]).0, CriterionState::Pass);

        assert_eq!(
            judge(Mode::Floors { scale: 1.0 }, [10_000_000, 100]),
            (
                CriterionState::Pass,
                "every class reached its floor".to_owned()
            )
        );
        assert_eq!(
            judge(Mode::Floors { scale: 1.0 }, [9_999_999, 100]),
            (
                CriterionState::Fail,
                "below the floor: T-sampled 9999999/10000000".to_owned()
            )
        );
        for mode in [
            budget(Duration::from_secs(60)),
            Mode::Floors { scale: 0.5 },
            Mode::Cases(100),
        ] {
            assert_eq!(
                judge(mode, [0, 0]).0,
                CriterionState::NotEvaluated,
                "{mode:?}"
            );
        }

        assert_eq!(
            budget(Duration::from_secs(60)).to_json(),
            json!({ "kind": "budget", "seconds": 60 })
        );
        assert_eq!(
            share(0.01).to_json(),
            json!({ "kind": "budget", "seconds": 60, "min_scale": 0.01 })
        );
    }

    /// summary.txt lists the unreachable kinds of the families a run
    /// selected, and no others.
    #[test]
    fn the_unreachable_list_follows_the_families() {
        static SCHNORR: ClassSpec = ClassSpec {
            name: "T-schnorr",
            family: Family::Schnorr,
            ..SAMPLED
        };
        let render = |classes: &[&'static ClassSpec]| {
            summarize(&shared_for(classes, budget(Duration::ZERO))).render()
        };
        let der = render(&[&SAMPLED]);
        assert!(
            der.contains("unreachable through the oracle: nothing in the families run"),
            "{der}"
        );
        assert!(!der.contains("ErrInvalidHashLen"), "{der}");
        let schnorr = render(&[&SAMPLED, &SCHNORR]);
        for (family, line) in UNREACHABLE {
            assert_eq!(
                schnorr.contains(line),
                *family == Family::Schnorr,
                "{line}:\n{schnorr}"
            );
        }
    }

    /// A canary passes when it fired in its primary within the bound,
    /// nowhere outside its footprint, and nothing else went wrong; the
    /// report passes when every canary and the baseline do, and its table
    /// says so per row.  The soak's primary runs to the bound whatever its
    /// volume.
    #[test]
    fn canary_reports_decide_by_primary_and_footprint() {
        let canary = crate::canary::find_canary("C5").expect("C5");
        let outcome = CanaryOutcome {
            canary,
            primary_cases: 48,
            first_index: Some(0),
            fired: vec![("K-wrap", 48), ("K-XTooBig", 3)],
            unexpected: Vec::new(),
            notes: Vec::new(),
            problems: Vec::new(),
            aborted: false,
        };
        assert!(outcome.pass());
        let mut report = CanaryReport {
            master: 7,
            baseline: None,
            outcomes: vec![outcome.clone()],
        };
        assert!(report.pass());
        assert_eq!(report.status(), RunStatus::Passed);
        let tsv = report.summary_tsv();
        let row = tsv.lines().nth(1).expect("a row");
        assert_eq!(
            row,
            "C5\tpubkey-reduce-mod-p\tK-wrap\t0\t48\tK-wrap:48,K-XTooBig:3\tnone\tpass\t"
        );
        assert!(report.render().contains("caught at K-wrap case 0"));

        let mut never = outcome.clone();
        never.first_index = None;
        assert!(!never.pass());
        // Caught, but not within the bound: too late, whatever the volume
        // the primary ran at.
        let mut late = outcome.clone();
        late.first_index = Some(CANARY_BOUND.saturating_sub(1));
        assert!(late.pass());
        late.first_index = Some(CANARY_BOUND);
        assert!(!late.pass());
        let rendered = CanaryReport {
            master: 7,
            baseline: None,
            outcomes: vec![late],
        }
        .render();
        assert!(
            rendered.contains("FAIL (caught at K-wrap case 10000, not within 10,000 cases;"),
            "{rendered}"
        );
        for cases in [1, 10_000, 50_000] {
            let volume = CanaryVolume::Soak { cases };
            assert_eq!(volume.primary(canary), Mode::Cases(CANARY_BOUND));
            assert_eq!(volume.baseline(), Mode::Cases(cases));
            assert_eq!(volume.others(), Mode::Cases(cases));
        }
        let mut wide = outcome.clone();
        wide.unexpected = vec![("K-valid", 1)];
        assert!(!wide.pass());
        let mut broken = outcome;
        broken.problems = vec!["K-wrap: 1 cases panicked".to_owned()];
        broken.aborted = true;
        assert!(!broken.pass());
        report.outcomes.push(wide);
        assert!(!report.pass());
        assert_eq!(report.status(), RunStatus::Failed);
        assert!(
            report
                .render()
                .contains("outside its footprint: K-valid, 1 cases")
        );
        report.outcomes.push(broken);
        assert_eq!(report.status(), RunStatus::Aborted);

        // A baseline that disagreed fails the report on its own.
        let mut summary = summarize(&shared_for(&[&SAMPLED], Mode::Cases(1)));
        summary.status = RunStatus::Failed;
        let report = CanaryReport {
            master: 7,
            baseline: Some(summary),
            outcomes: Vec::new(),
        };
        assert!(!report.baseline_pass() && !report.pass());
        assert!(report.summary_tsv().contains("\tmodel-baseline\t"));
    }

    /// The baseline runs the classes of the selected model canaries'
    /// commands, and none for a wrapper alone, even one on a model
    /// command.
    #[test]
    fn the_baseline_follows_the_model_canaries() {
        let names = |ids: &[&str]| -> Vec<&'static str> {
            let canaries: Vec<&'static Canary> = ids
                .iter()
                .map(|id| crate::canary::find_canary(id).expect("a canary"))
                .collect();
            baseline_classes(&canaries).iter().map(|c| c.name).collect()
        };
        let family = |prefix: &str| -> Vec<&'static str> {
            crate::class::CLASSES
                .iter()
                .filter(|c| c.name.starts_with(prefix))
                .map(|c| c.name)
                .collect()
        };
        assert!(names(&["C2", "C4", "C5", "C6", "C9"]).is_empty());
        assert_eq!(names(&["C1"]), family("EV-"));
        assert_eq!(names(&["C9", "C14"]), family("ER-"));
        assert_eq!(names(&["C6", "C18"]), family("SV-"));
        assert_eq!(names(&["C2", "C16"]), family("DV-"));
        let all: Vec<&'static Canary> = crate::canary::CANARIES.iter().collect();
        assert_eq!(baseline_classes(&all).len(), MODEL_BASELINE.classes().len());
    }

    #[test]
    fn thousands_separators() {
        for (n, s) in [
            (0, "0"),
            (999, "999"),
            (1_000, "1,000"),
            (12_345_678, "12,345,678"),
            (u64::MAX, "18,446,744,073,709,551,615"),
        ] {
            assert_eq!(thousands(n), s);
        }
    }

    /// A panic's message and, when a hook noted it, its place.
    #[test]
    fn panic_messages() {
        let payload: Box<dyn Any + Send> = Box::new("boom");
        assert_eq!(panic_message(payload.as_ref()), "boom");
        let payload: Box<dyn Any + Send> = Box::new(String::from("bang"));
        assert_eq!(panic_message(payload.as_ref()), "bang");
        PANIC_AT.with(|p| *p.borrow_mut() = Some("src/x.rs:1:2".to_owned()));
        let payload: Box<dyn Any + Send> = Box::new(7u8);
        assert_eq!(
            panic_message(payload.as_ref()),
            "a panic with a payload that is not text (at src/x.rs:1:2)"
        );
        assert_eq!(PANIC_AT.with(|p| p.borrow().clone()), None, "taken once");
    }
}
