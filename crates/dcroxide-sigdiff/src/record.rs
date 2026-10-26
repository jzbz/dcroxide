// SPDX-License-Identifier: ISC
//! The record of a run: the counts it keeps, the files it writes, and the
//! checks on where it may write them.
//!
//! ```text
//! <out>/manifest.json        written at start (status "running"), rewritten at the end
//! <out>/summary.txt          every criterion with pass, fail or "not evaluated"
//! <out>/counts.tsv           class  variant  request  command  ours  theirs  n
//! <out>/kinds.tsv            command  kind  theirs_n  compared_n  classes
//! <out>/digests.tsv          class  n  digest  final   (checkpoints and the final count)
//! <out>/mix.tsv              class  check  observed  expected  pass
//! <out>/progress.tsv         one line per progress interval
//! <out>/disagreements.jsonl  one JSON object per disagreement; empty means none
//! <out>/events.jsonl         oracle faults and restarts, including unreproduced ones
//! <out>/oracle-w<k>.stderr   each worker's oracle stderr, every spawn appended
//! <out>/canary/              the canary run (sigsoak canary): manifest.json,
//!                            summary.tsv, summary.txt, and the record of each
//!                            part in model-baseline/ and <canary>/{primary,others}/
//! ```

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use dcroxide_testutil::hex;
use serde_json::Value;

use crate::answer::{Answer, Kind, OursAnswer};
use crate::class::{Case, ClassSpec, Family, Mix, Tag};
use crate::cmd::Cmd;
use crate::compare::{CaseResult, Status};
use crate::digest::ClassDigest;

/// At most this many disagreement lines are written per run; counting goes
/// on past it, and the summary says how many were not written.
pub const MAX_DISAGREEMENT_LINES: u64 = 10_000;

/// The kinds every run that selects their family must see dcrd return at
/// least 10^4 times (the kind-coverage criterion): the 19 DER kinds, the 6
/// public key kinds, the 8 compact recovery kinds and the 4 Schnorr
/// signature parse kinds.  Recovery kinds are seen on dcrd's side; they are
/// compared with dcroxide's once dcroxide reports them.
pub const REACHABLE_KINDS: &[(Family, Cmd, &str)] = &[
    (Family::Der, Cmd::EcdsaParseDer, "ErrSigTooShort"),
    (Family::Der, Cmd::EcdsaParseDer, "ErrSigTooLong"),
    (Family::Der, Cmd::EcdsaParseDer, "ErrSigInvalidSeqID"),
    (Family::Der, Cmd::EcdsaParseDer, "ErrSigInvalidDataLen"),
    (Family::Der, Cmd::EcdsaParseDer, "ErrSigMissingSTypeID"),
    (Family::Der, Cmd::EcdsaParseDer, "ErrSigMissingSLen"),
    (Family::Der, Cmd::EcdsaParseDer, "ErrSigInvalidSLen"),
    (Family::Der, Cmd::EcdsaParseDer, "ErrSigInvalidRIntID"),
    (Family::Der, Cmd::EcdsaParseDer, "ErrSigZeroRLen"),
    (Family::Der, Cmd::EcdsaParseDer, "ErrSigNegativeR"),
    (Family::Der, Cmd::EcdsaParseDer, "ErrSigTooMuchRPadding"),
    (Family::Der, Cmd::EcdsaParseDer, "ErrSigRIsZero"),
    (Family::Der, Cmd::EcdsaParseDer, "ErrSigRTooBig"),
    (Family::Der, Cmd::EcdsaParseDer, "ErrSigInvalidSIntID"),
    (Family::Der, Cmd::EcdsaParseDer, "ErrSigZeroSLen"),
    (Family::Der, Cmd::EcdsaParseDer, "ErrSigNegativeS"),
    (Family::Der, Cmd::EcdsaParseDer, "ErrSigTooMuchSPadding"),
    (Family::Der, Cmd::EcdsaParseDer, "ErrSigSIsZero"),
    (Family::Der, Cmd::EcdsaParseDer, "ErrSigSTooBig"),
    (Family::Pubkey, Cmd::PubkeyParse, "ErrPubKeyInvalidLen"),
    (Family::Pubkey, Cmd::PubkeyParse, "ErrPubKeyInvalidFormat"),
    (Family::Pubkey, Cmd::PubkeyParse, "ErrPubKeyXTooBig"),
    (Family::Pubkey, Cmd::PubkeyParse, "ErrPubKeyYTooBig"),
    (Family::Pubkey, Cmd::PubkeyParse, "ErrPubKeyNotOnCurve"),
    (
        Family::Pubkey,
        Cmd::PubkeyParse,
        "ErrPubKeyMismatchedOddness",
    ),
    (
        Family::Recover,
        Cmd::EcdsaRecoverCompact,
        "ErrSigInvalidLen",
    ),
    (
        Family::Recover,
        Cmd::EcdsaRecoverCompact,
        "ErrSigInvalidRecoveryCode",
    ),
    (Family::Recover, Cmd::EcdsaRecoverCompact, "ErrSigRTooBig"),
    (Family::Recover, Cmd::EcdsaRecoverCompact, "ErrSigRIsZero"),
    (Family::Recover, Cmd::EcdsaRecoverCompact, "ErrSigSTooBig"),
    (Family::Recover, Cmd::EcdsaRecoverCompact, "ErrSigSIsZero"),
    (
        Family::Recover,
        Cmd::EcdsaRecoverCompact,
        "ErrSigOverflowsPrime",
    ),
    (
        Family::Recover,
        Cmd::EcdsaRecoverCompact,
        "ErrPointNotOnCurve",
    ),
    (Family::Schnorr, Cmd::SchnorrParse, "ErrSigTooShort"),
    (Family::Schnorr, Cmd::SchnorrParse, "ErrSigTooLong"),
    (Family::Schnorr, Cmd::SchnorrParse, "ErrSigRTooBig"),
    (Family::Schnorr, Cmd::SchnorrParse, "ErrSigSTooBig"),
];

/// The kinds and reasons no input through the oracle can reach, and the one
/// excluded by design, each with the family it belongs to: the summary
/// lists those of the families a run selected.
pub const UNREACHABLE: &[(Family, &str)] = &[
    (
        Family::Schnorr,
        "ErrInvalidHashLen (Schnorr): every oracle Schnorr command takes a 32-byte hash",
    ),
    (
        Family::Schnorr,
        "ErrSchnorrHashValue (Schnorr): needs BLAKE-256 at or above N, odds about 2^-128",
    ),
    (
        Family::Schnorr,
        "ErrPubKeyNotOnCurve in Schnorr verify: a parsed key is on the curve",
    ),
    (
        Family::Ed25519,
        "Ed25519 \"pubkey Y parameter is >= to P\": decoding reduces y",
    ),
    (
        Family::Ed25519,
        "Ed25519 ParseDERSignature: no oracle command reaches it",
    ),
    (
        Family::Schnorr,
        "excluded by design: ErrPrivateKeyIsZero in Schnorr signing (signing keys stay in [1, N-1])",
    ),
];

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A `counts.tsv` row's key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CountKey {
    /// The class, by its index in the run's class list.
    pub class: usize,
    /// The case's variant.
    pub variant: Cow<'static, str>,
    /// The request's position in its case.
    pub request: u8,
    /// The request's command.
    pub cmd: Cmd,
    /// dcroxide's outcome label (`panic` when it panicked).
    pub ours: Cow<'static, str>,
    /// dcrd's outcome label (`no-answer` when there is none).
    pub theirs: Cow<'static, str>,
}

/// A `kinds.tsv` row's counts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KindCount {
    /// How many times dcrd returned the kind.
    pub theirs: u64,
    /// How many of those were held against a kind of dcroxide's.
    pub compared: u64,
    /// The classes it came from, by index.
    pub classes: BTreeSet<usize>,
}

/// One class's counts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClassTotals {
    /// Cases completed.
    pub completed: u64,
    /// Cases per status, by status code.
    pub statuses: [u64; 4],
    /// Requests sent.
    pub requests: u64,
    /// Cases that fell back to fixed values (left out of every mix).
    pub fallbacks: u64,
    /// Cases counted for the mixes.
    pub mix_n: u64,
    /// Of those, cases whose first request dcrd accepted.
    pub accepted: u64,
    /// Of those, cases tagged [`Tag::Doubled`].
    pub doubled: u64,
    /// Of those, cases tagged [`Tag::FormsDiffer`].
    pub forms_differ: u64,
    /// The lowest index of a case that disagreed (status 1).
    pub first_disagree: Option<u64>,
    /// The class's digest.
    pub digest: ClassDigest,
}

/// The counts of a run, or of one worker's share of it; shares merge in
/// any order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Totals {
    /// `counts.tsv`.
    pub counts: HashMap<CountKey, u64>,
    /// `kinds.tsv`, by command and kind name.
    pub kinds: HashMap<(Cmd, String), KindCount>,
    /// Per class, by index in the run's class list.
    pub classes: Vec<ClassTotals>,
}

impl Totals {
    /// Empty counts for `classes` classes.
    pub fn new(classes: usize) -> Totals {
        Totals {
            counts: HashMap::new(),
            kinds: HashMap::new(),
            classes: vec![ClassTotals::default(); classes],
        }
    }

    /// Counts one completed case of class `class`, whose digest leaf is
    /// `leaf`.
    pub fn record(
        &mut self,
        class: usize,
        index: u64,
        case: &Case,
        ours: &[Result<OursAnswer, String>],
        result: &CaseResult,
        leaf: &[u8; 32],
    ) {
        let totals = &mut self.classes[class];
        totals.completed = totals.completed.saturating_add(1);
        let status = &mut totals.statuses[usize::from(result.status.code())];
        *status = status.saturating_add(1);
        if result.status == Status::Disagree {
            totals.first_disagree = Some(totals.first_disagree.map_or(index, |i| i.min(index)));
        }
        totals.requests = totals
            .requests
            .saturating_add(u64::try_from(case.requests.len()).unwrap_or(u64::MAX));
        totals.digest.add(index, leaf);
        if case.tags.has(Tag::Fallback) {
            totals.fallbacks = totals.fallbacks.saturating_add(1);
        } else {
            totals.mix_n = totals.mix_n.saturating_add(1);
            if result
                .theirs
                .first()
                .and_then(Option::as_ref)
                .is_some_and(Answer::accepted)
            {
                totals.accepted = totals.accepted.saturating_add(1);
            }
            if case.tags.has(Tag::Doubled) {
                totals.doubled = totals.doubled.saturating_add(1);
            }
            if case.tags.has(Tag::FormsDiffer) {
                totals.forms_differ = totals.forms_differ.saturating_add(1);
            }
        }
        for (j, request) in case.requests.iter().enumerate() {
            let key = CountKey {
                class,
                variant: case.variant.clone(),
                request: u8::try_from(j).expect("at most 255 requests"),
                cmd: request.cmd,
                ours: match &ours[j] {
                    Ok(o) => o.answer.label(),
                    Err(_) => Cow::Borrowed("panic"),
                },
                theirs: result.theirs[j]
                    .as_ref()
                    .map_or(Cow::Borrowed("no-answer"), Answer::label),
            };
            let n = self.counts.entry(key).or_insert(0);
            *n = n.saturating_add(1);
            if let Some(Answer::Reject {
                kind: Kind::Dcrd(name),
                ..
            }) = &result.theirs[j]
            {
                let count = self.kinds.entry((request.cmd, name.clone())).or_default();
                count.theirs = count.theirs.saturating_add(1);
                if result.kind_compared[j] {
                    count.compared = count.compared.saturating_add(1);
                }
                count.classes.insert(class);
            }
        }
    }

    /// Adds every count of `other`.
    pub fn merge(&mut self, other: Totals) {
        for (key, n) in other.counts {
            let mine = self.counts.entry(key).or_insert(0);
            *mine = mine.saturating_add(n);
        }
        for (key, count) in other.kinds {
            let mine = self.kinds.entry(key).or_default();
            mine.theirs = mine.theirs.saturating_add(count.theirs);
            mine.compared = mine.compared.saturating_add(count.compared);
            mine.classes.extend(count.classes);
        }
        if self.classes.len() < other.classes.len() {
            self.classes
                .resize(other.classes.len(), ClassTotals::default());
        }
        for (mine, theirs) in self.classes.iter_mut().zip(other.classes) {
            mine.completed = mine.completed.saturating_add(theirs.completed);
            for (a, b) in mine.statuses.iter_mut().zip(theirs.statuses) {
                *a = a.saturating_add(b);
            }
            mine.requests = mine.requests.saturating_add(theirs.requests);
            mine.fallbacks = mine.fallbacks.saturating_add(theirs.fallbacks);
            mine.mix_n = mine.mix_n.saturating_add(theirs.mix_n);
            mine.accepted = mine.accepted.saturating_add(theirs.accepted);
            mine.doubled = mine.doubled.saturating_add(theirs.doubled);
            mine.forms_differ = mine.forms_differ.saturating_add(theirs.forms_differ);
            mine.first_disagree = match (mine.first_disagree, theirs.first_disagree) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            mine.digest.merge(&theirs.digest);
        }
    }
}

/// One evaluated mix check (a row of `mix.tsv`).
#[derive(Debug, Clone, PartialEq)]
pub struct MixResult {
    /// The class.
    pub class: &'static str,
    /// The check, e.g. `accept-rate`.
    pub check: String,
    /// What the run saw.
    pub observed: String,
    /// What passes.
    pub expected: String,
    /// The verdict; `None` when the check's condition did not hold (too few
    /// cases, or a finite class that did not run whole).
    pub pass: Option<bool>,
}

/// Evaluates `spec`'s mixes over its counts; `whole` is whether a finite
/// class ran every element.
pub fn evaluate_mixes(spec: &ClassSpec, totals: &ClassTotals, whole: bool) -> Vec<MixResult> {
    let share = |k: u64| {
        if totals.mix_n == 0 {
            0.0
        } else {
            k as f64 / totals.mix_n as f64
        }
    };
    let band = |check: String, k: u64, lo: f64, hi: f64, min_n: u64| {
        let observed = share(k);
        MixResult {
            class: spec.name,
            check,
            observed: format!("{observed:.6} ({k} of {})", totals.mix_n),
            expected: format!("[{lo}, {hi}] once n >= {min_n}"),
            pass: (totals.mix_n >= min_n).then_some(observed >= lo && observed <= hi),
        }
    };
    spec.mix
        .iter()
        .map(|mix| match *mix {
            Mix::AcceptRate { lo, hi, min_n } => {
                band("accept-rate".to_owned(), totals.accepted, lo, hi, min_n)
            }
            Mix::TagRate { tag, lo, hi, min_n } => {
                let k = match tag {
                    Tag::Doubled => totals.doubled,
                    Tag::FormsDiffer => totals.forms_differ,
                    Tag::Fallback => totals.fallbacks,
                };
                band(format!("{}-rate", tag.name()), k, lo, hi, min_n)
            }
            Mix::AcceptCount(want) => MixResult {
                class: spec.name,
                check: "accept-count".to_owned(),
                observed: totals.accepted.to_string(),
                expected: format!("{want} when run whole"),
                pass: whole.then_some(totals.accepted == want),
            },
        })
        .collect()
}

/// Where a subcommand writes, for [`out_dir_problem`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutUse {
    /// `run`: the directory may exist holding only a `canary/` directory.
    Run,
    /// `canary`: `<out>/canary/` may exist only empty.
    Canary,
    /// `emit-corpus`: the directory may exist only empty.
    EmitCorpus,
}

/// Why `out` (taken relative to `cwd`) may not receive a run's files, or
/// `None` when it may.  Refused: anything equal to or inside `repo_root`
/// (generated output lives outside the working tree), a path whose
/// not-yet-existing part has `.` or `..` components, and an existing
/// directory holding files the subcommand would mix with its own.
///
/// `out`'s longest existing ancestor is canonicalized and the rest appended,
/// and `repo_root` is canonical too, so the comparison is canonical against
/// canonical: a checkout reached through a symlink, or Windows'
/// extended-length paths, cannot slip past it.
pub fn out_dir_problem(out: &Path, cwd: &Path, repo_root: &Path, usage: OutUse) -> Option<String> {
    let absolute = if out.is_absolute() {
        out.to_path_buf()
    } else {
        cwd.join(out)
    };
    let Some(existing) = absolute.ancestors().find(|a| a.exists()) else {
        return Some(format!("no part of {} exists", absolute.display()));
    };
    let rest = absolute
        .strip_prefix(existing)
        .expect("an ancestor is a prefix");
    if rest
        .components()
        .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
    {
        return Some(format!(
            "{} has . or .. below the part that exists",
            absolute.display()
        ));
    }
    let resolved = match std::fs::canonicalize(existing) {
        // Joining an empty rest would add a trailing separator, under which
        // a file does not exist.
        Ok(canonical) if rest.as_os_str().is_empty() => canonical,
        Ok(canonical) => canonical.join(rest),
        Err(e) => return Some(format!("{} does not resolve: {e}", existing.display())),
    };
    let root = match std::fs::canonicalize(repo_root) {
        Ok(root) => root,
        Err(e) => {
            return Some(format!(
                "the repository root {} does not resolve: {e}",
                repo_root.display()
            ));
        }
    };
    if resolved.starts_with(&root) {
        return Some(format!(
            "{} is inside the repository {}; generated output belongs outside the tree",
            resolved.display(),
            root.display()
        ));
    }
    if !resolved.exists() {
        return None;
    }
    if !resolved.is_dir() {
        return Some(format!("{} is not a directory", resolved.display()));
    }
    let entries = |dir: &Path| -> Result<Vec<(String, bool)>, String> {
        std::fs::read_dir(dir)
            .and_then(|it| {
                it.map(|e| {
                    let e = e?;
                    Ok((
                        e.file_name().to_string_lossy().into_owned(),
                        e.file_type()?.is_dir(),
                    ))
                })
                .collect()
            })
            .map_err(|e| format!("{} unreadable: {e}", dir.display()))
    };
    match usage {
        OutUse::Run => match entries(&resolved) {
            Ok(list) => list
                .iter()
                .find(|(name, is_dir)| !(name == "canary" && *is_dir))
                .map(|(name, _)| format!("{} already holds {name}", resolved.display())),
            Err(e) => Some(e),
        },
        OutUse::Canary => {
            let canary = resolved.join("canary");
            match canary.exists().then(|| entries(&canary)) {
                None => None,
                Some(Ok(list)) if list.is_empty() => None,
                Some(Ok(_)) => Some(format!("{} is not empty", canary.display())),
                Some(Err(e)) => Some(e),
            }
        }
        OutUse::EmitCorpus => match entries(&resolved) {
            Ok(list) if list.is_empty() => None,
            Ok(_) => Some(format!("{} is not empty", resolved.display())),
            Err(e) => Some(e),
        },
    }
}

/// The files of one run, or nothing at all for a run without an output
/// directory.
#[derive(Debug)]
pub struct Recorder {
    dir: Option<PathBuf>,
    manifest: Mutex<Option<Value>>,
    disagreements: Mutex<Option<File>>,
    events: Mutex<Option<File>>,
    progress: Mutex<Option<File>>,
    written: AtomicU64,
    unwritten: AtomicU64,
}

impl Recorder {
    /// A recorder writing into `dir` (created if missing), or writing
    /// nothing for `None`.  Writes the start manifest when given one, with
    /// `status` `"running"`, and the header of `progress.tsv` naming
    /// `classes`.
    pub fn create(
        dir: Option<&Path>,
        manifest: Option<Value>,
        classes: &[&str],
    ) -> io::Result<Recorder> {
        let recorder = Recorder {
            dir: dir.map(Path::to_path_buf),
            manifest: Mutex::new(manifest),
            disagreements: Mutex::new(None),
            events: Mutex::new(None),
            progress: Mutex::new(None),
            written: AtomicU64::new(0),
            unwritten: AtomicU64::new(0),
        };
        let Some(dir) = dir else {
            return Ok(recorder);
        };
        std::fs::create_dir_all(dir)?;
        recorder.write_manifest(None)?;
        *lock(&recorder.disagreements) = Some(File::create(dir.join("disagreements.jsonl"))?);
        *lock(&recorder.events) = Some(File::create(dir.join("events.jsonl"))?);
        let mut progress = File::create(dir.join("progress.tsv"))?;
        let mut header =
            String::from("elapsed_s\tcases\trequests\treq_per_s\tdisagreements\toracle_faults");
        for class in classes {
            header.push('\t');
            header.push_str(class);
        }
        header.push('\n');
        progress.write_all(header.as_bytes())?;
        *lock(&recorder.progress) = Some(progress);
        Ok(recorder)
    }

    /// Where worker `worker`'s oracle stderr goes, if anywhere.
    pub fn stderr_path(&self, worker: usize) -> Option<PathBuf> {
        self.dir
            .as_ref()
            .map(|dir| dir.join(format!("oracle-w{worker}.stderr")))
    }

    /// Appends a disagreement line, unless [`MAX_DISAGREEMENT_LINES`] were
    /// written already; returns whether it was.
    pub fn disagreement(&self, record: &Value) -> bool {
        let mut file = lock(&self.disagreements);
        let Some(file) = file.as_mut() else {
            return false;
        };
        if self.written.load(Ordering::SeqCst) >= MAX_DISAGREEMENT_LINES {
            self.unwritten.fetch_add(1, Ordering::SeqCst);
            return false;
        }
        let mut line = record.to_string();
        line.push('\n');
        if file
            .write_all(line.as_bytes())
            .and_then(|()| file.flush())
            .is_ok()
        {
            self.written.fetch_add(1, Ordering::SeqCst);
            true
        } else {
            self.unwritten.fetch_add(1, Ordering::SeqCst);
            false
        }
    }

    /// Disagreement lines not written, past the cap or on a write error.
    pub fn unwritten(&self) -> u64 {
        self.unwritten.load(Ordering::SeqCst)
    }

    /// Appends an event line.
    pub fn event(&self, record: &Value) {
        if let Some(file) = lock(&self.events).as_mut() {
            let mut line = record.to_string();
            line.push('\n');
            let _ = file.write_all(line.as_bytes()).and_then(|()| file.flush());
        }
    }

    /// Appends a progress row (its newline included).
    pub fn progress(&self, row: &str) {
        if let Some(file) = lock(&self.progress).as_mut() {
            let _ = file.write_all(row.as_bytes()).and_then(|()| file.flush());
        }
    }

    /// Rewrites `manifest.json` with `end` (status and end time) merged
    /// in, when there is a manifest and a directory.
    fn write_manifest(&self, end: Option<Value>) -> io::Result<()> {
        let Some(dir) = &self.dir else {
            return Ok(());
        };
        let mut manifest = lock(&self.manifest);
        let Some(manifest) = manifest.as_mut() else {
            return Ok(());
        };
        if let (Some(Value::Object(fields)), Some(object)) = (end, manifest.as_object_mut()) {
            object.extend(fields);
        }
        let text = serde_json::to_string_pretty(manifest).map_err(io::Error::other)?;
        write_atomically(&dir.join("manifest.json"), text.as_bytes())
    }

    /// Writes the end of a run: every table, the summary, and the manifest
    /// with its status and end time.
    pub fn write_final(&self, summary: &crate::run::Summary) -> io::Result<()> {
        let Some(dir) = &self.dir else {
            return Ok(());
        };
        let names: Vec<&str> = summary.classes.iter().map(|c| c.name).collect();

        let mut counts: Vec<(&CountKey, &u64)> = summary.totals.counts.iter().collect();
        counts.sort();
        let mut text = String::from("class\tvariant\trequest\tcommand\tours\ttheirs\tn\n");
        for (key, n) in counts {
            let _ = writeln!(
                text,
                "{}\t{}\t{}\t{}\t{}\t{}\t{n}",
                names[key.class],
                key.variant,
                key.request,
                key.cmd.name(),
                key.ours,
                key.theirs
            );
        }
        write_atomically(&dir.join("counts.tsv"), text.as_bytes())?;

        let kinds: BTreeMap<(&str, &str), &KindCount> = summary
            .totals
            .kinds
            .iter()
            .map(|((cmd, kind), count)| ((cmd.name(), kind.as_str()), count))
            .collect();
        let mut text = String::from("command\tkind\ttheirs_n\tcompared_n\tclasses\n");
        for ((cmd, kind), count) in kinds {
            let classes: Vec<&str> = count.classes.iter().map(|&c| names[c]).collect();
            let _ = writeln!(
                text,
                "{cmd}\t{kind}\t{}\t{}\t{}",
                count.theirs,
                count.compared,
                classes.join(",")
            );
        }
        write_atomically(&dir.join("kinds.tsv"), text.as_bytes())?;

        let mut text = String::from("class\tn\tdigest\tfinal\n");
        for class in &summary.classes {
            for row in class.digest.rows(class.name, class.completed) {
                let _ = writeln!(
                    text,
                    "{}\t{}\t{}\t{}",
                    class.name,
                    row.n,
                    hex(&row.digest),
                    row.is_final
                );
            }
        }
        write_atomically(&dir.join("digests.tsv"), text.as_bytes())?;

        let mut text = String::from("class\tcheck\tobserved\texpected\tpass\n");
        for mix in &summary.mixes {
            let pass = match mix.pass {
                Some(true) => "pass",
                Some(false) => "fail",
                None => "not evaluated",
            };
            let _ = writeln!(
                text,
                "{}\t{}\t{}\t{}\t{pass}",
                mix.class, mix.check, mix.observed, mix.expected
            );
        }
        write_atomically(&dir.join("mix.tsv"), text.as_bytes())?;

        write_atomically(&dir.join("summary.txt"), summary.render().as_bytes())?;
        self.write_manifest(Some(serde_json::json!({
            "status": summary.status.name(),
            "end": { "unix": crate::manifest::unix_now(), "utc": crate::manifest::utc(crate::manifest::unix_now()) },
        })))
    }
}

/// Writes the canary run's own files into `dir` (`<out>/canary`):
/// `summary.tsv`, one row per canary and one for the model baseline, and
/// `summary.txt`.  Each part of the run keeps its own record in a
/// subdirectory, written as it ran.
pub fn write_canary_record(dir: &Path, report: &crate::run::CanaryReport) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    write_atomically(&dir.join("summary.tsv"), report.summary_tsv().as_bytes())?;
    write_atomically(&dir.join("summary.txt"), report.render().as_bytes())
}

/// Writes `value` as pretty JSON to `path`, whole or not at all.
pub fn write_json(path: &Path, value: &Value) -> io::Result<()> {
    let text = serde_json::to_string_pretty(value).map_err(io::Error::other)?;
    write_atomically(path, text.as_bytes())
}

/// Writes `bytes` to a temporary file beside `path` and renames it into
/// place, so a reader never sees half a file.
fn write_atomically(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

/// Appends one line to a ledger file (created if missing).
pub fn append_ledger(path: &Path, fields: &[&str]) -> io::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let mut line = fields.join("\t");
    line.push('\n');
    file.write_all(line.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcroxide_testutil::TempDir;

    /// The repository root, a directory inside it reached through `..`
    /// and, on Unix, through a symlink to the root are refused; a fresh
    /// directory outside is taken, and an existing one only as each
    /// subcommand allows.
    #[test]
    fn out_dir_checks() {
        let root = TempDir::new("sigdiff-root");
        let repo = root.path().join("repo");
        std::fs::create_dir_all(repo.join("crates")).expect("mkdir");
        let outside = TempDir::new("sigdiff-out");

        let problem = |out: &Path, cwd: &Path, usage| out_dir_problem(out, cwd, &repo, usage);
        assert!(problem(&repo, outside.path(), OutUse::Run).is_some());
        assert!(problem(&repo.join("out"), outside.path(), OutUse::Run).is_some());
        assert!(
            problem(Path::new("../out"), &repo.join("crates"), OutUse::Run).is_some(),
            "a relative path into the repository"
        );
        assert!(
            problem(Path::new("crates/../../x/../repo/y"), &repo, OutUse::Run).is_some(),
            ".. below the existing part"
        );
        assert_eq!(
            problem(&outside.path().join("leg"), &repo, OutUse::Run),
            None
        );
        assert_eq!(
            problem(outside.path(), &repo, OutUse::Run),
            None,
            "empty is fine"
        );
        assert_eq!(
            problem(Path::new("leg"), outside.path(), OutUse::Run),
            None,
            "relative to the current directory"
        );

        // run: only a canary/ directory may be there already.
        std::fs::create_dir(outside.path().join("canary")).expect("mkdir");
        assert_eq!(problem(outside.path(), &repo, OutUse::Run), None);
        assert_eq!(problem(outside.path(), &repo, OutUse::Canary), None);
        std::fs::write(outside.path().join("canary").join("summary.tsv"), b"x").expect("write");
        assert!(problem(outside.path(), &repo, OutUse::Canary).is_some());
        assert!(problem(outside.path(), &repo, OutUse::EmitCorpus).is_some());
        std::fs::write(outside.path().join("summary.txt"), b"x").expect("write");
        assert!(problem(outside.path(), &repo, OutUse::Run).is_some());
        assert!(problem(&outside.path().join("summary.txt"), &repo, OutUse::Run).is_some());

        #[cfg(unix)]
        {
            let link = root.path().join("link");
            std::os::unix::fs::symlink(&repo, &link).expect("symlink");
            assert!(problem(&link.join("out"), outside.path(), OutUse::Run).is_some());
            assert!(problem(&link, outside.path(), OutUse::Run).is_some());
        }
    }

    #[test]
    fn mixes_evaluate_only_when_their_conditions_hold() {
        static SPEC: ClassSpec = ClassSpec {
            name: "T-mix",
            family: Family::Der,
            commands: &[Cmd::EcdsaParseDer],
            size: crate::class::Size::Finite { size: 4 },
            tier: crate::class::Tier::Finite,
            generator: |_, _| unreachable!("never generated"),
            mix: &[
                Mix::AcceptRate {
                    lo: 0.4,
                    hi: 0.6,
                    min_n: 4,
                },
                Mix::AcceptCount(2),
                Mix::TagRate {
                    tag: Tag::Doubled,
                    lo: 0.0,
                    hi: 0.1,
                    min_n: 10,
                },
            ],
            pr_cases: 4,
            doc: "",
        };
        let totals = ClassTotals {
            mix_n: 4,
            accepted: 2,
            doubled: 1,
            ..ClassTotals::default()
        };
        let results = evaluate_mixes(&SPEC, &totals, true);
        let passes: Vec<Option<bool>> = results.iter().map(|m| m.pass).collect();
        assert_eq!(passes, [Some(true), Some(true), None]);
        let results = evaluate_mixes(&SPEC, &totals, false);
        assert_eq!(
            results[1].pass, None,
            "a finite class that did not run whole"
        );
        let totals = ClassTotals {
            mix_n: 4,
            accepted: 3,
            ..ClassTotals::default()
        };
        let passes: Vec<Option<bool>> = evaluate_mixes(&SPEC, &totals, true)
            .iter()
            .map(|m| m.pass)
            .collect();
        assert_eq!(passes, [Some(false), Some(false), None]);
    }

    /// A class's first disagreement is the lowest index that disagreed,
    /// whatever order cases complete in and shares merge in; other
    /// statuses do not count.
    #[test]
    fn the_first_disagreement_is_the_lowest_index() {
        let case = Case {
            variant: Cow::Borrowed("v"),
            requests: vec![crate::cmd::ecdsa_parse_der(&[])],
            intents: vec![crate::class::Intent::Any],
            consistency: crate::class::Consistency::None,
            tags: crate::class::Tags::NONE,
        };
        let result = |status| CaseResult {
            status,
            failures: Vec::new(),
            theirs: vec![None],
            kind_compared: vec![false],
        };
        let ours = [Err("x".to_owned())];
        let mut a = Totals::new(1);
        let mut b = Totals::new(1);
        a.record(0, 9, &case, &ours, &result(Status::Disagree), &[0; 32]);
        a.record(0, 1, &case, &ours, &result(Status::OracleFailure), &[0; 32]);
        a.record(0, 0, &case, &ours, &result(Status::Agree), &[0; 32]);
        assert_eq!(a.classes[0].first_disagree, Some(9));
        b.record(0, 4, &case, &ours, &result(Status::Disagree), &[0; 32]);
        b.record(0, 7, &case, &ours, &result(Status::Disagree), &[0; 32]);
        assert_eq!(b.classes[0].first_disagree, Some(4));
        let mut none = Totals::new(1);
        none.record(0, 2, &case, &ours, &result(Status::OursPanicked), &[0; 32]);
        assert_eq!(none.classes[0].first_disagree, None);
        none.merge(a);
        assert_eq!(none.classes[0].first_disagree, Some(9));
        none.merge(b);
        assert_eq!(none.classes[0].first_disagree, Some(4));
    }

    #[test]
    fn the_disagreement_file_is_capped() {
        let dir = TempDir::new("sigdiff-recorder");
        let recorder = Recorder::create(Some(dir.path()), None, &["a"]).expect("create");
        recorder
            .written
            .store(MAX_DISAGREEMENT_LINES - 1, Ordering::SeqCst);
        assert!(recorder.disagreement(&serde_json::json!({ "n": 1 })));
        assert!(!recorder.disagreement(&serde_json::json!({ "n": 2 })));
        assert_eq!(recorder.unwritten(), 1);
        let text = std::fs::read_to_string(dir.path().join("disagreements.jsonl")).expect("read");
        assert_eq!(text, "{\"n\":1}\n");
        let none = Recorder::create(None, None, &[]).expect("no directory");
        assert!(!none.disagreement(&serde_json::json!({})));
        assert_eq!(none.stderr_path(0), None);
        assert_eq!(
            recorder.stderr_path(3),
            Some(dir.path().join("oracle-w3.stderr"))
        );
    }
}
