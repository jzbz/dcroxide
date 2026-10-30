// SPDX-License-Identifier: ISC
//! The entry the signature fuzz targets share: a fuzz input read as a case
//! of one of this crate's classes, answered by dcroxide and by dcrd's own
//! code through `tools/oracle` (or, for `dcrec_ed25519_model`, by the
//! Go-free model of dcrd's Ed25519), and the two compared.  Each target
//! under `fuzz/fuzz_targets/` is a thin wrapper around [`fuzz_one`] or
//! [`fuzz_ed25519_model`], so everything a target does runs in `cargo
//! test` as well, without libFuzzer.
//!
//! # Inputs
//!
//! `[selector: 1 byte][index: 8 bytes LE][entropy]`.  The selector picks a
//! class from the target's slot table ([`Target::slots`]), the index is the
//! case index (reduced modulo a finite class's size), and the rest is the
//! class generator's entropy, read as [`ByteEntropy`] reads it: zeros once
//! it runs out.  A selector past the table, or at a retired slot, reaches
//! no class, and the input is rejected.  The tables only grow, so a saved
//! input keeps naming its class.  A soak case is a fuzz input byte for byte
//! ([`seed_input`]).
//!
//! # The comparison
//!
//! [`check`] asks dcrd first, then dcroxide, and holds the answers side by
//! side with [`compare`], on the case with its intents rebased on the
//! models' view ([`rebase`]): a fuzzer chooses the stream, and a
//! construction can miss the branch it was built for while both sides
//! agree.  Every failure `compare` reports is a finding, and so is an
//! oracle that fails on the input.  A target panics on a finding with
//! everything needed to replay it ([`Report`]), and `sigsoak fuzz-replay`
//! replays a crash input without libFuzzer.  In a libFuzzer binary a panic
//! never unwinds, since libFuzzer's hook aborts first, so a panic in
//! dcroxide or in a generator is reported by its own message and the case
//! under way ([`install_panic_context`]); in `cargo test` and in
//! `fuzz-replay` dcroxide's panics unwind and become `ours-panicked`
//! failures.
//!
//! # The oracle
//!
//! One oracle serves a fuzz process ([`init_oracle_target`]), spawned as
//! testutil spawns it and held to the pin rule.  The oracle-backed targets
//! never skip: without an oracle they stop before fuzzing.  An oracle that
//! dies on an input is a finding against that input.  One killed from
//! outside (by the OOM killer, say) is blamed on the input under way, and
//! replaying that input shows it agreeing.  A hung oracle is a libFuzzer
//! timeout (`-timeout`) and outlives the target, since only an oracle that
//! reads sees its input end: CI kills what is left after each target, and
//! a local run leaves it for whoever ran it.
//!
//! # The freeze
//!
//! This module is plumbing ([`crate::fingerprint::PLUMBING`]): it decides
//! inputs, answers as compared and failures for fuzz inputs only, and no
//! soak run, digest, witness or gate run passes through it.  It reaches
//! dcroxide only through the answerer its caller passes
//! ([`crate::run::ours_answerer`]).

use std::cell::RefCell;
use std::fmt::{self, Write as _};
use std::sync::{Mutex, Once, OnceLock, PoisonError};

use dcroxide_testutil::{Oracle, SplitMix64, hex};
use serde_json::json;

use crate::answer::{Answer, OursAnswer};
use crate::class::{
    Case, ClassSpec, Consistency, Family, Intent, Tag, Tags, case_seed, find_class,
};
use crate::cmd::{Cmd, Request};
use crate::compare::{Category, Failure, compare};
use crate::entropy::{ByteEntropy, Entropy};
use crate::manifest::{SIGNATURE_MODULES, check_pin};
use crate::model::{self, ModelOutcome, ModelView};
use crate::reply::Reply;
use crate::run::{self, Mode, RequestLines, failure_line};

/// The five oracle-backed targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Target {
    /// `dcrec_diff_ecdsa`: ECDSA verification and signing, and DER parsing.
    Ecdsa,
    /// `dcrec_diff_recover`: compact signature recovery.
    Recover,
    /// `dcrec_diff_pubkey`: secp256k1 public key parsing.
    Pubkey,
    /// `dcrec_diff_schnorr`: EC-Schnorr-DCRv0 signing, parsing and
    /// verification.
    Schnorr,
    /// `dcrec_diff_ed25519`: Ed25519 signing, key and signature parsing and
    /// verification.
    Ed25519,
}

/// A retired slot: a class removed from the registry keeps its selector,
/// which then reaches no class.
pub const RETIRED: &str = "-";

// The slot tables: selector byte s reaches slot s.  Append only, never
// reorder, and mark a removed class's slot RETIRED, so that a saved input
// keeps naming its class; `the_slot_tables_only_grow` holds them to that.

/// `dcrec_diff_ecdsa`'s slots.
const ECDSA_SLOTS: [&str; 26] = [
    "EV-honest",
    "EV-highS",
    "EV-tamper",
    "EV-random",
    "EV-keyenc",
    "EV-keys",
    "EV-hashGEN",
    "EV-hash0",
    "EV-zero",
    "EV-range",
    "EV-xGEN-true",
    "EV-xGEN-false",
    "EV-xGEN-wrap",
    "EV-infinity",
    "EV-double",
    "EV-sEdge",
    "EV-rEdge",
    "EV-smallXKey",
    "ES-random",
    "ES-hashGEN",
    "ES-boundary",
    "ES-compact",
    "DER-valid",
    "DER-mutate",
    "DER-structured",
    "DER-kind",
];

/// `dcrec_diff_recover`'s slots.
const RECOVER_SLOTS: [&str; 12] = [
    "ER-honest",
    "ER-flipParity",
    "ER-highS",
    "ER-overflowValid",
    "ER-overflowPrime",
    "ER-notOnCurve",
    "ER-infinity",
    "ER-double",
    "ER-header",
    "ER-length",
    "ER-range",
    "ER-hash",
];

/// `dcrec_diff_pubkey`'s slots.
const PUBKEY_SLOTS: [&str; 12] = [
    "K-valid",
    "K-hybridMismatch",
    "K-XTooBig",
    "K-YTooBig",
    "K-wrap",
    "K-nearP",
    "K-offCurve",
    "K-negY",
    "K-mutate",
    "K-smallX",
    "K-format",
    "K-length",
];

/// `dcrec_diff_schnorr`'s slots.
const SCHNORR_SLOTS: [&str; 16] = [
    "SS-random",
    "SS-hashGEN",
    "SS-boundary",
    "SP-random",
    "SP-rRange",
    "SV-honest",
    "SV-tamper",
    "SV-random",
    "SV-hashGEN",
    "SV-zeroS",
    "SV-infinity",
    "SV-oddR",
    "SV-rGEN-true",
    "SV-rGEN-odd",
    "SV-unequalR",
    "SV-double",
];

/// `dcrec_diff_ed25519`'s slots, which `dcrec_ed25519_model` reads too.
const ED25519_SLOTS: [&str; 16] = [
    "DS-random",
    "DK-canonical",
    "DK-random",
    "DK-small",
    "DK-length",
    "DG-edges",
    "DG-random",
    "DV-honest",
    "DV-tamper",
    "DV-SplusL",
    "DV-topBits",
    "DV-random",
    "DV-torsion",
    "DV-torsionSweep",
    "DV-torsionNoncanon",
    "DV-zeroS-smallR",
];

impl Target {
    /// Every oracle-backed target.
    pub const ALL: [Target; 5] = [
        Target::Ecdsa,
        Target::Recover,
        Target::Pubkey,
        Target::Schnorr,
        Target::Ed25519,
    ];

    /// The target's name, its binary's under `fuzz/fuzz_targets/`.
    pub fn name(self) -> &'static str {
        match self {
            Target::Ecdsa => "dcrec_diff_ecdsa",
            Target::Recover => "dcrec_diff_recover",
            Target::Pubkey => "dcrec_diff_pubkey",
            Target::Schnorr => "dcrec_diff_schnorr",
            Target::Ed25519 => "dcrec_diff_ed25519",
        }
    }

    /// The target named `name`.
    pub fn find(name: &str) -> Option<Target> {
        Target::ALL.into_iter().find(|target| target.name() == name)
    }

    /// The families whose classes it reads: ECDSA and DER for
    /// [`Target::Ecdsa`], the family of the same name for each other.
    pub fn families(self) -> &'static [Family] {
        match self {
            Target::Ecdsa => &[Family::Ecdsa, Family::Der],
            Target::Recover => &[Family::Recover],
            Target::Pubkey => &[Family::Pubkey],
            Target::Schnorr => &[Family::Schnorr],
            Target::Ed25519 => &[Family::Ed25519],
        }
    }

    /// The slot table: selector byte `s` reaches `slots()[s]`, a class
    /// name or [`RETIRED`].
    pub fn slots(self) -> &'static [&'static str] {
        match self {
            Target::Ecdsa => &ECDSA_SLOTS,
            Target::Recover => &RECOVER_SLOTS,
            Target::Pubkey => &PUBKEY_SLOTS,
            Target::Schnorr => &SCHNORR_SLOTS,
            Target::Ed25519 => &ED25519_SLOTS,
        }
    }

    /// The class selector `selector` reaches: `None` past the table or at
    /// a retired slot.
    pub fn class_at(self, selector: u8) -> Option<&'static ClassSpec> {
        class_in(self.slots(), selector)
    }

    /// The selector that reaches `class`.
    pub fn selector_of(self, class: &str) -> Option<u8> {
        self.slots()
            .iter()
            .position(|name| *name == class)
            .and_then(|at| u8::try_from(at).ok())
    }

    /// The classes the table reaches, in slot order.
    pub fn classes(self) -> impl Iterator<Item = &'static ClassSpec> {
        self.slots()
            .iter()
            .filter(|name| **name != RETIRED)
            .map(|name| slot_class(name))
    }

    /// The target whose families hold `class`.
    pub fn of_class(class: &ClassSpec) -> Target {
        match class.family {
            Family::Ecdsa | Family::Der => Target::Ecdsa,
            Family::Recover => Target::Recover,
            Family::Pubkey => Target::Pubkey,
            Family::Schnorr => Target::Schnorr,
            Family::Ed25519 => Target::Ed25519,
        }
    }
}

/// The class selector `selector` reaches in `slots`.
fn class_in(slots: &[&str], selector: u8) -> Option<&'static ClassSpec> {
    slots
        .get(usize::from(selector))
        .filter(|name| **name != RETIRED)
        .map(|name| slot_class(name))
}

/// The class a slot names.  A slot naming no class is a table that was
/// not kept when a class left the registry, which the coverage test
/// catches.
fn slot_class(name: &str) -> &'static ClassSpec {
    find_class(name)
        .unwrap_or_else(|| panic!("a fuzz slot names {name}, no class: mark it {RETIRED:?}"))
}

/// The target that holds dcroxide's Ed25519 to the Go-free model, and the
/// name `sigsoak fuzz-replay` and `fuzz-seeds` give it.  It reads
/// [`Target::Ed25519`]'s table.
pub const ED25519_MODEL_TARGET: &str = "dcrec_ed25519_model";

/// An input read as a case of its target.
#[derive(Debug, Clone)]
pub struct Decoded {
    /// The class the selector reached.
    pub class: &'static ClassSpec,
    /// The case index.
    pub index: u64,
    /// The case.
    pub case: Case,
}

/// The class `data` selects among `target`'s, the case index, and the
/// entropy after the index: `None` when `data` is empty or its first byte
/// reaches no class.  A finite class's index is reduced modulo its size,
/// since some generators allocate the index's worth of bytes.
fn locate(target: Target, data: &[u8]) -> Option<(&'static ClassSpec, u64, ByteEntropy<'_>)> {
    let (&selector, rest) = data.split_first()?;
    let class = target.class_at(selector)?;
    let mut entropy = ByteEntropy::new(rest);
    let raw = entropy.next_u64();
    let index = match class.size.finite() {
        Some(size) => raw.checked_rem(size).unwrap_or(0),
        None => raw,
    };
    Some((class, index, entropy))
}

/// Case `index` of `class` from `entropy`.  Panics, as a generator bug,
/// when the case breaks the shape every case has: one to 255 requests,
/// one intent each, every request one of the class's commands.
fn generate_from(class: &'static ClassSpec, index: u64, entropy: &mut dyn Entropy) -> Case {
    let case = (class.generator)(entropy, index);
    assert!(
        !case.requests.is_empty() && case.requests.len() <= 255,
        "{} case {index:#018x}: {} requests",
        class.name,
        case.requests.len()
    );
    assert_eq!(
        case.requests.len(),
        case.intents.len(),
        "{} case {index:#018x}: one intent per request",
        class.name
    );
    if let Some(request) = case
        .requests
        .iter()
        .find(|r| !class.commands.contains(&r.cmd))
    {
        panic!(
            "{} case {index:#018x} sends {}, not among its commands",
            class.name,
            request.cmd.name()
        );
    }
    case
}

/// `data` as an input of `target`: `None` when it is empty or its first
/// byte reaches no class.  Bytes past what the generator draws are
/// ignored, and a short input reads as zeros.
pub fn decode(target: Target, data: &[u8]) -> Option<Decoded> {
    let (class, index, mut entropy) = locate(target, data)?;
    let case = generate_from(class, index, &mut entropy);
    Some(Decoded { class, index, case })
}

/// dcroxide's answer to a request: [`run::ours_answerer`], or a closure
/// standing in for it.
pub type Ours<'a> = &'a dyn Fn(Cmd, &[u8]) -> Result<OursAnswer, String>;

/// The reference's reply to a request, or why there is none: the
/// category it fails under and the detail.
pub type Theirs<'a> = &'a mut dyn FnMut(&Request) -> Result<Reply, (Category, String)>;

/// What a target concluded of an input that produced no finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Checked {
    /// The selector reached no class.
    NoClass,
    /// Every check passed.
    Agreed {
        /// The class.
        class: &'static str,
        /// The case index.
        index: u64,
        /// Whether a bounded retry ran out and the case fell back to fixed
        /// values.
        fallback: bool,
    },
}

/// What dcroxide's answers are held against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reference {
    /// dcrd's own code, through the oracle.
    Dcrd,
    /// The Go-free model of dcrd's Ed25519 (`src/model/ed25519.rs`).
    Model,
}

impl Reference {
    /// The reference as a report names it.
    fn name(self) -> &'static str {
        match self {
            Reference::Dcrd => "dcrd",
            Reference::Model => "the model",
        }
    }

    /// The label of its answer in a request's block.
    fn label(self) -> &'static str {
        match self {
            Reference::Dcrd => "dcrd",
            Reference::Model => "model",
        }
    }
}

/// One input as a target checked it: the case, both sides' answers and
/// every failure.  A report with a failure is a finding, which fails the
/// target; its `Display` is what the target panics with, and holds
/// everything needed to replay it, the input included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// What dcroxide was held against.
    pub reference: Reference,
    /// The target, as its binary is named.
    pub target: &'static str,
    /// The whole input.
    pub input: Vec<u8>,
    /// The class.
    pub class: &'static str,
    /// The case index.
    pub index: u64,
    /// The case's variant.
    pub variant: String,
    /// Whether the case fell back to fixed values.
    pub fallback: bool,
    /// The case's requests.
    pub requests: Vec<Request>,
    /// The intents the generator gave them.
    pub intents: Vec<Intent>,
    /// The intents they were held to ([`rebase`]).
    pub checked: Vec<Intent>,
    /// The reference's replies; `None` where none came (a failed oracle
    /// stops the case).
    pub theirs: Vec<Option<Reply>>,
    /// dcroxide's answers; empty when the reference failed first.
    pub ours: Vec<Result<OursAnswer, String>>,
    /// The models' view of the case.
    pub view: ModelView,
    /// Every failed check, in the order they were made; empty when the
    /// input agreed.
    pub failures: Vec<Failure>,
}

impl Report {
    /// Whether every check passed.
    pub fn agreed(&self) -> bool {
        self.failures.is_empty()
    }

    /// What the first failure says, for the report's first line.
    fn headline(&self) -> &'static str {
        let Some(first) = self.failures.first() else {
            return match self.reference {
                Reference::Dcrd => "dcroxide and dcrd agree",
                Reference::Model => "dcroxide and the model of dcrd's Ed25519 agree",
            };
        };
        match first.category {
            Category::Verdict
            | Category::Value
            | Category::Flag
            | Category::Kind
            | Category::Text => match self.reference {
                Reference::Dcrd => "dcroxide and dcrd disagree",
                Reference::Model => {
                    "dcroxide and the model of dcrd's Ed25519 (src/model/ed25519.rs, frozen) \
                     disagree"
                }
            },
            Category::Intent => match first.request.and_then(|j| self.checked.get(j)) {
                Some(Intent::Branch(_)) => {
                    "an answer is not the one the ECDSA model of dcrd's verification gives \
                     (src/model/ecdsa.rs, frozen)"
                }
                Some(Intent::Schnorr(_)) => {
                    "an answer is not the one the Schnorr model of dcrd's verification gives \
                     (src/model/schnorr.rs, frozen)"
                }
                _ => {
                    "an answer is not the one the class's construction implies \
                     (src/gen/ed25519.rs, frozen)"
                }
            },
            Category::Protocol | Category::OracleCrashed | Category::OracleHung => {
                match self.reference {
                    Reference::Dcrd => "the oracle failed",
                    Reference::Model => "the model could not answer",
                }
            }
            Category::Consistency => "the requests' verdicts are inconsistent",
            Category::OursPanicked => "dcroxide panicked",
            Category::OursHung => "dcroxide did not finish",
        }
    }

    /// The requests with an intent failure and no other: dcroxide and the
    /// reference agree there, so the frozen model or construction may be
    /// the side in error.
    fn intent_only(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.requests.len()).filter(|&j| {
            let on_j = || self.failures.iter().filter(move |f| f.request == Some(j));
            on_j().any(|f| f.category == Category::Intent)
                && on_j().all(|f| f.category == Category::Intent)
        })
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} case {:#018x} (variant {:?}{}): {}",
            self.target,
            self.class,
            self.index,
            self.variant,
            if self.fallback { ", fell back" } else { "" },
            self.headline()
        )?;
        for failure in &self.failures {
            write!(f, "\n  {}", failure_line(failure))?;
        }
        for j in self.intent_only() {
            write!(
                f,
                "\n  dcroxide and {} agree on request {j}: replay this input against dcrd with \
                 `sigsoak fuzz-replay{}` before changing dcroxide; the frozen model or \
                 construction may be the side in error",
                self.reference.name(),
                match self.reference {
                    Reference::Dcrd => String::new(),
                    Reference::Model => format!(" --target {}", Target::Ed25519.name()),
                }
            )?;
        }
        for (j, request) in self.requests.iter().enumerate() {
            let lines = RequestLines {
                j,
                request,
                intent: &self.intents[j],
                checked: self.checked.get(j),
                ours_label: "dcroxide",
                ours: self.ours.get(j),
                theirs_label: self.reference.label(),
                theirs: self.theirs.get(j).and_then(Option::as_ref),
                model: self.view.per_request.get(j).copied().flatten(),
            };
            for line in lines.to_string().lines() {
                write!(f, "\n  {line}")?;
            }
        }
        write!(
            f,
            "\n  input: {}\n  replay: sigsoak fuzz-replay --target {} FILE (the input above, or \
             the crash file libFuzzer wrote)",
            hex(&self.input),
            self.target
        )
    }
}

impl std::error::Error for Report {}

/// The classes whose generator intents hold on every stream that does not
/// fall back: the generator computes each from the signature it built (the
/// realized challenge's k·T, or a grind that succeeded) rather than
/// assuming its construction landed.  [`rebase`] keeps their `Accept` and
/// `Reject` on cases without the [`Tag::Fallback`] tag.
pub const KEPT_INTENTS: [&str; 4] = [
    "DV-torsion",
    "DV-torsionSweep",
    "DV-torsionNoncanon",
    "DV-zeroS-smallR",
];

/// `case` of `class` as the fuzz targets compare it, with the models' view
/// of it, which is `model::view(case)`.  Request `j`'s intent becomes the
/// branch or reason the view gives it, when it gives one; the generator's
/// `Accept` or `Reject` for a class of [`KEPT_INTENTS`] on a case that did
/// not fall back; and [`Intent::Any`] otherwise.  The consistency rule and
/// the tags are cleared: under a chosen stream both are properties of the
/// construction, not of either side.
pub fn rebase(class: &ClassSpec, case: &Case) -> (Case, ModelView) {
    let view = model::view(case);
    let keep = KEPT_INTENTS.contains(&class.name) && !case.tags.has(Tag::Fallback);
    let intents = case
        .intents
        .iter()
        .zip(&view.per_request)
        .map(|(intent, outcome)| match outcome {
            Some(ModelOutcome::Ecdsa { branch, .. }) => Intent::Branch(*branch),
            Some(ModelOutcome::Schnorr { reason, .. }) => Intent::Schnorr(*reason),
            None if keep && matches!(intent, Intent::Accept | Intent::Reject) => intent.clone(),
            None => Intent::Any,
        })
        .collect();
    let rebased = Case {
        variant: case.variant.clone(),
        requests: case.requests.clone(),
        intents,
        consistency: Consistency::None,
        tags: Tags::NONE,
    };
    (rebased, view)
}

/// The case a check is on, for the panic hook ([`install_panic_context`]).
struct Context {
    target: &'static str,
    reference: Reference,
    class: &'static str,
    index: u64,
    /// The case's variant, once it is generated.
    variant: Option<String>,
    /// The case's requests, once it is generated.
    requests: Vec<Request>,
    /// The reference's replies, as received.
    replies: Vec<String>,
    /// The request dcroxide is answering.
    request: Option<usize>,
}

thread_local! {
    /// The case a check on this thread is on.
    static CONTEXT: RefCell<Option<Context>> = const { RefCell::new(None) };
}

/// Changes this thread's context, unless it is borrowed or being destroyed.
fn update_context(change: impl FnOnce(&mut Option<Context>)) {
    let _ = CONTEXT.try_with(|cell| {
        if let Ok(mut context) = cell.try_borrow_mut() {
            change(&mut context);
        }
    });
}

/// Holds a check's context, and clears it when the check returns or
/// unwinds.
struct ContextGuard;

impl ContextGuard {
    fn begin(context: Context) -> ContextGuard {
        update_context(|slot| *slot = Some(context));
        ContextGuard
    }

    fn update(&self, change: impl FnOnce(&mut Context)) {
        update_context(|slot| {
            if let Some(context) = slot.as_mut() {
                change(context);
            }
        });
    }
}

impl Drop for ContextGuard {
    fn drop(&mut self) {
        update_context(|slot| *slot = None);
    }
}

/// The context as the panic hook prints it.
fn context_line(c: &Context) -> String {
    let case = format!("{} case {:#018x}", c.class, c.index);
    let Some(variant) = &c.variant else {
        return format!("{}: while generating {case}", c.target);
    };
    let Some(j) = c.request else {
        return format!("{}: while checking {case} (variant {variant:?})", c.target);
    };
    let request = c
        .requests
        .get(j)
        .map(|r| format!(" {} {}", r.cmd.name(), hex(&r.data)))
        .unwrap_or_default();
    let answered = c
        .replies
        .get(j)
        .map(|raw| format!("; {} answered {raw}", c.reference.name()))
        .unwrap_or_default();
    format!(
        "{}: while answering {case} (variant {variant:?}), request {j}{request}{answered}",
        c.target
    )
}

/// Wraps the panic hook in place (libfuzzer-sys's, which aborts, in a fuzz
/// target) with one that first prints the case a check on the panicking
/// thread is on, if any: in a libFuzzer binary a panic in dcroxide or in a
/// generator then names its case.  Installed once per process.
pub fn install_panic_context() {
    static INSTALLED: Once = Once::new();
    INSTALLED.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let line = CONTEXT
                .try_with(|cell| {
                    cell.try_borrow()
                        .ok()
                        .and_then(|context| context.as_ref().map(context_line))
                })
                .ok()
                .flatten();
            if let Some(line) = line {
                eprintln!("{line}");
            }
            previous(info);
        }));
    });
}

/// `data` decoded as an input of `target` and checked against
/// `reference`, which `theirs` answers for; `None` when no class is
/// reached.  The model has no signer, so a case of `ed25519_sign` held to
/// it is checked by verifying dcroxide's signatures under it instead.
fn examine_with(
    reference: Reference,
    target_name: &'static str,
    target: Target,
    data: &[u8],
    ours: Ours<'_>,
    theirs: Theirs<'_>,
) -> Option<Report> {
    let (class, index, mut entropy) = locate(target, data)?;
    let guard = ContextGuard::begin(Context {
        target: target_name,
        reference,
        class: class.name,
        index,
        variant: None,
        requests: Vec::new(),
        replies: Vec::new(),
        request: None,
    });
    let case = generate_from(class, index, &mut entropy);
    guard.update(|c| {
        c.variant = Some(case.variant.to_string());
        c.requests = case.requests.clone();
    });
    let (rebased, view) = rebase(class, &case);
    let n = case.requests.len();
    let mut report = Report {
        reference,
        target: target_name,
        input: data.to_vec(),
        class: class.name,
        index,
        variant: case.variant.into_owned(),
        fallback: case.tags.has(Tag::Fallback),
        requests: case.requests,
        intents: case.intents,
        checked: rebased.intents.clone(),
        theirs: vec![None; n],
        ours: Vec::with_capacity(n),
        view,
        failures: Vec::new(),
    };
    if reference == Reference::Model && report.requests.iter().any(|r| r.cmd == Cmd::Ed25519Sign) {
        report.failures = verify_signatures(&report.requests, ours, &guard, &mut report.ours);
        return Some(report);
    }
    let mut replies = Vec::with_capacity(n);
    for (j, request) in report.requests.iter().enumerate() {
        match theirs(request) {
            Ok(reply) => replies.push(reply),
            Err((category, detail)) => {
                report.failures.push(Failure {
                    category,
                    request: Some(j),
                    detail,
                });
                for (slot, reply) in report.theirs.iter_mut().zip(replies) {
                    *slot = Some(reply);
                }
                return Some(report);
            }
        }
    }
    guard.update(|c| c.replies = replies.iter().map(|r| r.raw.clone()).collect());
    for (j, request) in report.requests.iter().enumerate() {
        guard.update(|c| c.request = Some(j));
        report.ours.push(ours(request.cmd, &request.data));
    }
    let result = compare(&rebased, &report.ours, &replies, &report.view);
    report.failures = result.failures;
    report.theirs = replies.into_iter().map(Some).collect();
    Some(report)
}

/// The model target's check of a signing case: each of dcroxide's
/// signatures must be a signature and key, the key must parse under the
/// model and the signature verify under it.  The model has no signer, so
/// the bytes are not compared.
fn verify_signatures(
    requests: &[Request],
    ours: Ours<'_>,
    guard: &ContextGuard,
    answers: &mut Vec<Result<OursAnswer, String>>,
) -> Vec<Failure> {
    let mut failures = Vec::new();
    for (j, request) in requests.iter().enumerate() {
        let mut fail = |category: Category, detail: String| {
            failures.push(Failure {
                category,
                request: Some(j),
                detail,
            });
        };
        guard.update(|c| c.request = Some(j));
        let answer = ours(request.cmd, &request.data);
        let msg = match request.data.split_first_chunk::<32>() {
            Some((_, msg)) if request.cmd == Cmd::Ed25519Sign => msg,
            _ => {
                fail(
                    Category::Protocol,
                    if request.cmd == Cmd::Ed25519Sign {
                        "the model could not read the request".to_owned()
                    } else {
                        format!(
                            "the model has no signer, so it checks a case that signs by its \
                             signatures alone, and cannot check {} beside them",
                            request.cmd.name()
                        )
                    },
                );
                answers.push(answer);
                continue;
            }
        };
        match &answer {
            Err(message) => fail(Category::OursPanicked, message.clone()),
            Ok(o) => {
                if let Err(why) = verifies_under_model(&o.answer, msg) {
                    fail(
                        Category::Verdict,
                        format!("dcroxide's signature does not verify under the model: {why}"),
                    );
                }
            }
        }
        answers.push(answer);
    }
    failures
}

/// Whether `answer`, dcroxide's to an `ed25519_sign` of `msg`, is a
/// signature and key (`signature ‖ key`, 96 bytes) whose key parses under
/// the model and whose signature verifies under it.
fn verifies_under_model(answer: &Answer, msg: &[u8]) -> Result<(), String> {
    let Answer::Value { bytes, flag: None } = answer else {
        return Err(format!("the answer is {}", answer.describe()));
    };
    let Some((sig, key)) = bytes.split_first_chunk::<64>() else {
        return Err(format!("the answer is {} bytes, not 96", bytes.len()));
    };
    if key.len() != 32 {
        return Err(format!("the answer is {} bytes, not 96", bytes.len()));
    }
    let key = model::ed25519::parse_pub_key(key)
        .map_err(|text| format!("the key {} does not parse: {text}", hex(key)))?;
    model::ed25519::verify(&key, msg, sig).map_err(|reason| format!("{reason:?}"))
}

/// The model's reply to an Ed25519 parse or verify request, shaped as the
/// oracle's: a value in hex, a verdict, or dcrd's error text.
fn model_reply(request: &Request) -> Result<Reply, (Category, String)> {
    use model::ed25519::{Outcome, parse_pub_key, parse_signature, verify_request};
    let value = match request.cmd {
        Cmd::Ed25519PubkeyParse => match parse_pub_key(&request.data) {
            Ok(key) => json!({ "result": hex(&key.canonical) }),
            Err(text) => json!({ "error": text }),
        },
        Cmd::Ed25519Parse => match parse_signature(&request.data) {
            Ok(sig) => json!({ "result": hex(&sig) }),
            Err(text) => json!({ "error": text }),
        },
        Cmd::Ed25519Verify => match verify_request(request) {
            Some(Outcome::Verified(Ok(()))) => json!({ "result": "true" }),
            Some(Outcome::Verified(Err(_))) => json!({ "result": "false" }),
            Some(Outcome::KeyRejected(text)) => json!({ "error": text }),
            None => {
                return Err((
                    Category::Protocol,
                    "the model could not read the request".to_owned(),
                ));
            }
        },
        other => {
            return Err((
                Category::Protocol,
                format!("the model does not answer {}", other.name()),
            ));
        }
    };
    Reply::from_json(&value).map_err(|why| (Category::Protocol, why))
}

/// `data` decoded as an input of `target`, answered by `theirs` (dcrd)
/// and by `ours` (dcroxide), and compared, keeping everything whatever the
/// outcome: `None` when no class is reached.  dcrd answers first, so that
/// the panic context can show its answer when dcroxide panics, and an
/// answer it fails to give ends the case.
pub fn examine(target: Target, data: &[u8], ours: Ours<'_>, theirs: Theirs<'_>) -> Option<Report> {
    examine_with(Reference::Dcrd, target.name(), target, data, ours, theirs)
}

/// [`examine`], an agreement reduced to [`Checked::Agreed`] and anything
/// else a finding.
pub fn check(
    target: Target,
    data: &[u8],
    ours: Ours<'_>,
    theirs: Theirs<'_>,
) -> Result<Checked, Box<Report>> {
    conclude(examine(target, data, ours, theirs))
}

/// `data` decoded as a `dcrec_diff_ed25519` input and answered by dcroxide
/// and by the Go-free model of dcrd's Ed25519, with no oracle: each parse
/// and verify request gets the model's reply in place of dcrd's and is
/// compared as dcrd's would be, and each signature dcroxide makes must
/// verify under the model.
pub fn examine_ed25519_model(data: &[u8], ours: Ours<'_>) -> Option<Report> {
    examine_with(
        Reference::Model,
        ED25519_MODEL_TARGET,
        Target::Ed25519,
        data,
        ours,
        &mut model_reply,
    )
}

/// [`examine_ed25519_model`], an agreement reduced to
/// [`Checked::Agreed`] and anything else a finding.
pub fn check_ed25519_model(data: &[u8], ours: Ours<'_>) -> Result<Checked, Box<Report>> {
    conclude(examine_ed25519_model(data, ours))
}

fn conclude(report: Option<Report>) -> Result<Checked, Box<Report>> {
    match report {
        None => Ok(Checked::NoClass),
        Some(report) if report.agreed() => Ok(Checked::Agreed {
            class: report.class,
            index: report.index,
            fallback: report.fallback,
        }),
        Some(report) => Err(Box::new(report)),
    }
}

/// An oracle for a fuzz process: one `dcrd-oracle`, its pin checked,
/// answering one request at a time.
pub struct FuzzOracle {
    oracle: Oracle,
    build_info: Reply,
}

impl FuzzOracle {
    /// Asks `oracle` for its `build_info` and requires the pin rule
    /// ([`check_pin`]): both signature modules at `tools/oracle/go.mod`'s
    /// versions, no replacement, pseudo-versions naming the harness pin.
    pub fn new(mut oracle: Oracle) -> Result<FuzzOracle, String> {
        let line = oracle
            .try_call_line("build_info", &[])
            .map_err(|why| format!("the oracle did not answer build_info: {why}"))?;
        let build_info = Reply::from_line(line)
            .map_err(|why| format!("the oracle's build_info is unreadable: {why}"))?;
        let pin = check_pin(&build_info);
        if !pin.consistent() {
            return Err(format!(
                "the oracle's pin check failed: {}",
                pin.problems().join("; ")
            ));
        }
        Ok(FuzzOracle { oracle, build_info })
    }

    /// The oracle's `build_info`.
    pub fn build_info(&self) -> &Reply {
        &self.build_info
    }

    /// The oracle's Go and signature modules, for a line of a log.
    pub fn describe(&self) -> String {
        let mut line = format!(
            "oracle {}",
            self.build_info
                .go_version
                .as_deref()
                .unwrap_or("of unknown Go")
        );
        for module in SIGNATURE_MODULES {
            let short = module
                .strip_prefix("github.com/decred/dcrd/dcrec/")
                .unwrap_or(module);
            let version = self
                .build_info
                .modules
                .get(module)
                .map_or("unknown", String::as_str);
            let _ = write!(line, ", {short} {version}");
        }
        line
    }

    /// The oracle's reply to `request`: an oracle that does not answer is
    /// `oracle-crashed`, with its exit status, and a reply that is not a
    /// response object is `protocol`.
    pub fn answer(&mut self, request: &Request) -> Result<Reply, (Category, String)> {
        let line = self
            .oracle
            .try_call_line(request.cmd.name(), &request.data)
            .map_err(|why| (Category::OracleCrashed, why))?;
        Reply::from_line(line).map_err(|why| (Category::Protocol, why))
    }
}

/// The process oracle, spawned on first use as testutil spawns one
/// (`DCROXIDE_ORACLE_BIN`, or `tools/oracle` built with Go), its pin
/// checked; a missing oracle or a failed pin check panics.  libFuzzer runs
/// inputs on one thread, so the lock is uncontended.
fn process_oracle() -> &'static Mutex<FuzzOracle> {
    static ORACLE: OnceLock<Mutex<FuzzOracle>> = OnceLock::new();
    ORACLE.get_or_init(|| {
        let oracle = FuzzOracle::new(Oracle::spawn())
            .unwrap_or_else(|why| panic!("dcroxide-sigdiff fuzz: {why}"));
        eprintln!("dcroxide-sigdiff fuzz: {}", oracle.describe());
        Mutex::new(oracle)
    })
}

/// For an oracle-backed target's `init`: installs the panic context and
/// starts the process oracle, so that a missing oracle or a failed pin
/// check ends the process before it fuzzes.
pub fn init_oracle_target() {
    install_panic_context();
    process_oracle();
}

/// One input of an oracle-backed target against the process oracle:
/// panics with the report of a finding, and otherwise returns whether a
/// class was reached (the target's `Corpus::Keep`, or `Corpus::Reject`).
/// The oracle's lock is released before the panic, so a caller that
/// catches it can go on.
pub fn fuzz_one(target: Target, data: &[u8], ours: Ours<'_>) -> bool {
    let result = {
        let mut oracle = process_oracle()
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        check(target, data, ours, &mut |request| oracle.answer(request))
    };
    keep(result)
}

/// For `dcrec_ed25519_model`: [`check_ed25519_model`], panicking with the
/// report of a finding, and otherwise whether a class was reached.
pub fn fuzz_ed25519_model(data: &[u8], ours: Ours<'_>) -> bool {
    keep(check_ed25519_model(data, ours))
}

fn keep(result: Result<Checked, Box<Report>>) -> bool {
    match result {
        Ok(Checked::NoClass) => false,
        Ok(Checked::Agreed { .. }) => true,
        Err(report) => panic!("{report}"),
    }
}

/// The default master seed of `sigsoak fuzz-seeds`: "fuzzseed" in ASCII.
pub const SEED_MASTER: u64 = 0x6675_7a7a_7365_6564;

/// SplitMix64 that keeps every word it gives.  Only `next_u64` is
/// overridden, so every other draw is the trait's, as SplitMix64's is.
struct Recording {
    rng: SplitMix64,
    words: Vec<u64>,
}

impl Entropy for Recording {
    fn next_u64(&mut self) -> u64 {
        let word = self.rng.next_u64();
        self.words.push(word);
        word
    }
}

/// The input that decodes, in its class's target, to exactly case `index`
/// of `class` under `master` ([`crate::class::generate`]): the selector,
/// the index (8 bytes LE), then every word the generator drew from
/// SplitMix64 seeded with the case seed, 8 bytes LE each.  Panics unless
/// it decodes to that case.
pub fn seed_input(class: &'static ClassSpec, master: u64, index: u64) -> Vec<u8> {
    let target = Target::of_class(class);
    let selector = target
        .selector_of(class.name)
        .unwrap_or_else(|| panic!("{} has no slot in {}", class.name, target.name()));
    let mut recording = Recording {
        rng: SplitMix64(case_seed(master, class.name, index)),
        words: Vec::new(),
    };
    let case = generate_from(class, index, &mut recording);
    let mut input = Vec::with_capacity(recording.words.len().saturating_add(1).saturating_mul(8));
    input.push(selector);
    input.extend_from_slice(&index.to_le_bytes());
    for word in recording.words {
        input.extend_from_slice(&word.to_le_bytes());
    }
    let decoded = decode(target, &input).expect("a seed input reaches its class");
    assert!(
        decoded.class.name == class.name && decoded.index == index && decoded.case == case,
        "{} case {index}: the seed input decodes to another case",
        class.name
    );
    input
}

/// The indices of `class` the per-PR tests take, `cases` (or the class's
/// own count) as the run loop plans them: [`run::class_indices`] under
/// [`Mode::PerPr`].
pub fn seed_indices(class: &'static ClassSpec, cases: Option<u64>) -> Vec<u64> {
    run::class_indices(class, Mode::PerPr { cases }).collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::answer::Detail;
    use crate::class::{CLASSES, generate};
    use crate::model::EcdsaBranch;

    /// The slot tables as A8 wrote them, kept apart from the live tables:
    /// a live table must start with its golden copy, slot for slot.
    const GOLDEN: [(Target, &[&str]); 5] = [
        (
            Target::Ecdsa,
            &[
                "EV-honest",
                "EV-highS",
                "EV-tamper",
                "EV-random",
                "EV-keyenc",
                "EV-keys",
                "EV-hashGEN",
                "EV-hash0",
                "EV-zero",
                "EV-range",
                "EV-xGEN-true",
                "EV-xGEN-false",
                "EV-xGEN-wrap",
                "EV-infinity",
                "EV-double",
                "EV-sEdge",
                "EV-rEdge",
                "EV-smallXKey",
                "ES-random",
                "ES-hashGEN",
                "ES-boundary",
                "ES-compact",
                "DER-valid",
                "DER-mutate",
                "DER-structured",
                "DER-kind",
            ],
        ),
        (
            Target::Recover,
            &[
                "ER-honest",
                "ER-flipParity",
                "ER-highS",
                "ER-overflowValid",
                "ER-overflowPrime",
                "ER-notOnCurve",
                "ER-infinity",
                "ER-double",
                "ER-header",
                "ER-length",
                "ER-range",
                "ER-hash",
            ],
        ),
        (
            Target::Pubkey,
            &[
                "K-valid",
                "K-hybridMismatch",
                "K-XTooBig",
                "K-YTooBig",
                "K-wrap",
                "K-nearP",
                "K-offCurve",
                "K-negY",
                "K-mutate",
                "K-smallX",
                "K-format",
                "K-length",
            ],
        ),
        (
            Target::Schnorr,
            &[
                "SS-random",
                "SS-hashGEN",
                "SS-boundary",
                "SP-random",
                "SP-rRange",
                "SV-honest",
                "SV-tamper",
                "SV-random",
                "SV-hashGEN",
                "SV-zeroS",
                "SV-infinity",
                "SV-oddR",
                "SV-rGEN-true",
                "SV-rGEN-odd",
                "SV-unequalR",
                "SV-double",
            ],
        ),
        (
            Target::Ed25519,
            &[
                "DS-random",
                "DK-canonical",
                "DK-random",
                "DK-small",
                "DK-length",
                "DG-edges",
                "DG-random",
                "DV-honest",
                "DV-tamper",
                "DV-SplusL",
                "DV-topBits",
                "DV-random",
                "DV-torsion",
                "DV-torsionSweep",
                "DV-torsionNoncanon",
                "DV-zeroS-smallR",
            ],
        ),
    ];

    /// Whether `live` grew from `golden` by the tables' rules: at least as
    /// long, and equal slot by slot, a retired slot standing in for any
    /// name.
    fn grows(golden: &[&str], live: &[&str]) -> Result<(), String> {
        if live.len() < golden.len() {
            return Err(format!(
                "{} slots, fewer than the {} it had",
                live.len(),
                golden.len()
            ));
        }
        match golden
            .iter()
            .zip(live)
            .enumerate()
            .find(|(_, (was, is))| was != is && **is != RETIRED)
        {
            Some((selector, (was, is))) => Err(format!(
                "selector {selector} reached {was} and now reaches {is}: append, never \
                 reorder, and retire a removed class's slot"
            )),
            None => Ok(()),
        }
    }

    /// Each table reaches its families' classes exactly once and nothing
    /// else, within 256 slots, so a new class cannot go unfuzzed; the five
    /// together reach every class.
    #[test]
    fn the_slot_tables_cover_their_families() {
        let mut reached = BTreeSet::new();
        for target in Target::ALL {
            let slots = target.slots();
            assert!(slots.len() <= 256, "{}", target.name());
            let mut seen = BTreeSet::new();
            for name in slots.iter().filter(|n| **n != RETIRED) {
                let class = find_class(name)
                    .unwrap_or_else(|| panic!("{}: {name} is no class", target.name()));
                assert!(
                    target.families().contains(&class.family),
                    "{}: {name} is a {:?} class",
                    target.name(),
                    class.family
                );
                assert!(seen.insert(*name), "{}: {name} twice", target.name());
                assert_eq!(Target::of_class(class), target, "{name}");
                assert!(reached.insert(*name), "{name} in two tables");
            }
            for class in CLASSES
                .iter()
                .filter(|c| target.families().contains(&c.family))
            {
                assert!(
                    seen.contains(class.name),
                    "{}: {} has no slot",
                    target.name(),
                    class.name
                );
            }
            assert_eq!(Target::find(target.name()), Some(target));
        }
        assert_eq!(reached.len(), CLASSES.len());
        assert_eq!(reached.len(), 82);
        assert_eq!(Target::find(ED25519_MODEL_TARGET), None);
    }

    /// A selector reaches its slot's class, nothing past the table or at a
    /// retired slot, and `selector_of` inverts it.
    #[test]
    fn selectors_reach_their_slots() {
        for target in Target::ALL {
            for selector in 0..=u8::MAX {
                match target.class_at(selector) {
                    Some(class) => {
                        assert_eq!(target.slots()[usize::from(selector)], class.name);
                        assert_eq!(target.selector_of(class.name), Some(selector));
                    }
                    None => {
                        let slot = target.slots().get(usize::from(selector));
                        assert!(
                            slot.is_none_or(|name| *name == RETIRED),
                            "{}: selector {selector} reaches nothing at {slot:?}",
                            target.name()
                        );
                    }
                }
            }
            let live = target.slots().iter().filter(|name| **name != RETIRED);
            assert_eq!(target.classes().count(), live.count(), "{}", target.name());
        }
        let slots = ["EV-honest", RETIRED, "EV-highS"];
        assert_eq!(class_in(&slots, 0).map(|c| c.name), Some("EV-honest"));
        assert!(class_in(&slots, 1).is_none(), "a retired slot");
        assert_eq!(class_in(&slots, 2).map(|c| c.name), Some("EV-highS"));
        assert!(class_in(&slots, 3).is_none(), "past the table");
        assert_eq!(Target::Ecdsa.selector_of("K-valid"), None);
    }

    /// The live tables start with the tables A8 wrote, slot for slot, so a
    /// crash input or a cached corpus entry keeps naming its class; a
    /// table may grow at its end, and a slot may only be retired.
    #[test]
    fn the_slot_tables_only_grow() {
        for (target, golden) in GOLDEN {
            if let Err(why) = grows(golden, target.slots()) {
                panic!("{}: {why}", target.name());
            }
        }
        let a8 = ["EV-honest", "EV-highS", "EV-tamper"];
        assert_eq!(
            grows(&a8, &["EV-honest", "EV-highS", "EV-tamper", "X"]),
            Ok(())
        );
        assert_eq!(grows(&a8, &["EV-honest", RETIRED, "EV-tamper"]), Ok(()));
        for (live, selector) in [
            (&["EV-highS", "EV-honest", "EV-tamper"][..], 0),
            (&["EV-honest", "X", "EV-highS", "EV-tamper"][..], 1),
            (&["EV-honest", "EV-highS", "EV-tampered"][..], 2),
        ] {
            let why = grows(&a8, live).expect_err("not grown");
            assert!(why.starts_with(&format!("selector {selector} ")), "{why}");
        }
        assert!(grows(&a8, &["EV-honest"]).is_err());
    }

    /// The input `[selector][index LE][entropy]` of `class` in its target.
    fn input(class: &ClassSpec, index: u64, entropy: &[u8]) -> Vec<u8> {
        let target = Target::of_class(class);
        let mut input = vec![target.selector_of(class.name).expect("a slot")];
        input.extend_from_slice(&index.to_le_bytes());
        input.extend_from_slice(entropy);
        input
    }

    /// An empty input or a selector past the table reaches nothing; a
    /// finite class's index is reduced modulo its size, whatever the
    /// index bytes, before its generator allocates by it; and every class
    /// makes a well-formed case of its selector alone, an all-zero
    /// stream.
    #[test]
    fn decode_reads_the_selector_the_index_and_the_entropy() {
        for target in Target::ALL {
            assert!(decode(target, &[]).is_none());
            let past = u8::try_from(target.slots().len()).expect("a short table");
            assert!(decode(target, &[past]).is_none());
            assert!(decode(target, &[u8::MAX, 1, 2, 3]).is_none());
        }
        for class in CLASSES {
            let target = Target::of_class(class);
            let selector = target.selector_of(class.name).expect("a slot");
            let decoded = decode(target, &[selector]).expect("a class");
            assert_eq!((decoded.class.name, decoded.index), (class.name, 0));
            match class.size.finite() {
                Some(size) => {
                    for raw in [u64::MAX, u64::MAX.saturating_sub(1), size] {
                        let decoded = decode(target, &input(class, raw, &[])).expect("a class");
                        assert_eq!(Some(decoded.index), raw.checked_rem(size), "{}", class.name);
                    }
                }
                None => {
                    let decoded =
                        decode(target, &input(class, u64::MAX, &[7; 40])).expect("a class");
                    assert_eq!(decoded.index, u64::MAX, "{}", class.name);
                }
            }
        }
    }

    /// A seed input decodes to exactly the soak's case, consumed to its
    /// last byte, at the indices the per-PR tests take.
    #[test]
    fn seed_inputs_regenerate_their_cases() {
        let master = 0x5eed_f022_0000_0001;
        for class in CLASSES {
            let indices = seed_indices(class, Some(4));
            assert_eq!(
                indices,
                run::class_indices(class, Mode::PerPr { cases: Some(4) }).collect::<Vec<_>>()
            );
            let expected = match class.size.finite() {
                Some(size) if size <= 128 => size,
                _ => 4,
            };
            assert_eq!(indices.len() as u64, expected, "{}", class.name);
            for index in indices {
                let input = seed_input(class, master, index);
                let decoded = decode(Target::of_class(class), &input).expect("a class");
                assert_eq!(decoded.class.name, class.name);
                assert_eq!(decoded.index, index);
                assert_eq!(
                    decoded.case,
                    generate(class, master, index),
                    "{} case {index}",
                    class.name
                );
                let mut again = ByteEntropy::new(&input[9..]);
                let _ = (class.generator)(&mut again, index);
                assert!(
                    again.is_exhausted(),
                    "{} case {index}: the generator draws every word",
                    class.name
                );
            }
        }
        let counts: Vec<usize> = Target::ALL
            .iter()
            .map(|t| t.classes().map(|c| seed_indices(c, None).len()).sum())
            .collect();
        assert_eq!(counts, [1_276, 836, 631, 768, 1_055], "per-PR seed inputs");
    }

    /// A Branch or Schnorr intent becomes the model's view of its request,
    /// or `Any` where the model reads none; a kept class's `Accept` and
    /// `Reject` stay unless the case fell back; every other intent becomes
    /// `Any`; the consistency rule and the tags are cleared.
    #[test]
    fn rebase_holds_requests_to_the_models_view() {
        let class = |name| find_class(name).expect("registered");
        let xgen = class("EV-xGEN-true");
        let case = generate(xgen, 3, 0);
        assert_eq!(case.intents, [Intent::Branch(EcdsaBranch::Step10Accept)]);
        let (rebased, view) = rebase(xgen, &case);
        let Some(Some(ModelOutcome::Ecdsa { branch, .. })) = view.per_request.first() else {
            panic!("the ECDSA model reads EV-xGEN-true: {view:?}");
        };
        assert_eq!(rebased.intents, [Intent::Branch(*branch)]);
        assert_eq!(rebased.requests, case.requests);

        let mut unreadable = case.clone();
        unreadable.requests.push(Request {
            cmd: Cmd::EcdsaVerify,
            data: vec![0; 3],
        });
        unreadable
            .intents
            .push(Intent::Branch(EcdsaBranch::Step8Accept));
        let (rebased, _) = rebase(xgen, &unreadable);
        assert_eq!(rebased.intents[1], Intent::Any);

        let sv = class("SV-honest");
        let (rebased, view) = rebase(sv, &generate(sv, 3, 0));
        let Some(Some(ModelOutcome::Schnorr { reason, .. })) = view.per_request.first() else {
            panic!("the Schnorr model reads SV-honest: {view:?}");
        };
        assert_eq!(rebased.intents, [Intent::Schnorr(*reason)]);

        for name in ["DS-random", "K-XTooBig", "DK-canonical", "EV-honest"] {
            let (rebased, _) = rebase(class(name), &generate(class(name), 3, 0));
            assert!(
                rebased.intents.iter().all(|i| *i == Intent::Any),
                "{name}: {:?}",
                rebased.intents
            );
        }

        let torsion = class("DV-torsion");
        for index in 0..32 {
            let case = generate(torsion, 3, index);
            assert!(!case.tags.has(Tag::Fallback));
            let (rebased, _) = rebase(torsion, &case);
            assert_eq!(rebased.intents, case.intents, "DV-torsion case {index}");
            assert!(
                case.intents
                    .iter()
                    .all(|i| matches!(i, Intent::Accept | Intent::Reject))
            );
            let mut fell_back = case.clone();
            fell_back.tags = fell_back.tags.with(Tag::Fallback);
            let (rebased, _) = rebase(torsion, &fell_back);
            assert!(rebased.intents.iter().all(|i| *i == Intent::Any));
        }

        // The view is model::view's, of the case and of its rebase alike,
        // for each class's first cases on an all-zero stream and seeded.
        for class in CLASSES {
            for index in 0..3 {
                let zeros = generate_from(class, index, &mut ByteEntropy::new(&[]));
                for case in [zeros, generate(class, 9, index)] {
                    let (rebased, view) = rebase(class, &case);
                    assert_eq!(view, model::view(&case), "{} case {index}", class.name);
                    assert_eq!(view, model::view(&rebased), "{} case {index}", class.name);
                    assert_eq!(rebased.consistency, Consistency::None);
                    assert_eq!(rebased.tags, Tags::NONE);
                    assert_eq!(rebased.requests, case.requests);
                    assert_eq!(rebased.variant, case.variant);
                }
            }
        }
    }

    /// The torsion classes' intents are the realized algebra's, so they
    /// hold on any stream whose case did not fall back: under an all-zero
    /// stream, an all-0xff stream and eight random ones, each case gets
    /// the model verdict its intent names.  The streams run on threads of
    /// their own, since each takes seconds in a debug build.
    #[test]
    fn the_kept_intents_hold_on_any_stream() {
        use model::ed25519::{Outcome, verify_request};
        let mut streams: Vec<Vec<u8>> = vec![Vec::new(), vec![0xff; 8_192]];
        let mut rng = SplitMix64(0x6b65_7074_696e_7473);
        for _ in 0..8 {
            let mut stream = vec![0; 8_192];
            rng.fill(&mut stream);
            streams.push(stream);
        }
        let check_stream = |k: usize, stream: &[u8]| -> u64 {
            let mut checked = 0u64;
            for name in KEPT_INTENTS {
                let class = find_class(name).expect("registered");
                for index in seed_indices(class, None) {
                    let case = generate_from(class, index, &mut ByteEntropy::new(stream));
                    if case.tags.has(Tag::Fallback) {
                        continue;
                    }
                    for (j, (request, intent)) in
                        case.requests.iter().zip(&case.intents).enumerate()
                    {
                        let accepted =
                            matches!(verify_request(request), Some(Outcome::Verified(Ok(()))));
                        let want = match intent {
                            Intent::Accept => true,
                            Intent::Reject => false,
                            other => panic!("{name} case {index} request {j}: {other:?}"),
                        };
                        assert_eq!(
                            accepted, want,
                            "{name} case {index} request {j}, stream {k}: {intent:?}"
                        );
                        checked = checked.saturating_add(1);
                    }
                }
            }
            checked
        };
        let checked: u64 = std::thread::scope(|s| {
            let threads: Vec<_> = streams
                .iter()
                .enumerate()
                .map(|(k, stream)| s.spawn(move || check_stream(k, stream)))
                .collect();
            threads
                .into_iter()
                .map(|t| t.join().expect("a stream's check"))
                .fold(0, u64::saturating_add)
        });
        assert!(checked > 3_000, "{checked} requests checked");
    }

    /// A reply with this JSON.
    fn reply(json: &str) -> Reply {
        Reply::from_line(json).expect("a reply")
    }

    /// The answerer that panics: the check must not reach it.
    fn unreached(_: Cmd, _: &[u8]) -> Result<OursAnswer, String> {
        panic!("dcroxide was asked")
    }

    /// The fake dcrd answers, the fake dcroxide answers, and each failure
    /// is a finding: a verdict that differs, an oracle that fails (with no
    /// dcroxide answer), a dcroxide panic, and a verdict both sides give
    /// that the ECDSA model does not; agreeing fakes agree, and an input
    /// that reaches no class asks neither.
    #[test]
    fn check_holds_both_answers_and_the_rebased_intents() {
        let honest = find_class("EV-honest").expect("registered");
        let data = seed_input(honest, 1, 5);
        let verdict = |v: bool| Ok(OursAnswer::plain(Answer::Verdict(v)));
        let dcrd_true = &mut |_: &Request| Ok(reply(r#"{"result":"true"}"#));

        let report =
            check(Target::Ecdsa, &data, &|_, _| verdict(false), dcrd_true).expect_err("a finding");
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.category == Category::Verdict),
            "{report}"
        );
        assert_eq!(report.headline(), "dcroxide and dcrd disagree");
        assert_eq!((report.class, report.index), ("EV-honest", 5));

        assert_eq!(
            check(Target::Ecdsa, &data, &|_, _| verdict(true), dcrd_true),
            Ok(Checked::Agreed {
                class: "EV-honest",
                index: 5,
                fallback: false
            })
        );

        let report = check(Target::Ecdsa, &data, &unreached, &mut |_| {
            Err((Category::OracleCrashed, "gone (exit status: 2)".to_owned()))
        })
        .expect_err("a finding");
        assert!(report.ours.is_empty());
        assert_eq!(report.failures[0].category, Category::OracleCrashed);
        assert_eq!(report.headline(), "the oracle failed");
        assert!(
            report.to_string().contains("dcroxide: no answer"),
            "{report}"
        );

        let report = check(
            Target::Ecdsa,
            &data,
            &|_, _| Err("boom".to_owned()),
            dcrd_true,
        )
        .expect_err("a finding");
        assert_eq!(report.failures[0].category, Category::OursPanicked);
        assert_eq!(report.headline(), "dcroxide panicked");

        let xgen = find_class("EV-xGEN-true").expect("registered");
        let data = seed_input(xgen, 1, 0);
        let report = check(Target::Ecdsa, &data, &|_, _| verdict(false), &mut |_| {
            Ok(reply(r#"{"result":"false"}"#))
        })
        .expect_err("a finding");
        assert_eq!(
            report
                .failures
                .iter()
                .map(|f| f.category)
                .collect::<Vec<_>>(),
            [Category::Intent]
        );
        assert!(report.headline().contains("src/model/ecdsa.rs"), "{report}");
        assert!(
            report
                .to_string()
                .contains("dcroxide and dcrd agree on request 0: replay this input"),
            "{report}"
        );

        let past = u8::try_from(Target::Ecdsa.slots().len()).expect("short");
        assert_eq!(
            check(Target::Ecdsa, &[past, 1, 2], &unreached, &mut |_| panic!(
                "dcrd was asked"
            )),
            Ok(Checked::NoClass)
        );
    }

    /// The model has no signer: a signature dcroxide makes is checked by
    /// verifying it under the model, and one that does not verify, or an
    /// answer that is no signature, is a finding against the model.
    #[test]
    fn the_model_target_verifies_dcroxides_signatures() {
        let ds = find_class("DS-random").expect("registered");
        let data = seed_input(ds, 1, 0);
        let zeros = |_: Cmd, _: &[u8]| {
            Ok(OursAnswer::plain(Answer::Value {
                bytes: vec![0; 96],
                flag: None,
            }))
        };
        let report = check_ed25519_model(&data, &zeros).expect_err("a finding");
        assert_eq!(report.reference, Reference::Model);
        assert_eq!(report.failures.len(), 1, "{report}");
        assert_eq!(report.failures[0].category, Category::Verdict);
        assert!(
            report.failures[0]
                .detail
                .starts_with("dcroxide's signature does not verify under the model: "),
            "{report}"
        );
        assert!(
            report.headline().contains("src/model/ed25519.rs"),
            "{report}"
        );
        let verdict = |_: Cmd, _: &[u8]| Ok(OursAnswer::plain(Answer::Verdict(true)));
        let report = check_ed25519_model(&data, &verdict).expect_err("a finding");
        assert!(
            report.failures[0].detail.ends_with("the answer is true"),
            "{report}"
        );
        let report =
            check_ed25519_model(&data, &|_, _| Err("boom".to_owned())).expect_err("a finding");
        assert_eq!(report.failures[0].category, Category::OursPanicked);
    }

    /// A report names its target, class, index, variant, every request
    /// with both answers, its failures and its input, and says how to
    /// replay it; its first line follows the first failure.
    #[test]
    fn reports_print_everything_needed_to_replay() {
        let request = Request {
            cmd: Cmd::EcdsaVerify,
            data: vec![0x02, 0xab, 0xcd],
        };
        let mut report = Report {
            reference: Reference::Dcrd,
            target: "dcrec_diff_ecdsa",
            input: vec![0x0a, 0x05, 0xff],
            class: "EV-xGEN-true",
            index: 5,
            variant: "raw/compressed".to_owned(),
            fallback: false,
            requests: vec![request],
            intents: vec![Intent::Branch(EcdsaBranch::Step10Accept)],
            checked: vec![Intent::Branch(EcdsaBranch::Step8Accept)],
            theirs: vec![Some(reply(r#"{"result":"true"}"#))],
            ours: vec![Ok(OursAnswer {
                answer: Answer::Verdict(false),
                detail: Detail::Ecdsa(EcdsaBranch::Step10Reject),
            })],
            view: ModelView {
                per_request: vec![Some(ModelOutcome::Ecdsa {
                    branch: EcdsaBranch::Step8Accept,
                    doubled: false,
                })],
            },
            failures: vec![Failure {
                category: Category::Verdict,
                request: Some(0),
                detail: "ours false, theirs true".to_owned(),
            }],
        };
        let text = report.to_string();
        for part in [
            "dcrec_diff_ecdsa: EV-xGEN-true case 0x0000000000000005 (variant \
             \"raw/compressed\"): dcroxide and dcrd disagree\n",
            "\n  verdict on request 0: ours false, theirs true\n",
            "\n  request 0: ecdsa_verify 02abcd\n",
            "\n    intent: Branch(Step10Accept), checked: Branch(Step8Accept)\n",
            "\n    dcroxide: false (Ecdsa(Step10Reject))\n",
            "\n    dcrd: {\"result\":\"true\"}\n",
            "\n    model: Ecdsa { branch: Step8Accept, doubled: false }\n",
            "\n  input: 0a05ff\n",
            "\n  replay: sigsoak fuzz-replay --target dcrec_diff_ecdsa FILE",
        ] {
            assert!(text.contains(part), "{part:?} in:\n{text}");
        }
        assert!(!text.contains("agree on request"), "{text}");

        let headline = |report: &Report| report.to_string().lines().next().map(str::to_owned);
        report.reference = Reference::Model;
        assert!(
            headline(&report).is_some_and(|h| h.ends_with(
                "dcroxide and the model of dcrd's Ed25519 (src/model/ed25519.rs, frozen) disagree"
            )),
            "{report}"
        );
        assert!(report.to_string().contains("\n    model: {\"result\""));
        report.reference = Reference::Dcrd;
        for (category, checked, phrase) in [
            (
                Category::Intent,
                Intent::Branch(EcdsaBranch::Step8Accept),
                "the ECDSA model of dcrd's verification gives (src/model/ecdsa.rs, frozen)",
            ),
            (
                Category::Intent,
                Intent::Schnorr(Ok(())),
                "the Schnorr model of dcrd's verification gives (src/model/schnorr.rs, frozen)",
            ),
            (
                Category::Intent,
                Intent::Accept,
                "the class's construction implies (src/gen/ed25519.rs, frozen)",
            ),
            (Category::Protocol, Intent::Any, "the oracle failed"),
            (Category::OracleCrashed, Intent::Any, "the oracle failed"),
            (Category::OursPanicked, Intent::Any, "dcroxide panicked"),
            (Category::Kind, Intent::Any, "dcroxide and dcrd disagree"),
        ] {
            report.failures[0].category = category;
            report.checked = vec![checked];
            assert!(
                headline(&report).is_some_and(|h| h.ends_with(phrase)),
                "{category:?}: {report}"
            );
        }
        report.failures[0].category = Category::Intent;
        assert!(
            report
                .to_string()
                .contains("\n  dcroxide and dcrd agree on request 0: replay this input"),
            "{report}"
        );
        report.failures.clear();
        report.fallback = true;
        assert!(
            headline(&report)
                .is_some_and(|h| h
                    .ends_with("(variant \"raw/compressed\", fell back): dcroxide and dcrd agree")),
            "{report}"
        );
    }

    /// The panic context names the case being generated, or the request
    /// dcroxide is answering, with dcrd's answer to it.
    #[test]
    fn the_panic_context_names_the_case() {
        let mut context = Context {
            target: "dcrec_diff_ecdsa",
            reference: Reference::Dcrd,
            class: "EV-highS",
            index: 0x1f,
            variant: None,
            requests: Vec::new(),
            replies: Vec::new(),
            request: None,
        };
        assert_eq!(
            context_line(&context),
            "dcrec_diff_ecdsa: while generating EV-highS case 0x000000000000001f"
        );
        context.variant = Some("high/compressed".to_owned());
        context.requests = vec![Request {
            cmd: Cmd::EcdsaVerifyRaw,
            data: vec![0x21, 0x02],
        }];
        assert_eq!(
            context_line(&context),
            "dcrec_diff_ecdsa: while checking EV-highS case 0x000000000000001f (variant \
             \"high/compressed\")"
        );
        context.replies = vec![r#"{"result":"true"}"#.to_owned()];
        context.request = Some(0);
        assert_eq!(
            context_line(&context),
            "dcrec_diff_ecdsa: while answering EV-highS case 0x000000000000001f (variant \
             \"high/compressed\"), request 0 ecdsa_verify_raw 2102; dcrd answered \
             {\"result\":\"true\"}"
        );
    }

    /// An oracle whose `build_info` breaks the pin rule is refused, naming
    /// the module and both versions; one that keeps it is taken, and its
    /// exit is a failure of the next request, with its status.  The
    /// oracles are shell scripts, so no Go is needed.
    #[cfg(unix)]
    #[test]
    fn the_fuzz_oracle_holds_the_pin() {
        use crate::manifest::{ORACLE_GO_MOD, go_mod_version};
        let stand_in = |secp: &str| {
            let mut modules = serde_json::Map::new();
            for module in SIGNATURE_MODULES {
                let version = go_mod_version(ORACLE_GO_MOD, module).expect("required");
                modules.insert(module.to_owned(), json!(version));
            }
            if secp != "pinned" {
                modules.insert(SIGNATURE_MODULES[0].to_owned(), json!(secp));
            }
            let info = json!({ "go_version": "go1.26.2", "modules": modules });
            let mut cmd = std::process::Command::new("sh");
            cmd.arg("-c").arg(format!("read l; echo '{info}'"));
            Oracle::from_command(&mut cmd)
        };
        let want = go_mod_version(ORACLE_GO_MOD, SIGNATURE_MODULES[0]).expect("required");
        let refused = FuzzOracle::new(stand_in("v4.0.0"))
            .err()
            .expect("a bad pin is refused");
        for part in [SIGNATURE_MODULES[0], "built at v4.0.0", want] {
            assert!(refused.contains(part), "{part:?} in {refused}");
        }
        let mut oracle = FuzzOracle::new(stand_in("pinned")).expect("the pin holds");
        assert_eq!(
            oracle.describe(),
            format!(
                "oracle go1.26.2, secp256k1/v4 {want}, edwards/v2 {}",
                go_mod_version(ORACLE_GO_MOD, SIGNATURE_MODULES[1]).expect("required")
            )
        );
        let (category, why) = oracle
            .answer(&Request {
                cmd: Cmd::Blake256,
                data: Vec::new(),
            })
            .expect_err("the stand-in has exited");
        assert_eq!(category, Category::OracleCrashed);
        assert!(why.contains("exit status: 0"), "{why}");
    }
}
