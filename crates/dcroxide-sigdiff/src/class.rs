// SPDX-License-Identifier: ISC
//! The class registry: what a class is, the cases it generates and how a
//! case is named by its seed.
//!
//! A case is a pure function of `(master seed, class name, case index)`
//! ([`generate`]): the worker that runs it is no input, so results, counts
//! and digests do not depend on how many workers ran or which took the
//! case.  Class names are part of every case's seed, so a renamed class has
//! new cases; names are frozen with the generators.

use std::borrow::Cow;

use dcroxide_testutil::SplitMix64;

use crate::cmd::{Cmd, Request};
use crate::entropy::Entropy;
use crate::r#gen::{der, ecdsa, ed25519, pubkey, recover, schnorr};
use crate::model::EcdsaBranch;

/// The signature family a class tests.  A selection of every class of a
/// family is a whole family, which a gate-eligible run may select alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Family {
    /// ECDSA verification and signing (EV-*, ES-*).
    Ecdsa,
    /// DER signature parsing (DER-*).
    Der,
    /// secp256k1 public key parsing (K-*).
    Pubkey,
    /// Compact signature recovery (ER-*).
    Recover,
    /// EC-Schnorr-DCRv0 (SS-*, SP-*, SV-*).
    Schnorr,
    /// Ed25519 (DS-*, DK-*, DG-*, DV-*).
    Ed25519,
}

impl Family {
    /// The family's name, as manifests record a selection.
    pub fn name(self) -> &'static str {
        match self {
            Family::Ecdsa => "ecdsa",
            Family::Der => "der",
            Family::Pubkey => "pubkey",
            Family::Recover => "recover",
            Family::Schnorr => "schnorr",
            Family::Ed25519 => "ed25519",
        }
    }
}

/// The floor rule a class falls under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// 10^7 cases: parse classes, and verify classes whose inputs are drawn
    /// or edited rather than solved for.
    A,
    /// 10^6 cases: sign and recovery classes, and every class that solves
    /// for a key or signature to reach a named branch.
    B,
    /// Every element, every run.
    Finite,
}

impl Tier {
    /// The tier's floor, or `None` for a finite class (its size is its
    /// count).
    pub fn floor(self) -> Option<u64> {
        match self {
            Tier::A => Some(10_000_000),
            Tier::B => Some(1_000_000),
            Tier::Finite => None,
        }
    }
}

/// How a class's cases are drawn, and how many make its floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Size {
    /// Every case drawn from the entropy alone.
    Sampled {
        /// Cases at the floor.
        floor: u64,
    },
    /// Case `i` is in stratum `i % strata`, the entropy supplying the rest.
    Stratified {
        /// Number of strata.
        strata: u64,
        /// Cases at the floor.
        floor: u64,
    },
    /// Case `i` is element `i` of a fixed enumeration, run whole.
    Finite {
        /// Number of elements.
        size: u64,
    },
}

impl Size {
    /// The number of cases a floors run takes: the floor, or a finite
    /// class's size.
    pub fn floor(self) -> u64 {
        match self {
            Size::Sampled { floor } | Size::Stratified { floor, .. } => floor,
            Size::Finite { size } => size,
        }
    }

    /// The size of a finite class.
    pub fn finite(self) -> Option<u64> {
        match self {
            Size::Finite { size } => Some(size),
            _ => None,
        }
    }
}

/// A generator-side fact about a case that a [`Mix`] counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tag {
    /// The construction made the two summands of the verify sum equal.
    Doubled,
    /// The scalar-negation form of Ed25519 verification would give the
    /// other verdict.
    FormsDiffer,
    /// A bounded retry ran out and the case fell back to fixed values
    /// (variant `"fallback"`, intents [`Intent::Any`]); the run counts such
    /// cases apart and leaves them out of every mix.
    Fallback,
}

impl Tag {
    fn bit(self) -> u8 {
        match self {
            Tag::Doubled => 1,
            Tag::FormsDiffer => 2,
            Tag::Fallback => 4,
        }
    }

    /// The tag's name, as `mix.tsv` prints it.
    pub fn name(self) -> &'static str {
        match self {
            Tag::Doubled => "doubled",
            Tag::FormsDiffer => "forms-differ",
            Tag::Fallback => "fallback",
        }
    }
}

/// A set of [`Tag`]s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Tags(u8);

impl Tags {
    /// No tags.
    pub const NONE: Tags = Tags(0);

    /// This set with `tag` added.
    #[must_use]
    pub fn with(self, tag: Tag) -> Tags {
        Tags(self.0 | tag.bit())
    }

    /// Whether `tag` is in the set.
    pub fn has(self, tag: Tag) -> bool {
        self.0 & tag.bit() != 0
    }
}

/// A per-class outcome check over every case of a run.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Mix {
    /// The share of cases whose first request dcrd accepted (a `true`
    /// verdict or a value) lies in `[lo, hi]`; evaluated once the class
    /// completed at least `min_n` cases.
    AcceptRate {
        /// Lowest share that passes.
        lo: f64,
        /// Highest share that passes.
        hi: f64,
        /// Cases needed before the band is evaluated.
        min_n: u64,
    },
    /// Exactly this many cases' first request was accepted; evaluated only
    /// when a finite class ran whole.
    AcceptCount(u64),
    /// The share of cases carrying `tag` lies in `[lo, hi]`, once the class
    /// completed at least `min_n` cases.
    TagRate {
        /// The tag counted.
        tag: Tag,
        /// Lowest share that passes.
        lo: f64,
        /// Highest share that passes.
        hi: f64,
        /// Cases needed before the band is evaluated.
        min_n: u64,
    },
}

/// A check across the requests of one case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consistency {
    /// None.
    None,
    /// Every request gets the same verdict, on each side.
    SameVerdict,
}

/// The answer a request was built to get.  [`crate::compare::compare`]
/// holds both sides to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Intent {
    /// Nothing is required.
    Any,
    /// Both sides accept: a `true` verdict, or a value.
    Accept,
    /// dcrd's value is exactly these bytes (and dcroxide answers with a
    /// value, which the comparison already holds equal to dcrd's).
    AcceptValue(Vec<u8>),
    /// Both sides reject: a `false` verdict or an error for a verify
    /// command, an error for any other.
    Reject,
    /// dcrd rejects with this error kind, and dcroxide rejects.
    RejectKind(&'static str),
    /// dcrd rejects with an error that has no kind (Schnorr key parsing's
    /// own errors, and every Ed25519 error), and dcroxide rejects.
    RejectPlain,
    /// The ECDSA model ends in this step, and dcrd's verdict is the one it
    /// implies (as is dcroxide's step, when it reports one).
    Branch(EcdsaBranch),
    /// dcroxide's Schnorr reason and the Schnorr model's are this one, and
    /// dcrd's verdict is whether it is `Ok`.
    Schnorr(Result<(), &'static str>),
}

/// One case: the requests both sides answer, and what each is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Case {
    /// The case's stratum label, or `<stratum>/<presentation>` (a class's
    /// doc says which); `counts.tsv` keys on the whole label.
    pub variant: Cow<'static, str>,
    /// The oracle requests, one to 255 of them.
    pub requests: Vec<Request>,
    /// One intent per request.
    pub intents: Vec<Intent>,
    /// The check across the case's requests.
    pub consistency: Consistency,
    /// Generator-side facts a mix counts.
    pub tags: Tags,
}

/// A named class of inputs.
pub struct ClassSpec {
    /// The class's name, part of every one of its case seeds.
    pub name: &'static str,
    /// The family it belongs to.
    pub family: Family,
    /// Every command its cases send.
    pub commands: &'static [Cmd],
    /// How its cases are drawn and its floor.
    pub size: Size,
    /// The floor rule it falls under.
    pub tier: Tier,
    /// The generator: case `index` from its seeded entropy.
    pub generator: fn(&mut dyn Entropy, u64) -> Case,
    /// Outcome checks over a run.
    pub mix: &'static [Mix],
    /// Cases the per-PR test runs.
    pub pr_cases: u64,
    /// What the class is for, as `sigsoak list` prints it.
    pub doc: &'static str,
}

impl core::fmt::Debug for ClassSpec {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClassSpec")
            .field("name", &self.name)
            .field("family", &self.family)
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

/// Every class, in the order `sigsoak list` prints them: ECDSA
/// verification and signing, DER parsing, public key parsing, compact
/// recovery, EC-Schnorr-DCRv0 signing, parsing and verification, and
/// Ed25519 signing, key parsing, signature parsing and verification.
pub static CLASSES: &[ClassSpec] = &[
    ecdsa::EV_HONEST,
    ecdsa::EV_HIGH_S,
    ecdsa::EV_TAMPER,
    ecdsa::EV_RANDOM,
    ecdsa::EV_KEYENC,
    ecdsa::EV_KEYS,
    ecdsa::EV_HASH_GEN,
    ecdsa::EV_HASH0,
    ecdsa::EV_ZERO,
    ecdsa::EV_RANGE,
    ecdsa::EV_XGEN_TRUE,
    ecdsa::EV_XGEN_FALSE,
    ecdsa::EV_XGEN_WRAP,
    ecdsa::EV_INFINITY,
    ecdsa::EV_DOUBLE,
    ecdsa::EV_S_EDGE,
    ecdsa::EV_R_EDGE,
    ecdsa::EV_SMALL_X_KEY,
    ecdsa::ES_RANDOM,
    ecdsa::ES_HASH_GEN,
    ecdsa::ES_BOUNDARY,
    ecdsa::ES_COMPACT,
    der::DER_VALID,
    der::DER_MUTATE,
    der::DER_STRUCTURED,
    der::DER_KIND,
    pubkey::K_VALID,
    pubkey::K_HYBRID_MISMATCH,
    pubkey::K_X_TOO_BIG,
    pubkey::K_Y_TOO_BIG,
    pubkey::K_WRAP,
    pubkey::K_NEAR_P,
    pubkey::K_OFF_CURVE,
    pubkey::K_NEG_Y,
    pubkey::K_MUTATE,
    pubkey::K_SMALL_X,
    pubkey::K_FORMAT,
    pubkey::K_LENGTH,
    recover::ER_HONEST,
    recover::ER_FLIP_PARITY,
    recover::ER_HIGH_S,
    recover::ER_OVERFLOW_VALID,
    recover::ER_OVERFLOW_PRIME,
    recover::ER_NOT_ON_CURVE,
    recover::ER_INFINITY,
    recover::ER_DOUBLE,
    recover::ER_HEADER,
    recover::ER_LENGTH,
    recover::ER_RANGE,
    recover::ER_HASH,
    schnorr::SS_RANDOM,
    schnorr::SS_HASH_GEN,
    schnorr::SS_BOUNDARY,
    schnorr::SP_RANDOM,
    schnorr::SP_R_RANGE,
    schnorr::SV_HONEST,
    schnorr::SV_TAMPER,
    schnorr::SV_RANDOM,
    schnorr::SV_HASH_GEN,
    schnorr::SV_ZERO_S,
    schnorr::SV_INFINITY,
    schnorr::SV_ODD_R,
    schnorr::SV_R_GEN_TRUE,
    schnorr::SV_R_GEN_ODD,
    schnorr::SV_UNEQUAL_R,
    schnorr::SV_DOUBLE,
    ed25519::DS_RANDOM,
    ed25519::DK_CANONICAL,
    ed25519::DK_RANDOM,
    ed25519::DK_SMALL,
    ed25519::DK_LENGTH,
    ed25519::DG_EDGES,
    ed25519::DG_RANDOM,
    ed25519::DV_HONEST,
    ed25519::DV_TAMPER,
    ed25519::DV_S_PLUS_L,
    ed25519::DV_TOP_BITS,
    ed25519::DV_RANDOM,
    ed25519::DV_TORSION,
    ed25519::DV_TORSION_SWEEP,
    ed25519::DV_TORSION_NONCANON,
    ed25519::DV_ZERO_S_SMALL_R,
];

/// The class named `name`.
pub fn find_class(name: &str) -> Option<&'static ClassSpec> {
    CLASSES.iter().find(|class| class.name == name)
}

/// The classes a `--classes` list selects, in registry order: names or
/// patterns, comma-separated, where `*` matches any run of characters
/// (`EV-*,K-wrap`).  An empty list or `all` selects every class; an item
/// that matches no class is an error.
pub fn select_classes(list: &str) -> Result<Vec<&'static ClassSpec>, String> {
    let list = list.trim();
    if list.is_empty() || list == "all" {
        return Ok(CLASSES.iter().collect());
    }
    let mut chosen = vec![false; CLASSES.len()];
    for item in list.split(',').map(str::trim) {
        if item.is_empty() {
            return Err(format!("empty item in the class list {list:?}"));
        }
        let mut matched = false;
        for (class, chosen) in CLASSES.iter().zip(chosen.iter_mut()) {
            if glob_match(item, class.name) {
                *chosen = true;
                matched = true;
            }
        }
        if !matched {
            return Err(format!(
                "{item:?} names no class (sigsoak list prints them)"
            ));
        }
    }
    Ok(CLASSES
        .iter()
        .zip(chosen)
        .filter_map(|(class, chosen)| chosen.then_some(class))
        .collect())
}

/// Whether `name` matches `pattern`, in which `*` matches any run of
/// characters, including none, and everything else matches itself.
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or("");
    let Some(mut rest) = name.strip_prefix(first) else {
        return false;
    };
    let parts: Vec<&str> = parts.collect();
    let Some((last, middle)) = parts.split_last() else {
        // No `*`: the whole name must be the pattern.
        return rest.is_empty();
    };
    for part in middle {
        match rest.find(part) {
            Some(at) => rest = &rest[at.saturating_add(part.len())..],
            None => return false,
        }
    }
    rest.ends_with(last)
}

/// The seed of case `index` of class `class` under `master`: SplitMix64's
/// derive with the class name as label and the case index as index.
pub fn case_seed(master: u64, class: &str, index: u64) -> u64 {
    SplitMix64::derive(master, class, index)
}

/// Case `index` of `class` under `master`.  Panics when the generator
/// breaks the shape every case has (one to 255 requests, one intent each),
/// a bug in the generator.
pub fn generate(class: &ClassSpec, master: u64, index: u64) -> Case {
    let mut rng = SplitMix64(case_seed(master, class.name, index));
    let case = (class.generator)(&mut rng, index);
    assert!(
        !case.requests.is_empty() && case.requests.len() <= 255,
        "{} case {index}: {} requests",
        class.name,
        case.requests.len()
    );
    assert_eq!(
        case.requests.len(),
        case.intents.len(),
        "{} case {index}: one intent per request",
        class.name
    );
    case
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Class names are unique, each class's commands are the ones its cases
    /// send, and per-PR counts cover every stratum and stay within a finite
    /// class.
    #[test]
    fn the_registry_is_consistent() {
        let mut names = HashSet::new();
        for class in CLASSES {
            assert!(
                names.insert(class.name),
                "{} is registered twice",
                class.name
            );
            assert!(!class.commands.is_empty(), "{}", class.name);
            assert!(class.pr_cases > 0, "{}", class.name);
            match class.size {
                Size::Finite { size } => {
                    assert_eq!(class.tier, Tier::Finite, "{}", class.name);
                    assert!(class.pr_cases <= size, "{}", class.name);
                }
                Size::Stratified { strata, floor } => {
                    assert!(class.pr_cases >= strata, "{} misses strata", class.name);
                    assert_eq!(class.tier.floor(), Some(floor), "{}", class.name);
                }
                Size::Sampled { floor } => {
                    assert_eq!(class.tier.floor(), Some(floor), "{}", class.name);
                }
            }
            let mut sent = HashSet::new();
            for index in 0..class.pr_cases.min(64) {
                let case = generate(class, 0x5eed, index);
                for request in &case.requests {
                    assert!(
                        class.commands.contains(&request.cmd),
                        "{} sends {:?}, not among its commands",
                        class.name,
                        request.cmd
                    );
                    sent.insert(request.cmd);
                }
            }
            assert_eq!(
                sent.len(),
                class.commands.len(),
                "{}: unsent commands",
                class.name
            );
        }
    }

    /// A case is named by its master seed, class and index: generating it
    /// twice gives the same requests, other indices other ones, and its
    /// generator draws from the case seed a record prints for it.
    #[test]
    fn cases_are_pure_functions_of_their_names() {
        for class in CLASSES {
            let a = generate(class, 1, 5);
            assert_eq!(a, generate(class, 1, 5), "{}", class.name);
            assert_eq!(
                case_seed(1, class.name, 5),
                SplitMix64::derive(1, class.name, 5)
            );
            let mut rng = SplitMix64(case_seed(1, class.name, 5));
            assert_eq!(
                a,
                (class.generator)(&mut rng, 5),
                "{}: case 5 is drawn from its case seed",
                class.name
            );
        }
        let random = find_class("EV-random").expect("registered");
        assert_ne!(generate(random, 1, 3), generate(random, 2, 3));
        assert_ne!(generate(random, 1, 3), generate(random, 1, 6));
    }

    /// The classes, with the tier and family their names give, the floor of
    /// their tier, and a mix that matches their intents.
    #[test]
    fn the_classes_are_the_designs() {
        let names: Vec<&str> = CLASSES.iter().map(|c| c.name).collect();
        assert_eq!(
            names,
            [
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
            ]
        );
        assert_eq!(names.len(), 82, "the 82 classes");
        let tier_b = [
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
            "SS-random",
            "SS-hashGEN",
            "SS-boundary",
            "SV-infinity",
            "SV-oddR",
            "SV-rGEN-true",
            "SV-rGEN-odd",
            "SV-unequalR",
            "SV-double",
            "DS-random",
            "DV-torsionSweep",
            "DV-torsionNoncanon",
            "DV-zeroS-smallR",
        ];
        for class in CLASSES {
            let family = match class.name.split('-').next() {
                Some("EV" | "ES") => Family::Ecdsa,
                Some("DER") => Family::Der,
                Some("K") => Family::Pubkey,
                Some("ER") => Family::Recover,
                Some("SS" | "SP" | "SV") => Family::Schnorr,
                Some("DS" | "DK" | "DG" | "DV") => Family::Ed25519,
                other => panic!("{}: prefix {other:?}", class.name),
            };
            assert_eq!(class.family, family, "{}", class.name);
            let tier = if class.size.finite().is_some() {
                Tier::Finite
            } else if tier_b.contains(&class.name) || class.family == Family::Recover {
                Tier::B
            } else {
                Tier::A
            };
            assert_eq!(class.tier, tier, "{}", class.name);
            assert!(!class.doc.is_empty(), "{}", class.name);
            // Every case of a class whose mix is all or nothing carries an
            // intent that says the same of its first request.
            for index in 0..class.pr_cases.min(48) {
                let case = generate(class, 0x5eed, index);
                assert!(
                    !case.tags.has(Tag::Fallback),
                    "{} case {index} fell back",
                    class.name
                );
                let first = &case.intents[0];
                for mix in class.mix {
                    if let Mix::AcceptRate { lo, hi, .. } = *mix {
                        if lo == 1.0 && hi == 1.0 {
                            assert!(
                                matches!(
                                    first,
                                    Intent::Accept
                                        | Intent::AcceptValue(_)
                                        | Intent::Branch(
                                            EcdsaBranch::Step8Accept | EcdsaBranch::Step10Accept
                                        )
                                        | Intent::Schnorr(Ok(()))
                                ),
                                "{} case {index}: {first:?}",
                                class.name
                            );
                        } else if lo == 0.0 && hi == 0.0 {
                            assert!(
                                !matches!(
                                    first,
                                    Intent::Accept | Intent::AcceptValue(_) | Intent::Any
                                ) && !matches!(first, Intent::Branch(b) if b.accepts())
                                    && *first != Intent::Schnorr(Ok(())),
                                "{} case {index}: {first:?}",
                                class.name
                            );
                        }
                    }
                }
            }
        }
    }

    /// Every generator returns on an all-zero stream, an exhausted fuzz
    /// input, with a well-shaped case of its class's commands: every retry
    /// is bounded.
    #[test]
    fn generators_terminate_on_a_zero_stream() {
        for class in CLASSES {
            for index in 0..class.pr_cases.min(24) {
                let mut zeros = crate::entropy::ByteEntropy::new(&[]);
                let case = (class.generator)(&mut zeros, index);
                assert_eq!(case.requests.len(), case.intents.len(), "{}", class.name);
                assert!(!case.requests.is_empty(), "{}", class.name);
                for request in &case.requests {
                    assert!(class.commands.contains(&request.cmd), "{}", class.name);
                }
                if case.tags.has(Tag::Fallback) {
                    assert_eq!(case.variant, "fallback", "{}", class.name);
                    assert!(case.intents.iter().all(|i| *i == Intent::Any));
                }
            }
        }
    }

    #[test]
    fn class_lists_select_by_name_and_pattern() {
        let names = |list: &str| -> Result<Vec<&str>, String> {
            select_classes(list).map(|v| v.iter().map(|c| c.name).collect())
        };
        let all: Vec<&str> = CLASSES.iter().map(|c| c.name).collect();
        assert_eq!(names("").expect("empty"), all);
        assert_eq!(names("all").expect("all"), all);
        assert_eq!(names("*").expect("pattern"), all);
        assert_eq!(names("K-*").expect("pattern").len(), 12);
        assert_eq!(names("EV-*").expect("pattern").len(), 18);
        assert_eq!(
            names("K-length, K-wrap").expect("two names"),
            vec!["K-wrap", "K-length"],
            "registry order, not list order"
        );
        assert_eq!(names("K-*length,K-l*").expect("overlap").len(), 1);
        assert_eq!(
            names("*length").expect("pattern"),
            vec!["K-length", "ER-length", "DK-length"]
        );
        assert!(names("K-nothing").is_err());
        assert!(names("K-*,").is_err());

        for (pattern, name, want) in [
            ("EV-*", "EV-xGEN-true", true),
            ("EV-*", "ES-random", false),
            ("*-true", "EV-xGEN-true", true),
            ("EV-*GEN*", "EV-xGEN-true", true),
            ("EV-*GEN*", "EV-hashGEN", true),
            ("EV-x*-*-x", "EV-xGEN-true", false),
            ("*", "anything", true),
            ("K-wrap", "K-wrap", true),
            ("K-wrap", "K-wrapped", false),
            ("a*a", "a", false),
            ("a*a", "aa", true),
        ] {
            assert_eq!(glob_match(pattern, name), want, "{pattern} {name}");
        }
    }

    #[test]
    fn tags_are_a_set() {
        let tags = Tags::NONE.with(Tag::Doubled).with(Tag::Fallback);
        assert!(tags.has(Tag::Doubled) && tags.has(Tag::Fallback));
        assert!(!tags.has(Tag::FormsDiffer));
        assert!(!Tags::NONE.has(Tag::Doubled));
    }
}
