// SPDX-License-Identifier: ISC
//! The witness vectors `dcroxide-dcrec` keeps: for each class built to reach
//! a branch of dcrd's verification or recovery that only a solved-for input
//! reaches, the lowest-index case of each variant group and each dcrd
//! verdict, with dcrd's answer.  dcrec's own test answers each line
//! without Go and re-derives the branch, so the port's steps keep those
//! branches covered from the first.
//!
//! A case's variant group, its bucket, is the first `/`-separated component
//! of its variant ([`bucket`]): an EV class's presentation or construction,
//! a recovery header or compressed flag, a Schnorr stratum, an Ed25519 key
//! or encoding.  Each [`WitnessClass`] lists the (bucket, verdict) pairs
//! its lines cover.  [`emit`] runs each class from case 0 through the run
//! loop's case runner ([`crate::run::answer_cases`]), so that each case's
//! answers are held to dcrd's and to its intents as in a run, and stops the
//! class after the batch of cases in which every pair got its line.  A case
//! that disagrees, misses its intent or falls in no listed pair fails the
//! emission, and so does a class whose pairs are not all filled within
//! [`MAX_CASES`] cases.  Every class is still tried, each until the end of
//! the batch in which its first problem shows, so the failure names every
//! class that has one and each problem of the batches run; an oracle
//! failure ends the emission, with the problems found before it.
//!
//! Each line is `<class>|<variant>|<case index>|<command>|<request data
//! hex>|<answer>` ([`WitnessLine`]), the answer as [`answer_text`] writes
//! dcrd's.  Nothing in the file depends on a commit of this repository.

use std::collections::BTreeMap;
use std::fmt;

use dcroxide_testutil::{DCRD_PARITY_COMMIT, hex, unhex};

use crate::answer::{Answer, Kind};
use crate::class::{ClassSpec, find_class};
use crate::cmd::Cmd;
use crate::compare::Status;
use crate::pipe::PipeConfig;
use crate::run::answer_cases;

/// The master seed the committed file is emitted at: the ASCII bytes of
/// `witness1`.
pub const WITNESS_SEED: u64 = 0x7769_746e_6573_7331;

/// The most cases a class may take to fill its lines.
pub const MAX_CASES: u64 = 4_096;

/// Cases answered at a time, each batch by a fresh oracle.
const BATCH: u64 = 64;

/// The file's name, in `emit-corpus`'s output directory and in
/// `crates/dcroxide-dcrec/tests/data/`.
pub const FILE_NAME: &str = "sigdiff_witness_vectors.txt";

/// A class the file covers, and the (bucket, dcrd accepts) pairs its lines
/// cover, one line each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WitnessClass {
    /// The class's name.
    pub name: &'static str,
    /// Each line's bucket and whether dcrd accepts its case: a `true`
    /// verdict or a recovered key.
    pub lines: &'static [(&'static str, bool)],
}

/// The four ECDSA verify presentations, each with one verdict.
const fn presentations(accepts: bool) -> [(&'static str, bool); 4] {
    [
        ("raw-compressed", accepts),
        ("raw-uncompressed", accepts),
        ("raw-hybrid", accepts),
        ("der-compressed", accepts),
    ]
}

/// The witness classes, in registry order: the constructed ECDSA verify
/// classes, the constructed recovery classes, the Schnorr classes that
/// reach r at or above N, an unequal R and a doubling sum, and the Ed25519
/// classes of non-canonical small-order keys and of a zero S.
pub static WITNESS_CLASSES: &[WitnessClass] = &[
    WitnessClass {
        name: "EV-xGEN-true",
        lines: &presentations(true),
    },
    WitnessClass {
        name: "EV-xGEN-false",
        lines: &[("s+1", false), ("hash", false), ("unrelated", false)],
    },
    WitnessClass {
        name: "EV-xGEN-wrap",
        lines: &presentations(false),
    },
    WitnessClass {
        name: "EV-infinity",
        lines: &presentations(false),
    },
    WitnessClass {
        name: "EV-double",
        lines: &presentations(true),
    },
    WitnessClass {
        name: "ER-overflowValid",
        lines: &[("29", true), ("30", true), ("33", true), ("34", true)],
    },
    WitnessClass {
        name: "ER-infinity",
        lines: &[("uncompressed", false), ("compressed", false)],
    },
    WitnessClass {
        name: "ER-double",
        lines: &[("uncompressed", true), ("compressed", true)],
    },
    WitnessClass {
        name: "SV-rGEN-true",
        lines: &[("r>=N", true)],
    },
    WitnessClass {
        name: "SV-unequalR",
        lines: &[("random", false), ("xminusN", false), ("xplusN", false)],
    },
    WitnessClass {
        name: "SV-double",
        lines: &[("doubled", true)],
    },
    WitnessClass {
        name: "DV-torsionNoncanon",
        lines: &[
            ("identity-p1", true),
            ("order4-p-s0", true),
            ("order4-p-s0", false),
            ("order4-p-s1", true),
            ("order4-p-s1", false),
        ],
    },
    WitnessClass {
        name: "DV-zeroS-smallR",
        lines: &[("canonical", true), ("noncanonical", false)],
    },
];

/// A variant's bucket: its first `/`-separated component.
pub fn bucket(variant: &str) -> &str {
    variant.split('/').next().unwrap_or(variant)
}

/// dcrd's answer as a line records it: `true` or `false` for a verdict,
/// `ok:<hex>:<true|false>` for a recovered key and its compressed flag,
/// `err:<kind>` for a rejection with one of dcrd's kinds.  An error for
/// any other answer, which no witness class gets.
pub fn answer_text(answer: &Answer) -> Result<String, String> {
    match answer {
        Answer::Verdict(v) => Ok(v.to_string()),
        Answer::Value {
            bytes,
            flag: Some(flag),
        } => Ok(format!("ok:{}:{flag}", hex(bytes))),
        Answer::Reject {
            kind: Kind::Dcrd(kind),
            ..
        } => Ok(format!("err:{kind}")),
        other => Err(format!(
            "{}, which the witness format has no field for",
            other.describe()
        )),
    }
}

/// One line of the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessLine {
    /// The class.
    pub class: &'static str,
    /// The case's variant.
    pub variant: String,
    /// The case index.
    pub index: u64,
    /// The case's one request's command.
    pub cmd: Cmd,
    /// Its data, as the oracle received it.
    pub data: Vec<u8>,
    /// dcrd's answer, as [`answer_text`] writes it.
    pub answer: String,
}

impl fmt::Display for WitnessLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}|{}|{}|{}|{}|{}",
            self.class,
            self.variant,
            self.index,
            self.cmd.name(),
            hex(&self.data),
            self.answer
        )
    }
}

impl WitnessLine {
    /// A vector line read back: six `|`-separated fields, a registered
    /// class and a command the oracle has.
    pub fn parse(line: &str) -> Result<WitnessLine, String> {
        let fields: Vec<&str> = line.split('|').collect();
        let [class, variant, index, cmd, data, answer] = fields[..] else {
            return Err(format!("{line:?}: not six |-separated fields"));
        };
        let class = find_class(class).ok_or_else(|| format!("{line:?}: no class {class}"))?;
        let index = index
            .parse()
            .map_err(|_| format!("{line:?}: case index {index:?}"))?;
        let cmd = Cmd::ALL
            .into_iter()
            .find(|c| c.name() == cmd)
            .ok_or_else(|| format!("{line:?}: no command {cmd}"))?;
        let hex_digits =
            data.len().is_multiple_of(2) && data.bytes().all(|b| b.is_ascii_hexdigit());
        if !hex_digits {
            return Err(format!("{line:?}: the request data is not hex"));
        }
        Ok(WitnessLine {
            class: class.name,
            variant: variant.to_owned(),
            index,
            cmd,
            data: unhex(data),
            answer: answer.to_owned(),
        })
    }
}

/// The vector lines of a file's text: every line that is neither empty
/// nor a `#` comment.
pub fn vector_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
}

/// Why an emission produced no file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmitFailure {
    /// The oracle failed or would not start: nothing is known of the
    /// cases it did not answer.
    Oracle {
        /// What failed, and on which class.
        why: String,
        /// The case problems found before it failed, one each.
        problems: Vec<String>,
    },
    /// Cases disagreed, missed their intents or fell in no listed pair, or
    /// a class did not fill its lines within [`MAX_CASES`]: every problem,
    /// one each.
    Cases(Vec<String>),
}

impl EmitFailure {
    /// The exit code `sigsoak emit-corpus` ends with: 3 when the oracle
    /// failed, as an aborted run does; 1 when cases did, as a failed
    /// comparison does.
    pub fn exit_code(&self) -> u8 {
        match self {
            EmitFailure::Oracle { .. } => 3,
            EmitFailure::Cases(_) => 1,
        }
    }
}

impl fmt::Display for EmitFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EmitFailure::Oracle { why, problems } => {
                write!(f, "the oracle failed: {why}")?;
                if !problems.is_empty() {
                    write!(f, "\nand before it failed:\n{}", problems.join("\n"))?;
                }
                Ok(())
            }
            EmitFailure::Cases(problems) => f.write_str(&problems.join("\n")),
        }
    }
}

/// The witness lines under `master`, class by class in
/// [`WITNESS_CLASSES`] order and by case index within a class, each case
/// answered by dcroxide and by an oracle run as `pipe` says, a fresh one
/// for each batch.
pub fn emit(master: u64, pipe: &PipeConfig) -> Result<Vec<WitnessLine>, EmitFailure> {
    let mut lines = Vec::new();
    let mut problems = Vec::new();
    for witness in WITNESS_CLASSES {
        let Some(spec) = find_class(witness.name) else {
            problems.push(format!("no class {}", witness.name));
            continue;
        };
        match emit_class(witness, spec, master, pipe, &mut problems) {
            Ok(found) => lines.extend(found),
            Err(why) => return Err(EmitFailure::Oracle { why, problems }),
        }
    }
    if problems.is_empty() {
        Ok(lines)
    } else {
        Err(EmitFailure::Cases(problems))
    }
}

/// `accepted` or `rejected`, as dcrd answered.
fn verdict(accepts: bool) -> &'static str {
    if accepts { "accepted" } else { "rejected" }
}

/// One class's lines: batches of [`BATCH`] cases from case 0 until every
/// listed pair has its lowest-index case, each problem noted in
/// `problems`.  Every case of a batch is held to dcrd's answer and its
/// intent, those after the last line's included.  An error when the
/// oracle failed.
fn emit_class(
    witness: &WitnessClass,
    spec: &'static ClassSpec,
    master: u64,
    pipe: &PipeConfig,
    problems: &mut Vec<String>,
) -> Result<Vec<WitnessLine>, String> {
    let name = witness.name;
    let mut found: BTreeMap<usize, WitnessLine> = BTreeMap::new();
    let mut next = 0;
    let before = problems.len();
    while found.len() < witness.lines.len() && problems.len() == before {
        if next >= MAX_CASES {
            let missing: Vec<String> = witness
                .lines
                .iter()
                .enumerate()
                .filter(|(k, _)| !found.contains_key(k))
                .map(|(_, &(bucket, accepts))| format!("{bucket} {}", verdict(accepts)))
                .collect();
            problems.push(format!(
                "{name}: no case within {MAX_CASES} for {}",
                missing.join(", ")
            ));
            break;
        }
        let end = next.saturating_add(BATCH).min(MAX_CASES);
        let answered = answer_cases(spec, master, next..end, pipe)?;
        for a in answered {
            let at = format!("{name} case {} ({})", a.index, a.case.variant);
            if a.result.status != Status::Agree {
                let failures: Vec<String> = a
                    .result
                    .failures
                    .iter()
                    .map(|f| format!("{}: {}", f.category.name(), f.detail))
                    .collect();
                problems.push(format!("{at}: {}", failures.join("; ")));
                continue;
            }
            let ([request], [Some(theirs)]) = (&a.case.requests[..], &a.result.theirs[..]) else {
                problems.push(format!("{at}: not one request with dcrd's answer"));
                continue;
            };
            let accepts = theirs.accepted();
            let pair = (bucket(&a.case.variant), accepts);
            let Some(k) = witness.lines.iter().position(|&listed| listed == pair) else {
                problems.push(format!(
                    "{at}: bucket {} {} is no line of the class",
                    pair.0,
                    verdict(accepts)
                ));
                continue;
            };
            if found.contains_key(&k) {
                continue;
            }
            match answer_text(theirs) {
                Ok(answer) if !a.case.variant.contains('|') => {
                    found.insert(
                        k,
                        WitnessLine {
                            class: name,
                            variant: a.case.variant.into_owned(),
                            index: a.index,
                            cmd: request.cmd,
                            data: request.data.clone(),
                            answer,
                        },
                    );
                }
                Ok(_) => problems.push(format!("{at}: a variant with a |")),
                Err(why) => problems.push(format!("{at}: dcrd answered {why}")),
            }
        }
        next = end;
    }
    let mut lines: Vec<WitnessLine> = found.into_values().collect();
    lines.sort_by_key(|line| line.index);
    Ok(lines)
}

/// The file's header for lines emitted under `master`.
pub fn header(master: u64) -> String {
    format!(
        "# Witness vectors for the constructed signature input classes of\n\
         # dcroxide-sigdiff: per class, the first case of each variant group and\n\
         # each dcrd verdict, generated by\n\
         # `sigsoak emit-corpus --seed {master:#018x}`, each expected answer\n\
         # given by dcrd's dcrec/secp256k1/v4 and dcrec/edwards/v2 at the parity\n\
         # pin {DCRD_PARITY_COMMIT} through tools/oracle.  dcroxide-sigdiff's\n\
         # witness_file_regenerates test rebuilds the vector lines from the\n\
         # generators and the oracle and fails on any difference.\n\
         #\n\
         # <class>|<variant>|<case index>|<command>|<request data hex>|<answer>\n\
         # <answer> is true, false, ok:<hex>:<true|false> (a recovered key and the\n\
         # compressed flag), or err:<dcrd error kind>.\n"
    )
}

/// The whole file: [`header`], then one line each.
pub fn file(master: u64, lines: &[WitnessLine]) -> String {
    let mut out = header(master);
    for line in lines {
        out.push_str(&line.to_string());
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::class::{CLASSES, generate};
    use dcroxide_testutil::TempDir;
    use std::collections::BTreeSet;

    /// The witness classes are registered, in registry order, each of one
    /// request per case, and their listed pairs are distinct: 39 lines.
    #[test]
    fn the_witness_classes_are_registered() {
        let order: Vec<&str> = CLASSES
            .iter()
            .map(|c| c.name)
            .filter(|n| WITNESS_CLASSES.iter().any(|w| w.name == *n))
            .collect();
        let names: Vec<&str> = WITNESS_CLASSES.iter().map(|w| w.name).collect();
        assert_eq!(order, names, "every witness class registered, in order");
        for witness in WITNESS_CLASSES {
            let distinct: BTreeSet<_> = witness.lines.iter().collect();
            assert_eq!(distinct.len(), witness.lines.len(), "{}", witness.name);
            let spec = find_class(witness.name).expect("registered");
            for index in 0..BATCH {
                let case = generate(spec, WITNESS_SEED, index);
                assert_eq!(case.requests.len(), 1, "{} case {index}", witness.name);
                let b = bucket(&case.variant);
                assert!(
                    witness.lines.iter().any(|(listed, _)| *listed == b),
                    "{} case {index}: bucket {b} is listed",
                    witness.name
                );
            }
        }
        let total: usize = WITNESS_CLASSES.iter().map(|w| w.lines.len()).sum();
        assert_eq!(total, 39);
    }

    #[test]
    fn buckets_are_first_components() {
        assert_eq!(bucket("s+1/raw-hybrid"), "s+1");
        assert_eq!(bucket("noncanonical/T0/T0/y+p"), "noncanonical");
        assert_eq!(bucket("r>=N"), "r>=N");
        assert_eq!(bucket(""), "");
    }

    /// Each answer shape the format has, and none other.
    #[test]
    fn answers_are_written_as_the_header_says() {
        assert_eq!(answer_text(&Answer::Verdict(true)).as_deref(), Ok("true"));
        assert_eq!(answer_text(&Answer::Verdict(false)).as_deref(), Ok("false"));
        let key = Answer::Value {
            bytes: vec![0x02, 0xab],
            flag: Some(true),
        };
        assert_eq!(answer_text(&key).as_deref(), Ok("ok:02ab:true"));
        let reject = Answer::Reject {
            kind: Kind::Dcrd("ErrPointNotOnCurve".into()),
            text: Some("text".into()),
        };
        assert_eq!(
            answer_text(&reject).as_deref(),
            Ok("err:ErrPointNotOnCurve")
        );
        for other in [
            Answer::Value {
                bytes: vec![1],
                flag: None,
            },
            Answer::Reject {
                kind: Kind::Plain,
                text: Some("text".into()),
            },
        ] {
            assert!(answer_text(&other).is_err(), "{other:?}");
        }
    }

    /// An oracle failure keeps the case problems found before it and ends
    /// `emit-corpus` as an aborted run does; case problems alone end it as
    /// a failed comparison does.
    #[test]
    fn failures_keep_their_problems() {
        let problem = "EV-xGEN-true case 0 (raw-compressed): verdict: ours true, theirs false";
        let oracle = EmitFailure::Oracle {
            why: "SV-rGEN-true: the oracle exited".to_owned(),
            problems: vec![problem.to_owned()],
        };
        assert_eq!(oracle.exit_code(), 3);
        assert_eq!(
            oracle.to_string(),
            format!(
                "the oracle failed: SV-rGEN-true: the oracle exited\nand before it failed:\n{problem}"
            )
        );
        let alone = EmitFailure::Oracle {
            why: "it exited".to_owned(),
            problems: Vec::new(),
        };
        assert_eq!(alone.to_string(), "the oracle failed: it exited");
        let cases = EmitFailure::Cases(vec![problem.to_owned(), "SV-double: no case".to_owned()]);
        assert_eq!(cases.exit_code(), 1);
        assert_eq!(cases.to_string(), format!("{problem}\nSV-double: no case"));
    }

    /// An oracle that does not start ends the emission on the class whose
    /// batch it was to answer, and the failure names that class.
    #[test]
    fn an_oracle_that_does_not_start_names_its_class() {
        let dir = TempDir::new("sigdiff-no-oracle");
        let failure = emit(WITNESS_SEED, &PipeConfig::new(dir.path().join("oracle")))
            .expect_err("no oracle to start");
        assert_eq!(failure.exit_code(), 3, "{failure}");
        let EmitFailure::Oracle { why, problems } = &failure else {
            panic!("{failure}");
        };
        assert!(
            why.starts_with("EV-xGEN-true: the oracle did not start: "),
            "{why}"
        );
        assert!(problems.is_empty(), "{problems:?}");
    }

    /// A line reads back as it was written, and a malformed one is refused.
    #[test]
    fn lines_read_back() {
        let line = WitnessLine {
            class: "EV-xGEN-true",
            variant: "raw-compressed".to_owned(),
            index: 7,
            cmd: Cmd::EcdsaVerifyRaw,
            data: vec![0x21, 0x02, 0xff],
            answer: "true".to_owned(),
        };
        let text = line.to_string();
        assert_eq!(
            text,
            "EV-xGEN-true|raw-compressed|7|ecdsa_verify_raw|2102ff|true"
        );
        assert_eq!(WitnessLine::parse(&text), Ok(line));
        for bad in [
            "EV-xGEN-true|raw-compressed|7|ecdsa_verify_raw|2102ff",
            "EV-nothing|raw-compressed|7|ecdsa_verify_raw|2102ff|true",
            "EV-xGEN-true|raw-compressed|x|ecdsa_verify_raw|2102ff|true",
            "EV-xGEN-true|raw-compressed|7|ecdsa_verify_nothing|2102ff|true",
            "EV-xGEN-true|raw-compressed|7|ecdsa_verify_raw|2102f|true",
            "EV-xGEN-true|raw-compressed|7|ecdsa_verify_raw|zz|true",
        ] {
            assert!(WitnessLine::parse(bad).is_err(), "{bad}");
        }
        let file = file(WITNESS_SEED, &[WitnessLine::parse(&text).expect("parses")]);
        assert_eq!(vector_lines(&file).collect::<Vec<_>>(), [text.as_str()]);
        assert!(file.starts_with("# Witness vectors"));
        assert!(file.contains("--seed 0x7769746e65737331`"));
        assert!(file.contains(&format!("pin {DCRD_PARITY_COMMIT} through")));
    }
}
