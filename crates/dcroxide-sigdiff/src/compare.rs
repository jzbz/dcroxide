// SPDX-License-Identifier: ISC
//! Holding dcroxide's answers to a case against dcrd's.
//!
//! Per request, in order: dcroxide panicked; the verdict (a verdict, a
//! value or a rejection, and the boolean); a value's bytes and flag; a
//! rejection's kind ([`match_kinds`]) and, where dcroxide reproduces dcrd's
//! text, the text ([`compares_text`]); then the intent the request was
//! built for.  Then the check across the case's requests.  An oracle that
//! failed on the case is recorded apart ([`CaseResult::oracle_failure`]).

use crate::answer::{
    Answer, Detail, Kind, KindMatch, OursAnswer, compares_text, match_kinds, theirs_answer,
};
use crate::class::{Case, Consistency, Intent, Tag};
use crate::cmd::Cmd;
use crate::model::{ModelOutcome, ModelView};
use crate::reply::Reply;

/// A case's status, as its digest leaf records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Status {
    /// Every check passed.
    Agree,
    /// A check failed.
    Disagree,
    /// The oracle failed on the case: it is the culprit of a crash, a hang
    /// or a broken protocol, and dcrd's answer is missing.
    OracleFailure,
    /// dcroxide panicked on one of the case's requests.
    OursPanicked,
}

impl Status {
    /// The status byte of a digest leaf: 0 agree, 1 disagree, 2 oracle
    /// failure, 3 dcroxide panicked.
    pub fn code(self) -> u8 {
        match self {
            Status::Agree => 0,
            Status::Disagree => 1,
            Status::OracleFailure => 2,
            Status::OursPanicked => 3,
        }
    }

    /// The status for each code, in code order.
    pub const ALL: [Status; 4] = [
        Status::Agree,
        Status::Disagree,
        Status::OracleFailure,
        Status::OursPanicked,
    ];
}

/// What a failed check found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Category {
    /// dcroxide panicked.
    OursPanicked,
    /// The two answers are of different shapes, or different verdicts.
    Verdict,
    /// Both gave a value, with different bytes.
    Value,
    /// Both recovered the same key, with different compressed flags.
    Flag,
    /// Both rejected, with different kinds.
    Kind,
    /// Both rejected with one kind, with different texts.
    Text,
    /// An answer is not the one the request was built for.
    Intent,
    /// The case's requests got answers its consistency rule forbids.
    Consistency,
    /// The oracle exited on the case.
    OracleCrashed,
    /// The oracle stopped answering on the case.
    OracleHung,
    /// The oracle's reply broke the protocol or does not fit the command.
    Protocol,
    /// dcroxide did not return within the hang timeout.
    OursHung,
}

impl Category {
    /// The category's name, as records print it.
    pub fn name(self) -> &'static str {
        match self {
            Category::OursPanicked => "ours-panicked",
            Category::Verdict => "verdict",
            Category::Value => "value",
            Category::Flag => "flag",
            Category::Kind => "kind",
            Category::Text => "text",
            Category::Intent => "intent",
            Category::Consistency => "consistency",
            Category::OracleCrashed => "oracle-crashed",
            Category::OracleHung => "oracle-hung",
            Category::Protocol => "protocol",
            Category::OursHung => "ours-hung",
        }
    }
}

/// One failed check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// What failed.
    pub category: Category,
    /// The request it failed on; `None` for a check across requests.
    pub request: Option<usize>,
    /// What each side said.
    pub detail: String,
}

/// The comparison of one case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseResult {
    /// The case's status.
    pub status: Status,
    /// Every failed check, in the order they were made.
    pub failures: Vec<Failure>,
    /// dcrd's answer to each request; `None` where there is none to digest
    /// (the oracle failed, or its reply did not fit the command).
    pub theirs: Vec<Option<Answer>>,
    /// Per request, whether dcrd's error kind was held against a kind of
    /// dcroxide's (`kinds.tsv` counts how often).
    pub kind_compared: Vec<bool>,
}

impl CaseResult {
    /// The result of a case the oracle failed on: no answer from dcrd for
    /// any of its `requests` requests, and status
    /// [`Status::OracleFailure`] (or [`Status::OursPanicked`] when dcroxide
    /// had panicked on it too, which the panic outranks).
    pub fn oracle_failure(
        requests: usize,
        ours: &[Result<OursAnswer, String>],
        category: Category,
        detail: String,
    ) -> CaseResult {
        let mut failures: Vec<Failure> = ours
            .iter()
            .enumerate()
            .filter_map(|(j, o)| o.as_ref().err().map(|msg| (j, msg)))
            .map(|(j, msg)| Failure {
                category: Category::OursPanicked,
                request: Some(j),
                detail: msg.clone(),
            })
            .collect();
        let status = if failures.is_empty() {
            Status::OracleFailure
        } else {
            Status::OursPanicked
        };
        failures.insert(
            0,
            Failure {
                category,
                request: None,
                detail,
            },
        );
        CaseResult {
            status,
            failures,
            theirs: vec![None; requests],
            kind_compared: vec![false; requests],
        }
    }
}

/// Holds dcroxide's answers to `case` (`ours[j]` is `Err(message)` where it
/// panicked on request `j`) against the oracle's replies, and both against
/// the case's intents, with the models' view of it.
pub fn compare(
    case: &Case,
    ours: &[Result<OursAnswer, String>],
    theirs: &[Reply],
    model: &ModelView,
) -> CaseResult {
    let n = case.requests.len();
    assert!(
        ours.len() == n && theirs.len() == n && case.intents.len() == n,
        "one answer, reply and intent per request"
    );
    let mut failures = Vec::new();
    let mut theirs_answers = Vec::with_capacity(n);
    let mut kind_compared = vec![false; n];
    for (j, request) in case.requests.iter().enumerate() {
        let cmd = request.cmd;
        let mut fail = |category: Category, detail: String| {
            failures.push(Failure {
                category,
                request: Some(j),
                detail,
            });
        };
        let theirs_j = match theirs_answer(cmd, &theirs[j]) {
            Ok(answer) => Some(answer),
            Err(why) => {
                fail(Category::Protocol, why);
                None
            }
        };
        let ours_j = match &ours[j] {
            Ok(answer) => Some(answer),
            Err(message) => {
                fail(Category::OursPanicked, message.clone());
                None
            }
        };
        if let (Some(o), Some(t)) = (ours_j, &theirs_j) {
            kind_compared[j] = compare_answers(cmd, &o.answer, t, &mut fail);
        }
        if let Some(why) = check_intent(
            &case.intents[j],
            case.tags.has(Tag::Doubled),
            ours_j,
            theirs_j.as_ref(),
            model.per_request.get(j).copied().flatten(),
        ) {
            fail(Category::Intent, why);
        }
        theirs_answers.push(theirs_j);
    }
    if case.consistency == Consistency::SameVerdict {
        let theirs_same = all_equal(theirs_answers.iter().flatten().map(Answer::accepted));
        let ours_same = all_equal(
            ours.iter()
                .filter_map(|o| o.as_ref().ok())
                .map(|o| o.answer.accepted()),
        );
        if !theirs_same || !ours_same {
            failures.push(Failure {
                category: Category::Consistency,
                request: None,
                detail: format!(
                    "the requests' verdicts differ (dcrd consistent: {theirs_same}, dcroxide \
                     consistent: {ours_same})"
                ),
            });
        }
    }
    let status = if ours.iter().any(Result::is_err) {
        Status::OursPanicked
    } else if failures.is_empty() {
        Status::Agree
    } else {
        Status::Disagree
    };
    CaseResult {
        status,
        failures,
        theirs: theirs_answers,
        kind_compared,
    }
}

/// Whether every item equals the first (true for none).
fn all_equal(mut items: impl Iterator<Item = bool>) -> bool {
    match items.next() {
        Some(first) => items.all(|v| v == first),
        None => true,
    }
}

/// Steps 2-4: the verdict, then a value's bytes and flag or a rejection's
/// kind and text.  Returns whether dcrd's kind was held against one of
/// dcroxide's.
fn compare_answers(
    cmd: Cmd,
    ours: &Answer,
    theirs: &Answer,
    fail: &mut dyn FnMut(Category, String),
) -> bool {
    match (ours, theirs) {
        (Answer::Verdict(a), Answer::Verdict(b)) => {
            if a != b {
                fail(Category::Verdict, format!("ours {a}, theirs {b}"));
            }
            false
        }
        (Answer::Value { bytes: a, flag: fa }, Answer::Value { bytes: b, flag: fb }) => {
            if a != b {
                fail(
                    Category::Value,
                    format!("ours {}, theirs {}", ours.describe(), theirs.describe()),
                );
            } else if fa != fb {
                fail(Category::Flag, format!("ours {fa:?}, theirs {fb:?}"));
            }
            false
        }
        (Answer::Reject { kind: ka, text: ta }, Answer::Reject { kind: kb, text: tb }) => {
            match match_kinds(ka, kb) {
                KindMatch::NotCompared => false,
                KindMatch::Differ => {
                    fail(
                        Category::Kind,
                        format!("ours {}, theirs {}", ours.label(), theirs.label()),
                    );
                    true
                }
                KindMatch::Equal => {
                    if compares_text(cmd, kb) && ta != tb {
                        fail(Category::Text, format!("ours {ta:?}, theirs {tb:?}"));
                    }
                    true
                }
            }
        }
        _ => {
            fail(
                Category::Verdict,
                format!("ours {}, theirs {}", ours.describe(), theirs.describe()),
            );
            false
        }
    }
}

/// Step 5: the request's intent, or why it does not hold.  `doubled` is
/// whether the generator tagged the case as one whose verify sum doubles,
/// which the model must confirm.
fn check_intent(
    intent: &Intent,
    doubled: bool,
    ours: Option<&OursAnswer>,
    theirs: Option<&Answer>,
    model: Option<ModelOutcome>,
) -> Option<String> {
    let ours_accepts = ours.map(|o| o.answer.accepted());
    let theirs_accepts = theirs.map(Answer::accepted);
    match intent {
        Intent::Any => None,
        Intent::Accept => (theirs_accepts == Some(false) || ours_accepts == Some(false))
            .then(|| format!("built to be accepted; {}", sides(ours, theirs))),
        Intent::Reject => (theirs_accepts == Some(true) || ours_accepts == Some(true))
            .then(|| format!("built to be rejected; {}", sides(ours, theirs))),
        Intent::AcceptValue(want) => {
            let theirs_ok = match theirs {
                Some(Answer::Value { bytes, .. }) => bytes == want,
                Some(_) => false,
                None => true,
            };
            let ours_ok = ours.is_none_or(|o| matches!(o.answer, Answer::Value { .. }));
            (!theirs_ok || !ours_ok).then(|| {
                format!(
                    "built for the value {}; {}",
                    dcroxide_testutil::hex(want),
                    sides(ours, theirs)
                )
            })
        }
        Intent::RejectKind(kind) => {
            let theirs_ok = match theirs {
                Some(Answer::Reject {
                    kind: Kind::Dcrd(name),
                    ..
                }) => name == kind,
                Some(_) => false,
                None => true,
            };
            let ours_ok = ours.is_none_or(|o| matches!(o.answer, Answer::Reject { .. }));
            (!theirs_ok || !ours_ok).then(|| format!("built for {kind}; {}", sides(ours, theirs)))
        }
        Intent::RejectPlain => {
            let theirs_ok = matches!(
                theirs,
                Some(Answer::Reject {
                    kind: Kind::Plain,
                    ..
                }) | None
            );
            let ours_ok = ours.is_none_or(|o| matches!(o.answer, Answer::Reject { .. }));
            (!theirs_ok || !ours_ok).then(|| {
                format!(
                    "built for a rejection without a kind; {}",
                    sides(ours, theirs)
                )
            })
        }
        Intent::Branch(branch) => {
            let model_ok = matches!(
                model,
                Some(ModelOutcome::Ecdsa { branch: b, doubled: d }) if b == *branch && (d || !doubled)
            );
            let theirs_ok = match theirs {
                Some(Answer::Verdict(v)) => *v == branch.accepts(),
                Some(_) => false,
                None => true,
            };
            let ours_ok = match ours.map(|o| o.detail) {
                Some(Detail::Ecdsa(b)) => b == *branch,
                _ => true,
            };
            (!model_ok || !theirs_ok || !ours_ok).then(|| {
                format!(
                    "built for {}{}; model {model:?}; {}",
                    branch.name(),
                    if doubled { " with a doubling" } else { "" },
                    sides(ours, theirs)
                )
            })
        }
        Intent::Schnorr(reason) => {
            let model_ok = matches!(
                model,
                Some(ModelOutcome::Schnorr { reason: r, doubled: d }) if r == *reason && (d || !doubled)
            );
            let theirs_ok = match theirs {
                Some(Answer::Verdict(v)) => *v == reason.is_ok(),
                Some(_) => false,
                None => true,
            };
            let ours_ok = match ours.map(|o| o.detail) {
                Some(Detail::Schnorr(r)) => r == *reason,
                Some(_) => false,
                None => true,
            };
            (!model_ok || !theirs_ok || !ours_ok).then(|| {
                format!(
                    "built for {reason:?}; model {model:?}; {}",
                    sides(ours, theirs)
                )
            })
        }
    }
}

fn sides(ours: Option<&OursAnswer>, theirs: Option<&Answer>) -> String {
    let ours = match ours {
        Some(o) => match o.detail {
            Detail::None => o.answer.describe(),
            detail => format!("{} ({detail:?})", o.answer.describe()),
        },
        None => "no answer".to_owned(),
    };
    let theirs = theirs.map_or_else(|| "no answer".to_owned(), Answer::describe);
    format!("ours {ours}, theirs {theirs}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::class::Tags;
    use crate::cmd::{self, Request};
    use crate::model::EcdsaBranch;
    use std::borrow::Cow;

    fn case(requests: Vec<Request>, intents: Vec<Intent>) -> Case {
        Case {
            variant: Cow::Borrowed("v"),
            requests,
            intents,
            consistency: Consistency::None,
            tags: Tags::NONE,
        }
    }

    fn reply(line: &str) -> Reply {
        Reply::from_line(line).expect("reply")
    }

    fn ours(answer: Answer) -> Result<OursAnswer, String> {
        Ok(OursAnswer::plain(answer))
    }

    fn categories(result: &CaseResult) -> Vec<Category> {
        result.failures.iter().map(|f| f.category).collect()
    }

    fn reject(kind: &str, text: &str) -> Answer {
        Answer::Reject {
            kind: Kind::Dcrd(kind.to_owned()),
            text: Some(text.to_owned()),
        }
    }

    #[test]
    fn agreeing_answers_agree() {
        let c = case(
            vec![cmd::ecdsa_parse_der(&[0x30])],
            vec![Intent::RejectKind("ErrSigTooShort")],
        );
        let r = compare(
            &c,
            &[ours(reject("ErrSigTooShort", "ErrSigTooShort"))],
            &[reply(
                "{\"id\":0,\"error\":\"malformed signature: too short\",\"kind\":\"ErrSigTooShort\"}",
            )],
            &ModelView::default(),
        );
        assert_eq!(r.status, Status::Agree, "{r:?}");
        assert_eq!(r.kind_compared, [true]);
        assert_eq!(
            r.theirs,
            [Some(reject(
                "ErrSigTooShort",
                "malformed signature: too short"
            ))]
        );
    }

    /// Each check fires on the difference it is for, in order.
    #[test]
    fn each_check_fires() {
        let key = cmd::pubkey_parse(&[5]);
        let one = |o: Result<OursAnswer, String>, t: &str, intent: Intent| {
            compare(
                &case(vec![key.clone()], vec![intent]),
                &[o],
                &[reply(t)],
                &ModelView::default(),
            )
        };
        let text_err = "{\"error\":\"malformed public key: invalid length: 1\",\"kind\":\"ErrPubKeyInvalidLen\"}";
        let r = one(
            ours(reject("ErrPubKeyInvalidLen", "other text")),
            text_err,
            Intent::Any,
        );
        assert_eq!(categories(&r), [Category::Text]);
        assert_eq!(r.status, Status::Disagree);
        let r = one(
            ours(reject("ErrPubKeyInvalidFormat", "x")),
            text_err,
            Intent::Any,
        );
        assert_eq!(categories(&r), [Category::Kind]);
        let r = one(
            ours(Answer::Value {
                bytes: vec![1],
                flag: None,
            }),
            text_err,
            Intent::RejectKind("ErrPubKeyInvalidLen"),
        );
        assert_eq!(categories(&r), [Category::Verdict, Category::Intent]);
        let r = one(
            ours(Answer::Value {
                bytes: vec![1],
                flag: None,
            }),
            "{\"result\":\"02\",\"compressed\":\"03\"}",
            Intent::AcceptValue(vec![2, 3]),
        );
        assert_eq!(categories(&r), [Category::Value]);
        let r = one(Err("boom".into()), text_err, Intent::Any);
        assert_eq!(categories(&r), [Category::OursPanicked]);
        assert_eq!(r.status, Status::OursPanicked);
        let r = one(
            ours(reject("ErrPubKeyInvalidLen", "x")),
            "{\"result\":\"zz\"}",
            Intent::Any,
        );
        assert_eq!(categories(&r), [Category::Protocol]);
        assert_eq!(r.theirs, [None]);

        // Unavailable is never compared, and passes.
        let r = one(
            ours(Answer::Reject {
                kind: Kind::Unavailable,
                text: None,
            }),
            text_err,
            Intent::RejectKind("ErrPubKeyInvalidLen"),
        );
        assert_eq!(
            (r.status, r.kind_compared.as_slice()),
            (Status::Agree, &[false][..])
        );

        // The flag of a recovery.
        let rec = cmd::ecdsa_recover_compact(&[0; 32], &[]);
        let r = compare(
            &case(vec![rec], vec![Intent::Any]),
            &[ours(Answer::Value {
                bytes: vec![2],
                flag: Some(false),
            })],
            &[reply("{\"result\":\"02\",\"was_compressed\":\"true\"}")],
            &ModelView::default(),
        );
        assert_eq!(categories(&r), [Category::Flag]);
    }

    /// A verify command: `Accept` needs `true` on both sides, `Reject`
    /// `false` or an error, and the range rejection of dcroxide matches
    /// either of dcrd's range kinds.
    #[test]
    fn verify_intents_and_scalar_range() {
        let req = cmd::ecdsa_verify_raw(&[2; 33], &[0; 32], &[0; 32], &[0; 32]);
        let run = |o: Answer, t: &str, intent: Intent| {
            compare(
                &case(vec![req.clone()], vec![intent]),
                &[ours(o)],
                &[reply(t)],
                &ModelView::default(),
            )
        };
        assert_eq!(
            run(
                Answer::Verdict(true),
                "{\"result\":\"true\"}",
                Intent::Accept
            )
            .status,
            Status::Agree
        );
        let r = run(
            Answer::Verdict(false),
            "{\"result\":\"false\"}",
            Intent::Accept,
        );
        assert_eq!(categories(&r), [Category::Intent]);
        assert_eq!(
            run(
                Answer::Verdict(false),
                "{\"result\":\"false\"}",
                Intent::Reject
            )
            .status,
            Status::Agree
        );
        let range = Answer::Reject {
            kind: Kind::ScalarRange,
            text: None,
        };
        let r = run(
            range.clone(),
            "{\"error\":\"invalid signature: S >= group order\",\"kind\":\"ErrSigSTooBig\"}",
            Intent::RejectKind("ErrSigSTooBig"),
        );
        assert_eq!(r.status, Status::Agree, "{r:?}");
        assert_eq!(
            run(
                range,
                "{\"error\":\"e\",\"kind\":\"ErrSigSTooBig\"}",
                Intent::Reject
            )
            .status,
            Status::Agree
        );
    }

    /// `Reject` fails when either side accepts, even when the two agree;
    /// `RejectPlain` also when dcrd's rejection carries a kind.
    #[test]
    fn rejection_intents_fail_on_an_acceptance() {
        let req = cmd::ecdsa_verify_raw(&[2; 33], &[0; 32], &[1; 32], &[1; 32]);
        let run = |o: Answer, t: &str| {
            compare(
                &case(vec![req.clone()], vec![Intent::Reject]),
                &[ours(o)],
                &[reply(t)],
                &ModelView::default(),
            )
        };
        let r = run(Answer::Verdict(true), "{\"result\":\"true\"}");
        assert_eq!(categories(&r), [Category::Intent], "both accept");
        for (o, t) in [
            (true, "{\"result\":\"false\"}"),
            (false, "{\"result\":\"true\"}"),
        ] {
            let r = run(Answer::Verdict(o), t);
            assert_eq!(
                categories(&r),
                [Category::Verdict, Category::Intent],
                "ours {o}"
            );
        }
        let r = run(
            Answer::Reject {
                kind: Kind::ScalarRange,
                text: None,
            },
            "{\"error\":\"e\",\"kind\":\"ErrSigRTooBig\"}",
        );
        assert_eq!(r.status, Status::Agree, "an error is a rejection");

        let key = cmd::schnorr_pubkey_parse(&[4; 65]);
        let text = "bad pubkey byte string size (want 33, have 65)";
        let plain = format!("{{\"error\":\"{text}\"}}");
        let one = |o: Answer, t: &str| {
            compare(
                &case(vec![key.clone()], vec![Intent::RejectPlain]),
                &[ours(o)],
                &[reply(t)],
                &ModelView::default(),
            )
        };
        let ours_plain = Answer::Reject {
            kind: Kind::Plain,
            text: Some(text.to_owned()),
        };
        assert_eq!(one(ours_plain.clone(), &plain).status, Status::Agree);
        let r = one(
            ours_plain,
            "{\"error\":\"x\",\"kind\":\"ErrPubKeyInvalidLen\"}",
        );
        assert_eq!(categories(&r), [Category::Kind, Category::Intent]);
        let value = Answer::Value {
            bytes: vec![2],
            flag: None,
        };
        let r = one(value.clone(), &plain);
        assert_eq!(categories(&r), [Category::Verdict, Category::Intent]);
        let r = one(value, "{\"result\":\"02\"}");
        assert_eq!(categories(&r), [Category::Intent], "both accept");
    }

    /// A branch intent needs the model's branch, dcrd's verdict for it,
    /// the doubling the generator tagged, and dcroxide's step when it
    /// reports one.
    #[test]
    fn branch_and_schnorr_intents() {
        let req = cmd::ecdsa_verify_raw(&[2; 33], &[0; 32], &[1; 32], &[1; 32]);
        let mut c = case(vec![req], vec![Intent::Branch(EcdsaBranch::Step10Accept)]);
        let model = |branch, doubled| ModelView {
            per_request: vec![Some(ModelOutcome::Ecdsa { branch, doubled })],
        };
        let t = [reply("{\"result\":\"true\"}")];
        let o = [ours(Answer::Verdict(true))];
        assert_eq!(
            compare(&c, &o, &t, &model(EcdsaBranch::Step10Accept, false)).status,
            Status::Agree
        );
        let r = compare(&c, &o, &t, &model(EcdsaBranch::Step8Accept, false));
        assert_eq!(categories(&r), [Category::Intent]);
        let r = compare(&c, &o, &t, &ModelView::default());
        assert_eq!(
            categories(&r),
            [Category::Intent],
            "a missing model outcome fails"
        );
        let detailed = [Ok(OursAnswer {
            answer: Answer::Verdict(true),
            detail: Detail::Ecdsa(EcdsaBranch::Step8Accept),
        })];
        let r = compare(&c, &detailed, &t, &model(EcdsaBranch::Step10Accept, false));
        assert_eq!(
            categories(&r),
            [Category::Intent],
            "dcroxide's own step is held to it"
        );
        c.tags = Tags::NONE.with(Tag::Doubled);
        let r = compare(&c, &o, &t, &model(EcdsaBranch::Step10Accept, false));
        assert_eq!(
            categories(&r),
            [Category::Intent],
            "the doubling must be confirmed"
        );
        assert_eq!(
            compare(&c, &o, &t, &model(EcdsaBranch::Step10Accept, true)).status,
            Status::Agree
        );

        let req = cmd::schnorr_verify(&[2; 33], &[0; 32], &[0; 64]);
        let c = case(vec![req], vec![Intent::Schnorr(Err("ErrSigRYIsOdd"))]);
        let model = ModelView {
            per_request: vec![Some(ModelOutcome::Schnorr {
                reason: Err("ErrSigRYIsOdd"),
                doubled: false,
            })],
        };
        let t = [reply("{\"result\":\"false\"}")];
        let good = [Ok(OursAnswer {
            answer: Answer::Verdict(false),
            detail: Detail::Schnorr(Err("ErrSigRYIsOdd")),
        })];
        assert_eq!(compare(&c, &good, &t, &model).status, Status::Agree);
        let bad = [Ok(OursAnswer {
            answer: Answer::Verdict(false),
            detail: Detail::Schnorr(Err("ErrUnequalRValues")),
        })];
        assert_eq!(
            categories(&compare(&c, &bad, &t, &model)),
            [Category::Intent]
        );
    }

    #[test]
    fn consistency_across_requests() {
        let req = cmd::ecdsa_verify_raw(&[2; 33], &[0; 32], &[1; 32], &[1; 32]);
        let mut c = case(vec![req.clone(), req], vec![Intent::Any, Intent::Any]);
        c.consistency = Consistency::SameVerdict;
        let o = [ours(Answer::Verdict(true)), ours(Answer::Verdict(false))];
        let t = [
            reply("{\"result\":\"true\"}"),
            reply("{\"result\":\"false\"}"),
        ];
        let r = compare(
            &c,
            &o,
            &t,
            &ModelView {
                per_request: vec![None, None],
            },
        );
        assert_eq!(categories(&r), [Category::Consistency]);
        let o = [ours(Answer::Verdict(true)), ours(Answer::Verdict(true))];
        let t = [
            reply("{\"result\":\"true\"}"),
            reply("{\"result\":\"true\"}"),
        ];
        assert_eq!(
            compare(&c, &o, &t, &ModelView::default()).status,
            Status::Agree
        );
    }

    #[test]
    fn an_oracle_failure_has_no_answers() {
        let r = CaseResult::oracle_failure(
            2,
            &[ours(Answer::Verdict(true)), ours(Answer::Verdict(true))],
            Category::OracleHung,
            "hung".into(),
        );
        assert_eq!(r.status, Status::OracleFailure);
        assert_eq!(r.theirs, [None, None]);
        assert_eq!(categories(&r), [Category::OracleHung]);
        let r = CaseResult::oracle_failure(
            1,
            &[Err("boom".into())],
            Category::OracleCrashed,
            "exited".into(),
        );
        assert_eq!(r.status, Status::OursPanicked);
        assert_eq!(
            categories(&r),
            [Category::OracleCrashed, Category::OursPanicked]
        );
    }
}
