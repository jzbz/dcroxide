// SPDX-License-Identifier: ISC
//! Answers both sides are reduced to before they are compared, and their
//! canonical encodings for digests.

use std::borrow::Cow;

use dcroxide_testutil::{hex, unhex};

use crate::cmd::Cmd;
use crate::model::EcdsaBranch;
use crate::reply::Reply;

/// A normalized answer to one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// A verify command ran: `"true"` or `"false"`.
    Verdict(bool),
    /// A parse, sign or recovery succeeded.
    Value {
        /// The value's bytes, per command (`crate::compare` documents the
        /// layout of each).
        bytes: Vec<u8>,
        /// A recovered key's compressed flag; `None` for every other
        /// command.
        flag: Option<bool>,
    },
    /// An error.
    Reject {
        /// Its kind.
        kind: Kind,
        /// Its text, where the side gives one.
        text: Option<String>,
    },
}

/// The kind of a rejection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Kind {
    /// One of dcrd's `ErrorKind` names, which is how the oracle reports
    /// kinds and how dcroxide names them.
    Dcrd(String),
    /// An error with no kind: dcrd returned a plain error (Ed25519 and
    /// Schnorr-key parsing, and the oracle's own layout errors).
    Plain,
    /// dcroxide only: r or s at or above N, without saying which (its raw
    /// signature constructor answers `None` for either).
    ScalarRange,
    /// dcroxide only: an error whose kind dcroxide does not report.
    Unavailable,
}

/// How two kinds compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KindMatch {
    /// The kinds are the same.
    Equal,
    /// dcroxide reports no kind, so none was compared.
    NotCompared,
    /// The kinds differ.
    Differ,
}

/// Holds dcroxide's kind against dcrd's: names must match;
/// [`Kind::ScalarRange`] matches `ErrSigRTooBig` and `ErrSigSTooBig`;
/// [`Kind::Unavailable`] matches any rejection, uncompared; [`Kind::Plain`]
/// matches itself.
pub fn match_kinds(ours: &Kind, theirs: &Kind) -> KindMatch {
    let equal = match (ours, theirs) {
        (Kind::Unavailable, _) => return KindMatch::NotCompared,
        (Kind::Dcrd(a), Kind::Dcrd(b)) => a == b,
        (Kind::ScalarRange, Kind::Dcrd(b)) => b == "ErrSigRTooBig" || b == "ErrSigSTooBig",
        (Kind::Plain, Kind::Plain) => true,
        _ => false,
    };
    if equal {
        KindMatch::Equal
    } else {
        KindMatch::Differ
    }
}

/// Whether a rejection of kind `theirs` to `cmd` has its text compared: every
/// public key parse rejection on both curves, every Ed25519 parse rejection,
/// and a verify command's key rejections, whose text dcroxide reproduces.
/// DER and Schnorr signature rejections compare the kind only.
pub fn compares_text(cmd: Cmd, theirs: &Kind) -> bool {
    match cmd {
        Cmd::PubkeyParse
        | Cmd::SchnorrPubkeyParse
        | Cmd::Ed25519PubkeyParse
        | Cmd::Ed25519Parse
        | Cmd::Ed25519Verify => true,
        Cmd::EcdsaVerify | Cmd::EcdsaVerifyRaw | Cmd::SchnorrVerify => {
            matches!(theirs, Kind::Dcrd(name) if name.starts_with("ErrPubKey"))
        }
        _ => false,
    }
}

/// What dcroxide reports beyond its answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detail {
    /// Nothing.
    None,
    /// The Schnorr verify reason: `Ok`, or dcrd's `ErrorKind` name.
    Schnorr(Result<(), &'static str>),
    /// The step of dcrd's ECDSA verify that decided, when dcroxide reports
    /// it.
    Ecdsa(EcdsaBranch),
}

/// dcroxide's answer to one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OursAnswer {
    /// The answer.
    pub answer: Answer,
    /// What it reports beyond the answer.
    pub detail: Detail,
}

impl OursAnswer {
    /// An answer with no detail.
    pub fn plain(answer: Answer) -> OursAnswer {
        OursAnswer {
            answer,
            detail: Detail::None,
        }
    }
}

impl Answer {
    /// Whether the answer accepts: a `true` verdict or a value.
    pub fn accepted(&self) -> bool {
        matches!(self, Answer::Verdict(true) | Answer::Value { .. })
    }

    /// The answer's one-word outcome label, as `counts.tsv` prints it:
    /// `true`, `false`, `ok`, `reject:<ErrKind>`, `reject:plain`,
    /// `reject:scalar-range` or `reject:unavailable`.
    pub fn label(&self) -> Cow<'static, str> {
        match self {
            Answer::Verdict(true) => Cow::Borrowed("true"),
            Answer::Verdict(false) => Cow::Borrowed("false"),
            Answer::Value { .. } => Cow::Borrowed("ok"),
            Answer::Reject { kind, .. } => match kind {
                Kind::Dcrd(name) => Cow::Owned(format!("reject:{name}")),
                Kind::Plain => Cow::Borrowed("reject:plain"),
                Kind::ScalarRange => Cow::Borrowed("reject:scalar-range"),
                Kind::Unavailable => Cow::Borrowed("reject:unavailable"),
            },
        }
    }

    /// The answer in full, for a record: the label, then a value's hex and
    /// flag or a rejection's text.
    pub fn describe(&self) -> String {
        match self {
            Answer::Verdict(v) => v.to_string(),
            Answer::Value { bytes, flag: None } => format!("ok:{}", hex(bytes)),
            Answer::Value {
                bytes,
                flag: Some(flag),
            } => format!("ok:{}:{flag}", hex(bytes)),
            Answer::Reject { text: None, .. } => self.label().into_owned(),
            Answer::Reject {
                text: Some(text), ..
            } => format!("{}: {text}", self.label()),
        }
    }
}

/// dcrd's answer as the oracle reported it, normalized per command: a
/// verdict for a verify command, the value's bytes for the others
/// (`pubkey_parse`: uncompressed ‖ compressed; `ed25519_sign`: signature ‖
/// key; `ecdsa_recover_compact`: the key, with its flag), or a rejection
/// with dcrd's kind (or none) and text.  An error is a reply whose fields do
/// not fit the command, which no oracle at the pin sends.
pub fn theirs_answer(cmd: Cmd, reply: &Reply) -> Result<Answer, String> {
    if let Some(text) = &reply.error {
        let kind = match &reply.kind {
            Some(name) => Kind::Dcrd(name.clone()),
            None => Kind::Plain,
        };
        return Ok(Answer::Reject {
            kind,
            text: Some(text.clone()),
        });
    }
    let result = reply
        .result
        .as_deref()
        .ok_or_else(|| format!("{}: a reply with neither result nor error", cmd.name()))?;
    let decode = |field: &str, text: &str| -> Result<Vec<u8>, String> {
        let valid = text.len().is_multiple_of(2) && text.bytes().all(|b| b.is_ascii_hexdigit());
        if valid {
            Ok(unhex(text))
        } else {
            Err(format!("{}: {field} is not hex: {text:?}", cmd.name()))
        }
    };
    let value = |bytes: Vec<u8>| Answer::Value { bytes, flag: None };
    match cmd {
        _ if cmd.is_verify() => match result {
            "true" => Ok(Answer::Verdict(true)),
            "false" => Ok(Answer::Verdict(false)),
            other => Err(format!("{}: verdict {other:?}", cmd.name())),
        },
        Cmd::PubkeyParse | Cmd::Ed25519Sign => {
            let second = reply
                .compressed
                .as_deref()
                .ok_or_else(|| format!("{}: no compressed field", cmd.name()))?;
            let mut bytes = decode("result", result)?;
            bytes.extend(decode("compressed", second)?);
            Ok(value(bytes))
        }
        Cmd::EcdsaRecoverCompact => {
            let flag = reply
                .was_compressed
                .ok_or_else(|| format!("{}: no was_compressed field", cmd.name()))?;
            Ok(Answer::Value {
                bytes: decode("result", result)?,
                flag: Some(flag),
            })
        }
        Cmd::HashString => Ok(value(result.as_bytes().to_vec())),
        Cmd::BuildInfo => Err("build_info has no answer to compare".to_owned()),
        _ => Ok(value(decode("result", result)?)),
    }
}

/// Appends the canonical encoding of dcrd's answer to a request of `cmd`
/// (`None`: no answer) to a digest leaf's input: a tag byte (0 true, 1
/// false, 2 value, 3 rejection with a kind, 4 rejection without one, 5 no
/// answer); for a value `u32be(len) ‖ bytes ‖ u8(flag: 0 none, 1 false,
/// 2 true)`; for a kind `u8(len) ‖ kind`; and for a rejection
/// `u32be(len) ‖ text` when its text is compared ([`compares_text`]), else
/// `u32be(0)`.  dcroxide's kinds ([`Kind::ScalarRange`],
/// [`Kind::Unavailable`]) never appear here.
pub fn canon(cmd: Cmd, theirs: Option<&Answer>, out: &mut Vec<u8>) {
    let push_len32 = |out: &mut Vec<u8>, len: usize| {
        let len = u32::try_from(len).expect("an answer under 4 GiB");
        out.extend_from_slice(&len.to_be_bytes());
    };
    match theirs {
        None => out.push(5),
        Some(Answer::Verdict(true)) => out.push(0),
        Some(Answer::Verdict(false)) => out.push(1),
        Some(Answer::Value { bytes, flag }) => {
            out.push(2);
            push_len32(out, bytes.len());
            out.extend_from_slice(bytes);
            out.push(match flag {
                None => 0,
                Some(false) => 1,
                Some(true) => 2,
            });
        }
        Some(Answer::Reject { kind, text }) => {
            match kind {
                Kind::Dcrd(name) => {
                    out.push(3);
                    out.push(u8::try_from(name.len()).expect("a kind name under 256 bytes"));
                    out.extend_from_slice(name.as_bytes());
                }
                Kind::Plain | Kind::ScalarRange | Kind::Unavailable => out.push(4),
            }
            match text {
                Some(text) if compares_text(cmd, kind) => {
                    push_len32(out, text.len());
                    out.extend_from_slice(text.as_bytes());
                }
                _ => push_len32(out, 0),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(line: &str) -> Reply {
        Reply::from_line(line).expect("reply")
    }

    fn reject(kind: Kind, text: &str) -> Answer {
        Answer::Reject {
            kind,
            text: Some(text.to_owned()),
        }
    }

    #[test]
    fn theirs_normalizes_each_command() {
        assert_eq!(
            theirs_answer(Cmd::EcdsaVerify, &reply("{\"result\":\"true\"}")),
            Ok(Answer::Verdict(true))
        );
        assert_eq!(
            theirs_answer(Cmd::Ed25519Verify, &reply("{\"result\":\"false\"}")),
            Ok(Answer::Verdict(false))
        );
        assert_eq!(
            theirs_answer(Cmd::EcdsaParseDer, &reply("{\"result\":\"00ff\"}")),
            Ok(Answer::Value {
                bytes: vec![0, 0xff],
                flag: None
            })
        );
        assert_eq!(
            theirs_answer(
                Cmd::PubkeyParse,
                &reply("{\"result\":\"04aa\",\"compressed\":\"02bb\"}")
            ),
            Ok(Answer::Value {
                bytes: vec![4, 0xaa, 2, 0xbb],
                flag: None
            })
        );
        assert_eq!(
            theirs_answer(
                Cmd::EcdsaRecoverCompact,
                &reply("{\"result\":\"03cc\",\"was_compressed\":\"true\"}")
            ),
            Ok(Answer::Value {
                bytes: vec![3, 0xcc],
                flag: Some(true)
            })
        );
        assert_eq!(
            theirs_answer(
                Cmd::EcdsaVerifyRaw,
                &reply(
                    "{\"error\":\"invalid signature: R >= group order\",\"kind\":\"ErrSigRTooBig\"}"
                )
            ),
            Ok(reject(
                Kind::Dcrd("ErrSigRTooBig".into()),
                "invalid signature: R >= group order"
            ))
        );
        assert_eq!(
            theirs_answer(
                Cmd::SchnorrPubkeyParse,
                &reply("{\"error\":\"bad pubkey byte string size (want 33, have 1)\"}")
            ),
            Ok(reject(
                Kind::Plain,
                "bad pubkey byte string size (want 33, have 1)"
            ))
        );
        assert_eq!(
            theirs_answer(Cmd::HashString, &reply("{\"result\":\"ab\"}")),
            Ok(Answer::Value {
                bytes: b"ab".to_vec(),
                flag: None
            })
        );
        for (cmd, line) in [
            (Cmd::EcdsaVerify, "{\"result\":\"yes\"}"),
            (Cmd::EcdsaVerify, "{}"),
            (Cmd::EcdsaParseDer, "{\"result\":\"0g\"}"),
            (Cmd::EcdsaParseDer, "{\"result\":\"abc\"}"),
            (Cmd::PubkeyParse, "{\"result\":\"04\"}"),
            (Cmd::EcdsaRecoverCompact, "{\"result\":\"03\"}"),
            (Cmd::BuildInfo, "{\"result\":\"x\"}"),
        ] {
            assert!(theirs_answer(cmd, &reply(line)).is_err(), "{cmd:?} {line}");
        }
    }

    #[test]
    fn kinds_match_by_the_rules() {
        let dcrd = |s: &str| Kind::Dcrd(s.to_owned());
        assert_eq!(match_kinds(&dcrd("ErrA"), &dcrd("ErrA")), KindMatch::Equal);
        assert_eq!(match_kinds(&dcrd("ErrA"), &dcrd("ErrB")), KindMatch::Differ);
        assert_eq!(
            match_kinds(&Kind::ScalarRange, &dcrd("ErrSigRTooBig")),
            KindMatch::Equal
        );
        assert_eq!(
            match_kinds(&Kind::ScalarRange, &dcrd("ErrSigSTooBig")),
            KindMatch::Equal
        );
        assert_eq!(
            match_kinds(&Kind::ScalarRange, &dcrd("ErrSigRIsZero")),
            KindMatch::Differ
        );
        assert_eq!(
            match_kinds(&Kind::Unavailable, &dcrd("ErrX")),
            KindMatch::NotCompared
        );
        assert_eq!(
            match_kinds(&Kind::Unavailable, &Kind::Plain),
            KindMatch::NotCompared
        );
        assert_eq!(match_kinds(&Kind::Plain, &Kind::Plain), KindMatch::Equal);
        assert_eq!(match_kinds(&Kind::Plain, &dcrd("ErrA")), KindMatch::Differ);
        assert_eq!(match_kinds(&dcrd("ErrA"), &Kind::Plain), KindMatch::Differ);

        assert!(compares_text(Cmd::PubkeyParse, &dcrd("ErrPubKeyXTooBig")));
        assert!(compares_text(Cmd::SchnorrPubkeyParse, &Kind::Plain));
        assert!(compares_text(
            Cmd::EcdsaVerifyRaw,
            &dcrd("ErrPubKeyNotOnCurve")
        ));
        assert!(!compares_text(Cmd::EcdsaVerifyRaw, &dcrd("ErrSigRTooBig")));
        assert!(!compares_text(Cmd::EcdsaVerify, &dcrd("ErrSigTooShort")));
        assert!(!compares_text(Cmd::EcdsaParseDer, &dcrd("ErrSigTooShort")));
        assert!(!compares_text(Cmd::SchnorrParse, &dcrd("ErrSigRTooBig")));
        assert!(compares_text(Cmd::Ed25519Verify, &Kind::Plain));
    }

    #[test]
    fn labels_and_descriptions() {
        assert_eq!(Answer::Verdict(true).label(), "true");
        assert_eq!(Answer::Verdict(false).label(), "false");
        let value = Answer::Value {
            bytes: vec![1],
            flag: Some(false),
        };
        assert_eq!(value.label(), "ok");
        assert_eq!(value.describe(), "ok:01:false");
        assert!(value.accepted() && Answer::Verdict(true).accepted());
        assert!(!Answer::Verdict(false).accepted());
        let r = reject(Kind::Dcrd("ErrSigTooShort".into()), "too short");
        assert_eq!(r.label(), "reject:ErrSigTooShort");
        assert_eq!(r.describe(), "reject:ErrSigTooShort: too short");
        assert!(!r.accepted());
        for (kind, label) in [
            (Kind::Plain, "reject:plain"),
            (Kind::ScalarRange, "reject:scalar-range"),
            (Kind::Unavailable, "reject:unavailable"),
        ] {
            let r = Answer::Reject { kind, text: None };
            assert_eq!(r.label(), label);
            assert_eq!(r.describe(), label);
        }
    }

    /// The canonical encodings, byte for byte as documented.
    #[test]
    fn canonical_encodings() {
        let enc = |cmd: Cmd, a: Option<&Answer>| {
            let mut out = Vec::new();
            canon(cmd, a, &mut out);
            out
        };
        assert_eq!(enc(Cmd::EcdsaVerify, Some(&Answer::Verdict(true))), [0]);
        assert_eq!(enc(Cmd::EcdsaVerify, Some(&Answer::Verdict(false))), [1]);
        assert_eq!(enc(Cmd::EcdsaVerify, None), [5]);
        assert_eq!(
            enc(
                Cmd::EcdsaParseDer,
                Some(&Answer::Value {
                    bytes: vec![0xaa, 0xbb],
                    flag: None
                })
            ),
            [2, 0, 0, 0, 2, 0xaa, 0xbb, 0]
        );
        assert_eq!(
            enc(
                Cmd::EcdsaRecoverCompact,
                Some(&Answer::Value {
                    bytes: vec![],
                    flag: Some(true)
                })
            ),
            [2, 0, 0, 0, 0, 2]
        );
        // A DER kind: the kind, and no text.
        assert_eq!(
            enc(
                Cmd::EcdsaParseDer,
                Some(&reject(Kind::Dcrd("ErrX".into()), "ignored"))
            ),
            [3, 4, b'E', b'r', b'r', b'X', 0, 0, 0, 0]
        );
        // A key kind: the kind and the text.
        assert_eq!(
            enc(
                Cmd::PubkeyParse,
                Some(&reject(Kind::Dcrd("ErrK".into()), "ab"))
            ),
            [3, 4, b'E', b'r', b'r', b'K', 0, 0, 0, 2, b'a', b'b']
        );
        assert_eq!(
            enc(Cmd::Ed25519Parse, Some(&reject(Kind::Plain, "c"))),
            [4, 0, 0, 0, 1, b'c']
        );
        assert_eq!(
            enc(
                Cmd::EcdsaSign,
                Some(&Answer::Reject {
                    kind: Kind::Plain,
                    text: None
                })
            ),
            [4, 0, 0, 0, 0]
        );
    }
}
