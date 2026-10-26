// SPDX-License-Identifier: ISC
//! The canaries: deliberately broken stand-ins for dcroxide, which show
//! that the classes can fail.
//!
//! A canary answers in dcroxide's place for the commands it covers,
//! inside the comparison; the code under test is never touched.  Each gets
//! one of dcrd's branches wrong the way a plausible bug would, and must
//! disagree with dcrd in the class built for that branch (its primary) and
//! in no class outside those it declares (its footprint).  A class that
//! could not tell a canary from dcroxide could not catch that bug either.
//!
//! There are two kinds:
//!
//! - Model canaries: one of [`crate::model`]'s models with one [`Break`]
//!   switched on.  Before a model verifies, dcroxide's own code parses the
//!   request ([`ours::ecdsa_verify_parts`] and its siblings), so
//!   dcroxide's rejections, kinds and texts stand and only the arithmetic
//!   after parsing is the model's.  The parsed key reaches `k256` through
//!   its uncompressed bytes and `from_coordinates`.  Compact recovery is
//!   the model's from the first byte, with dcrd's kinds.
//! - Wrapper canaries: dcroxide's answer, changed by a rule on the request
//!   bytes.  Every answer the rule does not name passes through as
//!   dcroxide gives it, rejections and details included.
//!
//! [`MODEL_BASELINE`] stands every model in for dcroxide with no break.  It
//! must agree with dcrd everywhere, which shows that each model canary
//! fires only because of its break, and holds the models themselves
//! against dcrd.
//!
//! Seven canaries fire, by construction, in classes beside their primary:
//! a parser that reduces a coordinate mod P also accepts the K-XTooBig and
//! K-YTooBig inputs whose reduced value decodes, for instance.  Each
//! declares those classes as its footprint, and the canary run fails a
//! canary that disagrees anywhere else.

use crate::answer::{Answer, Detail, Kind, OursAnswer};
use crate::arith::{self, HALF_N, N, P};
use crate::class::{CLASSES, ClassSpec, find_class, glob_match};
use crate::cmd::Cmd;
use crate::r#gen::from_xy;
use crate::model::{self, Break};
use crate::ours;

/// The commands a model answers: ECDSA verification in both layouts,
/// compact recovery, EC-Schnorr-DCRv0 verification and Ed25519 raw
/// verification.
pub const MODEL_COMMANDS: &[Cmd] = &[
    Cmd::EcdsaVerify,
    Cmd::EcdsaVerifyRaw,
    Cmd::EcdsaRecoverCompact,
    Cmd::SchnorrVerify,
    Cmd::Ed25519Verify,
];

/// ECDSA verification, both layouts.
const ECDSA_VERIFY: &[Cmd] = &[Cmd::EcdsaVerify, Cmd::EcdsaVerifyRaw];

/// Compact recovery.
const RECOVER: &[Cmd] = &[Cmd::EcdsaRecoverCompact];

/// Every command that parses a secp256k1 public key of any format.
const KEY_PARSE: &[Cmd] = &[
    Cmd::PubkeyParse,
    Cmd::SchnorrPubkeyParse,
    Cmd::EcdsaVerifyRaw,
];

/// EC-Schnorr-DCRv0 verification.
const SCHNORR_VERIFY: &[Cmd] = &[Cmd::SchnorrVerify];

/// Ed25519 raw verification.
const ED25519_VERIFY: &[Cmd] = &[Cmd::Ed25519Verify];

/// ECDSA signing.
const ECDSA_SIGN: &[Cmd] = &[Cmd::EcdsaSign];

/// How a stand-in answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// The models, with this break switched on; with [`Break::None`], the
    /// model baseline.
    Model(Break),
    /// C2: a `true` verdict becomes `false` when s > ⌊N/2⌋, as
    /// libsecp256k1, and the `ecdsa` crate with `NORMALIZE_S`, treat a high
    /// S that parses.  A range rejection stays one: libsecp256k1 too
    /// rejects an s at or above N when it parses.
    LowS,
    /// C4: a hybrid key whose coordinates are off the curve is rejected
    /// with ErrPubKeyNotOnCurve, the curve tested before the oddness.
    CurveBeforeOddness,
    /// C5: a coordinate at or above P is reduced mod P instead of
    /// rejected.
    ReduceModP,
    /// C6: a `true` verdict becomes `false` when r ≥ N, with
    /// ErrUnequalRValues as its reason.
    RBelowN,
    /// C9: the hash is reduced mod N before signing, which is the nonce
    /// input libsecp256k1 takes, by asking dcroxide to sign the reduced
    /// hash.
    SignReducedHash,
}

/// Something that answers in dcroxide's place: a canary, or the model
/// baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StandIn {
    /// Its name, as `--canary` takes it.
    pub name: &'static str,
    /// How it answers.
    pub rule: Rule,
    /// The commands it answers; dcroxide answers every other.
    pub commands: &'static [Cmd],
}

impl StandIn {
    /// Whether it answers `cmd`.
    pub fn covers(&self, cmd: Cmd) -> bool {
        self.commands.contains(&cmd)
    }

    /// Its answer to `cmd` with argument bytes `data`, for a command it
    /// covers.  Like dcroxide's adapter, it panics on a layout it cannot
    /// decode.
    pub fn answer(&self, cmd: Cmd, data: &[u8]) -> OursAnswer {
        assert!(
            self.covers(cmd),
            "{}: does not answer {}",
            self.name,
            cmd.name()
        );
        match self.rule {
            Rule::Model(brk) => model_answer(brk, cmd, data),
            Rule::LowS => low_s(cmd, data),
            Rule::CurveBeforeOddness => curve_before_oddness(cmd, data),
            Rule::ReduceModP => reduce_mod_p(cmd, data),
            Rule::RBelowN => r_below_n(data),
            Rule::SignReducedHash => sign_reduced_hash(data),
        }
    }

    /// Every class that sends one of its commands, in registry order.
    pub fn classes(&self) -> Vec<&'static ClassSpec> {
        CLASSES
            .iter()
            .filter(|class| class.commands.iter().any(|&cmd| self.covers(cmd)))
            .collect()
    }
}

/// The model baseline: every model, with no break, in dcroxide's place for
/// every command a model answers.
pub const MODEL_BASELINE: StandIn = StandIn {
    name: "model-baseline",
    rule: Rule::Model(Break::None),
    commands: MODEL_COMMANDS,
};

/// The cases of its primary within which a canary must first disagree with
/// dcrd: the canary run takes at most this many, and a canary first caught
/// at a later index fails.
pub const CANARY_BOUND: u64 = 10_000;

/// A deliberately broken stand-in for dcroxide, with the classes it must
/// and may disagree with dcrd in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Canary {
    /// Its short name, `C1` to `C18`.
    pub id: &'static str,
    /// Its name.
    pub name: &'static str,
    /// How it answers.
    pub rule: Rule,
    /// The commands it answers in dcroxide's place.
    pub commands: &'static [Cmd],
    /// The class it must disagree with dcrd in, within [`CANARY_BOUND`]
    /// cases.
    pub primary: &'static str,
    /// The other classes it may disagree in.
    pub footprint: &'static [&'static str],
    /// Cases of the primary the per-PR test runs, when more than the
    /// primary's own per-PR count are needed for the canary to fire with
    /// certainty in practice.
    pub pr_primary: Option<u64>,
    /// What it gets wrong, and why its primary catches it.
    pub doc: &'static str,
}

impl Canary {
    /// It as a stand-in.
    pub fn stand_in(&self) -> StandIn {
        StandIn {
            name: self.name,
            rule: self.rule,
            commands: self.commands,
        }
    }

    /// `model` or `wrapper`.
    pub fn kind(&self) -> &'static str {
        match self.rule {
            Rule::Model(_) => "model",
            _ => "wrapper",
        }
    }

    /// The primary class.
    pub fn primary_class(&self) -> &'static ClassSpec {
        find_class(self.primary).unwrap_or_else(|| panic!("{}: no class {}", self.id, self.primary))
    }

    /// The cases of its primary the per-PR test runs.
    pub fn primary_pr_cases(&self) -> u64 {
        self.pr_primary
            .unwrap_or_else(|| self.primary_class().pr_cases)
    }

    /// Whether it may disagree with dcrd in `class`: its primary or a class
    /// of its footprint.
    pub fn may_fire_in(&self, class: &str) -> bool {
        class == self.primary || self.footprint.contains(&class)
    }

    /// Every class that sends one of its commands, other than its primary,
    /// in registry order.
    pub fn others(&self) -> Vec<&'static ClassSpec> {
        self.stand_in()
            .classes()
            .into_iter()
            .filter(|class| class.name != self.primary)
            .collect()
    }
}

/// Every canary, C1 to C18.
pub static CANARIES: &[Canary] = &[
    Canary {
        id: "C1",
        name: "ecdsa-verify-no-rplusn",
        rule: Rule::Model(Break::EcdsaNoRPlusN),
        commands: ECDSA_VERIFY,
        primary: "EV-xGEN-true",
        footprint: &[],
        pr_primary: None,
        doc: "ECDSA verify without steps 9 and 10: every EV-xGEN-true case verifies only \
              through r + N",
    },
    Canary {
        id: "C2",
        name: "ecdsa-verify-low-s",
        rule: Rule::LowS,
        commands: ECDSA_VERIFY,
        primary: "EV-highS",
        footprint: &["EV-sEdge"],
        pr_primary: None,
        doc: "rejects a valid signature whose s is above N/2: every EV-highS case, and \
              EV-sEdge's two high-S strata",
    },
    Canary {
        id: "C3",
        name: "recover-ignores-overflow-bit",
        rule: Rule::Model(Break::RecoverIgnoresOverflow),
        commands: RECOVER,
        primary: "ER-overflowValid",
        footprint: &["ER-overflowPrime", "ER-notOnCurve", "ER-header"],
        pr_primary: None,
        doc: "compact recovery that takes x = r under every header: every ER-overflowValid \
              case recovers through x = r + N, and every overflow header elsewhere changes",
    },
    Canary {
        id: "C4",
        name: "pubkey-curve-before-oddness",
        rule: Rule::CurveBeforeOddness,
        commands: KEY_PARSE,
        primary: "K-hybridMismatch",
        footprint: &[],
        pr_primary: None,
        doc: "key parsing that tests the curve before a hybrid key's oddness: \
              K-hybridMismatch's off-curve half",
    },
    Canary {
        id: "C5",
        name: "pubkey-reduce-mod-p",
        rule: Rule::ReduceModP,
        commands: KEY_PARSE,
        primary: "K-wrap",
        footprint: &["K-XTooBig", "K-YTooBig"],
        pr_primary: None,
        doc: "key parsing that reduces a coordinate at or above P: every K-wrap case decodes \
              once reduced, and K-XTooBig and K-YTooBig cases answer otherwise",
    },
    Canary {
        id: "C6",
        name: "schnorr-verify-r-below-n",
        rule: Rule::RBelowN,
        commands: SCHNORR_VERIFY,
        primary: "SV-rGEN-true",
        footprint: &[],
        pr_primary: None,
        doc: "Schnorr verify that rejects r at or above N: every SV-rGEN-true case is valid \
              with r = R.x >= N",
    },
    Canary {
        id: "C7",
        name: "ed25519-scalar-negation",
        rule: Rule::Model(Break::Ed25519ScalarNegation),
        commands: ED25519_VERIFY,
        primary: "DV-torsion",
        footprint: &["DV-torsionSweep", "DV-torsionNoncanon", "DV-zeroS-smallR"],
        pr_primary: None,
        doc: "Ed25519 verify computing s·B + (L - k)·A: 48 of DV-torsion's 128 cases, and \
              the other torsion classes",
    },
    Canary {
        id: "C8",
        name: "ed25519-hash-input-key",
        rule: Rule::Model(Break::Ed25519HashInputKey),
        commands: ED25519_VERIFY,
        primary: "DV-torsionNoncanon",
        footprint: &[],
        // It fires on about a quarter of the class's cases: 128 leave odds
        // of about 10^-16 that it never does.
        pr_primary: Some(128),
        doc: "Ed25519 verify hashing the key's bytes as given: DV-torsionNoncanon's order-4 \
              keys, about a quarter of its cases",
    },
    Canary {
        id: "C9",
        name: "ecdsa-sign-reduced-hash",
        rule: Rule::SignReducedHash,
        commands: ECDSA_SIGN,
        primary: "ES-hashGEN",
        footprint: &[],
        pr_primary: None,
        doc: "ECDSA signing over the hash mod N, which changes the RFC6979 nonce: every \
              ES-hashGEN hash is at or above N",
    },
    Canary {
        id: "C10",
        name: "ecdsa-verify-infinity-accepts",
        rule: Rule::Model(Break::EcdsaAcceptsInfinity),
        commands: ECDSA_VERIFY,
        primary: "EV-infinity",
        footprint: &[],
        pr_primary: None,
        doc: "ECDSA verify accepting when u1·G + u2·Q is the point at infinity: every \
              EV-infinity case",
    },
    Canary {
        id: "C11",
        name: "ecdsa-verify-incomplete-add",
        rule: Rule::Model(Break::EcdsaIncompleteAdd),
        commands: ECDSA_VERIFY,
        primary: "EV-double",
        footprint: &[],
        pr_primary: None,
        doc: "ECDSA verify with incomplete addition: every EV-double case's sum doubles",
    },
    Canary {
        id: "C12",
        name: "schnorr-verify-incomplete-add",
        rule: Rule::Model(Break::SchnorrIncompleteAdd),
        commands: SCHNORR_VERIFY,
        primary: "SV-double",
        footprint: &["SV-infinity"],
        pr_primary: None,
        doc: "Schnorr verify with incomplete addition: every SV-double case, and SV-infinity's \
              reason, since its sum is no longer the point at infinity",
    },
    Canary {
        id: "C13",
        name: "recover-incomplete-add",
        rule: Rule::Model(Break::RecoverIncompleteAdd),
        commands: RECOVER,
        primary: "ER-double",
        footprint: &["ER-infinity"],
        pr_primary: None,
        doc: "compact recovery with incomplete addition: every ER-double case, and \
              ER-infinity, whose sum is no longer the point at infinity",
    },
    Canary {
        id: "C14",
        name: "recover-accepts-infinity",
        rule: Rule::Model(Break::RecoverAcceptsInfinity),
        commands: RECOVER,
        primary: "ER-infinity",
        footprint: &[],
        pr_primary: None,
        doc: "compact recovery returning a key when Q is the point at infinity: every \
              ER-infinity case",
    },
    Canary {
        id: "C15",
        name: "ed25519-compare-decoded-r",
        rule: Rule::Model(Break::Ed25519CompareDecodedR),
        commands: ED25519_VERIFY,
        primary: "DV-zeroS-smallR",
        footprint: &[],
        pr_primary: None,
        doc: "Ed25519 verify comparing R as a point: DV-zeroS-smallR's 43 non-canonical strata, \
              R as y + p, signed on an x of zero, or both",
    },
    Canary {
        id: "C16",
        name: "ed25519-verify-s-range",
        rule: Rule::Model(Break::Ed25519SRange),
        commands: ED25519_VERIFY,
        primary: "DV-zeroS-smallR",
        footprint: &["DV-SplusL"],
        pr_primary: None,
        doc: "Ed25519 verify rejecting S = 0 or S >= L: DV-zeroS-smallR's 43 canonical strata, \
              and every DV-SplusL case",
    },
    Canary {
        id: "C17",
        name: "ecdsa-verify-no-step9",
        rule: Rule::Model(Break::EcdsaNoStep9),
        commands: ECDSA_VERIFY,
        primary: "EV-xGEN-wrap",
        footprint: &[],
        pr_primary: None,
        doc: "ECDSA verify without step 9's guard, comparing (r + N) mod P: every \
              EV-xGEN-wrap case",
    },
    Canary {
        id: "C18",
        name: "schnorr-verify-r-mod-n",
        rule: Rule::Model(Break::SchnorrRModN),
        commands: SCHNORR_VERIFY,
        primary: "SV-unequalR",
        footprint: &[],
        pr_primary: None,
        doc: "Schnorr verify comparing R.x mod N with r mod N: SV-unequalR's xminusN and \
              xplusN strata",
    },
];

/// The canary named `name` (by its name or its id).
pub fn find_canary(name: &str) -> Option<&'static Canary> {
    CANARIES.iter().find(|c| c.name == name || c.id == name)
}

/// The stand-in named `name`: a canary, by its name or id, or the model
/// baseline.
pub fn find_stand_in(name: &str) -> Option<StandIn> {
    if name == MODEL_BASELINE.name {
        return Some(MODEL_BASELINE);
    }
    find_canary(name).map(Canary::stand_in)
}

/// The canaries a `--canary` list selects, in registry order: names, ids or
/// patterns with `*`, comma-separated.  An empty list or `all` selects
/// every canary; an item that matches none is an error.
pub fn select_canaries(list: &str) -> Result<Vec<&'static Canary>, String> {
    let list = list.trim();
    if list.is_empty() || list == "all" {
        return Ok(CANARIES.iter().collect());
    }
    let mut chosen = vec![false; CANARIES.len()];
    for item in list.split(',').map(str::trim) {
        if item.is_empty() {
            return Err(format!("empty item in the canary list {list:?}"));
        }
        let mut matched = false;
        for (canary, chosen) in CANARIES.iter().zip(chosen.iter_mut()) {
            if glob_match(item, canary.name) || glob_match(item, canary.id) {
                *chosen = true;
                matched = true;
            }
        }
        if !matched {
            return Err(format!(
                "{item:?} names no canary (sigsoak list --canaries prints them)"
            ));
        }
    }
    Ok(CANARIES
        .iter()
        .zip(chosen)
        .filter_map(|(canary, chosen)| chosen.then_some(canary))
        .collect())
}

/// The model's answer, with `brk` switched on.
fn model_answer(brk: Break, cmd: Cmd, data: &[u8]) -> OursAnswer {
    match cmd {
        Cmd::EcdsaVerify | Cmd::EcdsaVerifyRaw => {
            OursAnswer::plain(match ours::ecdsa_verify_parts(cmd, data) {
                Ok(parts) => {
                    let decision = model::ecdsa::verify_with(
                        &key_point(&parts.key),
                        &parts.hash,
                        &parts.r,
                        &parts.s,
                        brk,
                    )
                    .expect("a signature dcroxide parsed holds r and s below N");
                    Answer::Verdict(decision.accepts)
                }
                Err(reject) => reject,
            })
        }
        Cmd::EcdsaRecoverCompact => {
            let (hash, sig) = data.split_first_chunk::<32>().unwrap_or_else(|| {
                panic!("{}: {} bytes do not fit its layout", cmd.name(), data.len())
            });
            OursAnswer::plain(match model::ecdsa::recover_with(sig, hash, brk) {
                Ok(got) => Answer::Value {
                    bytes: got.serialized(),
                    flag: Some(got.compressed),
                },
                Err(kind) => Answer::Reject {
                    kind: Kind::Dcrd(kind.to_owned()),
                    text: None,
                },
            })
        }
        Cmd::SchnorrVerify => match ours::schnorr_verify_parts(data) {
            Ok(parts) => {
                let (reason, _) = model::schnorr::verify_with(
                    &key_point(&parts.key),
                    &parts.hash,
                    &parts.r,
                    &parts.s,
                    brk,
                )
                .expect("a signature dcroxide parsed holds r below P and s below N");
                OursAnswer {
                    answer: Answer::Verdict(reason.is_ok()),
                    detail: Detail::Schnorr(reason),
                }
            }
            Err(reject) => OursAnswer::plain(reject),
        },
        Cmd::Ed25519Verify => OursAnswer::plain(match ours::ed25519_verify_parts(data) {
            Ok(parts) => {
                let key = model::ed25519::PublicKey {
                    encoded: parts.key,
                    canonical: parts.canonical,
                    point: model::ed25519::decode(&parts.canonical)
                        .expect("a key dcroxide parsed decodes"),
                };
                Answer::Verdict(
                    model::ed25519::verify_with(&key, parts.msg, &parts.sig, brk).is_ok(),
                )
            }
            Err(reject) => reject,
        }),
        _ => panic!("{}: no model answers it", cmd.name()),
    }
}

/// The point of a key dcroxide parsed, from its uncompressed bytes.
fn key_point(uncompressed: &[u8; 65]) -> k256::AffinePoint {
    let (x, y) = uncompressed[1..].split_at(32);
    from_xy(
        x.try_into().expect("32 bytes"),
        y.try_into().expect("32 bytes"),
    )
    .expect("a key dcroxide parsed is a point of the curve")
}

/// The key of an `ecdsa_verify_raw` request (key_len ‖ key ‖ ...), or
/// `None` when the request is too short to hold it.
fn raw_key_range(data: &[u8]) -> Option<std::ops::Range<usize>> {
    let len = usize::from(*data.first()?);
    let end = len.checked_add(1)?;
    (end <= data.len()).then_some(1..end)
}

/// C2.
fn low_s(cmd: Cmd, data: &[u8]) -> OursAnswer {
    let ours = ours::answer(cmd, data);
    if ours.answer == Answer::Verdict(true)
        && let Ok(parts) = ours::ecdsa_verify_parts(cmd, data)
        && parts.s > HALF_N
    {
        return OursAnswer {
            answer: Answer::Verdict(false),
            detail: ours.detail,
        };
    }
    ours
}

/// C4.  `schnorr_pubkey_parse` refuses every key but a 33-byte one by its
/// length, before any oddness, so its answers pass through.
fn curve_before_oddness(cmd: Cmd, data: &[u8]) -> OursAnswer {
    let key = match cmd {
        Cmd::PubkeyParse => Some(data),
        Cmd::EcdsaVerifyRaw => raw_key_range(data).map(|range| &data[range]),
        _ => None,
    };
    if let Some(reject) = key.and_then(off_curve_first) {
        return OursAnswer::plain(reject);
    }
    ours::answer(cmd, data)
}

/// For a 65-byte hybrid key (06 or 07) whose coordinates are off the
/// curve: the ErrPubKeyNotOnCurve rejection dcroxide gives the same
/// coordinates under 04, which a parser that tests the curve before the
/// oddness gives whatever the parity.  `None` for any other key.
fn off_curve_first(key: &[u8]) -> Option<Answer> {
    if key.len() != 65 || !matches!(key[0], 0x06 | 0x07) {
        return None;
    }
    let mut uncompressed = key.to_vec();
    uncompressed[0] = 0x04;
    let answer = ours::answer(Cmd::PubkeyParse, &uncompressed).answer;
    matches!(
        &answer,
        Answer::Reject { kind: Kind::Dcrd(kind), .. } if kind == "ErrPubKeyNotOnCurve"
    )
    .then_some(answer)
}

/// C5.
fn reduce_mod_p(cmd: Cmd, data: &[u8]) -> OursAnswer {
    let mut data = data.to_vec();
    let key = match cmd {
        Cmd::PubkeyParse | Cmd::SchnorrPubkeyParse => Some(0..data.len()),
        Cmd::EcdsaVerifyRaw => raw_key_range(&data),
        _ => None,
    };
    if let Some(range) = key {
        reduce_key(&mut data[range]);
    }
    ours::answer(cmd, &data)
}

/// Replaces each coordinate of a key at or above P by its value less P,
/// where the key's length and format byte are ones dcrd parses (02/03 ‖ x,
/// 04/06/07 ‖ x ‖ y); dcrd's earlier checks then still come first.
fn reduce_key(key: &mut [u8]) {
    let coordinates = match key {
        [0x02 | 0x03, rest @ ..] if rest.len() == 32 => rest,
        [0x04 | 0x06 | 0x07, rest @ ..] if rest.len() == 64 => rest,
        _ => return,
    };
    for value in coordinates.as_chunks_mut::<32>().0 {
        if *value >= P {
            *value = arith::sub_be(value, &P).0;
        }
    }
}

/// C6: `schnorr_verify` is 33-byte key ‖ hash ‖ r ‖ s.
fn r_below_n(data: &[u8]) -> OursAnswer {
    let ours = ours::answer(Cmd::SchnorrVerify, data);
    let r_at_or_above_n = data.get(65..97).is_some_and(|r| r >= &N[..]);
    if ours.answer == Answer::Verdict(true) && r_at_or_above_n {
        return OursAnswer {
            answer: Answer::Verdict(false),
            detail: Detail::Schnorr(Err("ErrUnequalRValues")),
        };
    }
    ours
}

/// C9: `ecdsa_sign` is key ‖ hash.
fn sign_reduced_hash(data: &[u8]) -> OursAnswer {
    let mut data = data.to_vec();
    if let Some(hash) = data.get_mut(32..64) {
        let hash: &mut [u8; 32] = hash.try_into().expect("32 bytes");
        if *hash >= N {
            *hash = arith::sub_be(hash, &N).0;
        }
    }
    ours::answer(Cmd::EcdsaSign, &data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::class::generate;
    use crate::cmd;
    use crate::r#gen::{base_mul, compressed};
    use std::collections::HashSet;

    /// The registry is the design's: C1 to C18 with unique names, each with
    /// the design's primary and footprint; every primary and footprint
    /// class exists and sends one of the canary's commands; no footprint
    /// names the primary or repeats; a model canary covers only commands a
    /// model answers.
    #[test]
    fn the_registry_is_consistent() {
        let ids: Vec<&str> = CANARIES.iter().map(|c| c.id).collect();
        let want: Vec<String> = (1..=18).map(|n| format!("C{n}")).collect();
        assert_eq!(ids, want);
        let mut names = HashSet::new();
        for canary in CANARIES {
            assert!(names.insert(canary.name), "{} twice", canary.name);
            assert_ne!(canary.name, MODEL_BASELINE.name);
            assert!(!canary.commands.is_empty() && !canary.doc.is_empty());
            let classes: Vec<&str> = canary.stand_in().classes().iter().map(|c| c.name).collect();
            assert!(
                classes.contains(&canary.primary),
                "{}: {} sends none of its commands",
                canary.id,
                canary.primary
            );
            let mut footprint = HashSet::new();
            for class in canary.footprint {
                assert!(classes.contains(class), "{}: footprint {class}", canary.id);
                assert_ne!(*class, canary.primary, "{}", canary.id);
                assert!(footprint.insert(class), "{}: {class} twice", canary.id);
            }
            assert!(canary.may_fire_in(canary.primary));
            assert!(!canary.others().iter().any(|c| c.name == canary.primary));
            assert_eq!(canary.others().len(), classes.len() - 1, "{}", canary.id);
            assert!(canary.primary_pr_cases() >= canary.primary_class().pr_cases);
            if let Rule::Model(brk) = canary.rule {
                assert_ne!(brk, Break::None, "{}", canary.id);
                assert!(
                    canary.commands.iter().all(|c| MODEL_COMMANDS.contains(c)),
                    "{}",
                    canary.id
                );
                assert_eq!(canary.kind(), "model");
            } else {
                assert_eq!(canary.kind(), "wrapper");
            }
            assert_eq!(find_canary(canary.id), Some(canary));
            assert_eq!(find_canary(canary.name), Some(canary));
            assert_eq!(find_stand_in(canary.name), Some(canary.stand_in()));
        }
        // Each canary's primary and footprint, as the design's table has
        // them: seven fire beside their primary, by construction.  A wider
        // footprint would hide a firing the canary run must report.
        let table: Vec<(&str, &str, &[&str])> = CANARIES
            .iter()
            .map(|c| (c.id, c.primary, c.footprint))
            .collect();
        let none: &[&str] = &[];
        assert_eq!(
            table,
            [
                ("C1", "EV-xGEN-true", none),
                ("C2", "EV-highS", &["EV-sEdge"][..]),
                (
                    "C3",
                    "ER-overflowValid",
                    &["ER-overflowPrime", "ER-notOnCurve", "ER-header"][..]
                ),
                ("C4", "K-hybridMismatch", none),
                ("C5", "K-wrap", &["K-XTooBig", "K-YTooBig"][..]),
                ("C6", "SV-rGEN-true", none),
                (
                    "C7",
                    "DV-torsion",
                    &["DV-torsionSweep", "DV-torsionNoncanon", "DV-zeroS-smallR"][..]
                ),
                ("C8", "DV-torsionNoncanon", none),
                ("C9", "ES-hashGEN", none),
                ("C10", "EV-infinity", none),
                ("C11", "EV-double", none),
                ("C12", "SV-double", &["SV-infinity"][..]),
                ("C13", "ER-double", &["ER-infinity"][..]),
                ("C14", "ER-infinity", none),
                ("C15", "DV-zeroS-smallR", none),
                ("C16", "DV-zeroS-smallR", &["DV-SplusL"][..]),
                ("C17", "EV-xGEN-wrap", none),
                ("C18", "SV-unequalR", none),
            ]
        );
        assert_eq!(find_stand_in("model-baseline"), Some(MODEL_BASELINE));
        assert_eq!(find_stand_in("C0"), None);
        assert_eq!(MODEL_BASELINE.classes().len(), 18 + 12 + 11 + 9);
    }

    #[test]
    fn canary_lists_select_by_name_id_and_pattern() {
        let ids = |list: &str| -> Result<Vec<&str>, String> {
            select_canaries(list).map(|v| v.iter().map(|c| c.id).collect())
        };
        assert_eq!(ids("all").expect("all").len(), 18);
        assert_eq!(ids("").expect("empty").len(), 18);
        assert_eq!(
            ids("C9, recover-accepts-infinity").expect("two"),
            ["C9", "C14"]
        );
        assert_eq!(
            ids("ed25519-*").expect("pattern"),
            ["C7", "C8", "C15", "C16"]
        );
        assert_eq!(ids("C1").expect("one id"), ["C1"], "C1 is not C1*");
        assert!(ids("C19").is_err());
        assert!(ids("C1,").is_err());
    }

    /// Each canary, standing in, answers its primary otherwise than
    /// dcroxide does within the per-PR count, which, since dcroxide agrees
    /// with dcrd there, is a disagreement with dcrd.  The oracle-backed
    /// test, `tests/canaries.rs`, holds them against dcrd itself.
    #[test]
    fn every_canary_changes_an_answer_in_its_primary() {
        for canary in CANARIES {
            let stand_in = canary.stand_in();
            let class = canary.primary_class();
            let changed = (0..canary.primary_pr_cases()).find(|&i| {
                let case = generate(class, 0x5eed, i);
                case.requests.iter().any(|r| {
                    stand_in.covers(r.cmd)
                        && stand_in.answer(r.cmd, &r.data) != ours::answer(r.cmd, &r.data)
                })
            });
            assert!(
                changed.is_some(),
                "{} {} never changes an answer of {}",
                canary.id,
                canary.name,
                class.name
            );
        }
    }

    /// The Ed25519 canaries that fire in DV-zeroS-smallR change an answer
    /// on the strata their docs name, over one cycle of its 86: C15 on the
    /// 43 non-canonical ones, C16 on the 43 canonical ones, and C7 on the
    /// 42 canonical ones whose T is not the identity, where (L - k)·T is
    /// -k·T + 5·T.
    #[test]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "a counter of at most 86 cases in usize"
    )]
    fn the_zero_s_canaries_change_their_strata() {
        let class = find_class("DV-zeroS-smallR").expect("DV-zeroS-smallR");
        let cases: Vec<_> = (0..86).map(|i| generate(class, 0x5eed, i)).collect();
        for (id, count) in [("C15", 43), ("C16", 43), ("C7", 42)] {
            let stand_in = find_canary(id).expect("a canary").stand_in();
            let mut changed = 0;
            for case in &cases {
                let v = &case.variant;
                let fires = match id {
                    "C15" => v.starts_with("noncanonical/"),
                    "C16" => v.starts_with("canonical/"),
                    _ => v.starts_with("canonical/") && !v.starts_with("canonical/T0/"),
                };
                let r = &case.requests[0];
                let differs = stand_in.answer(r.cmd, &r.data) != ours::answer(r.cmd, &r.data);
                assert_eq!(differs, fires, "{id}: {v}");
                changed += usize::from(differs);
            }
            assert_eq!(changed, count, "{id}");
        }
    }

    /// The wrappers, C2, C4, C5, C6 and C9, change exactly the answers
    /// their rules name.
    #[test]
    fn wrappers_follow_their_rules() {
        let mut d = [0u8; 32];
        d[31] = 1;
        let hash = [9u8; 32];
        let low = |cmd: Cmd, data: &[u8]| low_s(cmd, data).answer;
        let reduce = |cmd: Cmd, data: &[u8]| reduce_mod_p(cmd, data).answer;

        // C2: dcroxide's own low-S signature passes; its high-S twin
        // verifies for dcroxide and not for the wrapper; a range rejection
        // stays one.
        let signed = ours::answer(Cmd::EcdsaSign, &[d, hash].concat()).answer;
        let Answer::Value { bytes: der, .. } = signed else {
            panic!("{signed:?}");
        };
        let key = compressed(&base_mul(&k256::Scalar::ONE));
        let (r, s) = model::ecdsa::decode_der(&der).expect("minimal DER");
        let high = arith::sub_be(&N, &s).0;
        let ok = cmd::ecdsa_verify_raw(&key, &hash, &r, &s);
        let flipped = cmd::ecdsa_verify_raw(&key, &hash, &r, &high);
        assert_eq!(low(ok.cmd, &ok.data), Answer::Verdict(true));
        assert_eq!(
            ours::answer(flipped.cmd, &flipped.data).answer,
            Answer::Verdict(true)
        );
        assert_eq!(low(flipped.cmd, &flipped.data), Answer::Verdict(false));
        let range = cmd::ecdsa_verify_raw(&key, &hash, &r, &N);
        assert_eq!(
            low(range.cmd, &range.data),
            ours::answer(range.cmd, &range.data).answer
        );
        // At the boundary: EV-sEdge's s = ⌊N/2⌋ is low and passes, its
        // s = ⌊N/2⌋ + 1 and N − 1 are high and are refused, in every
        // presentation.
        let s_edge = find_class("EV-sEdge").expect("EV-sEdge");
        for i in 0..16 {
            let case = generate(s_edge, 0x5eed, i);
            let req = &case.requests[0];
            assert_eq!(
                ours::answer(req.cmd, &req.data).answer,
                Answer::Verdict(true)
            );
            let high = case.variant.starts_with("s=N-1") || case.variant.starts_with("s=N/2+1");
            assert_eq!(
                low(req.cmd, &req.data),
                Answer::Verdict(!high),
                "{}",
                case.variant
            );
        }

        // C5: x + P under 02 parses as x (x = 1 is an x coordinate); x at
        // or above P under an invalid format stays an invalid format; a
        // valid key is untouched.
        let mut small = [0u8; 33];
        small[0] = 0x02;
        small[32] = 1;
        let mut wrapped = small;
        wrapped[1..].copy_from_slice(&arith::add_be(&arith::be_from_u64(1), &P).0);
        for cmd in [Cmd::PubkeyParse, Cmd::SchnorrPubkeyParse] {
            let small_answer = ours::answer(cmd, &small).answer;
            assert!(small_answer.accepted(), "{cmd:?}");
            assert_eq!(reduce(cmd, &wrapped), small_answer, "{cmd:?}");
            assert_ne!(ours::answer(cmd, &wrapped).answer, small_answer, "{cmd:?}");
        }
        let mut bad_format = [0xffu8; 33];
        bad_format[0] = 0x05;
        assert_eq!(
            reduce(Cmd::PubkeyParse, &bad_format),
            ours::answer(Cmd::PubkeyParse, &bad_format).answer
        );
        assert_eq!(
            reduce(ok.cmd, &ok.data),
            ours::answer(ok.cmd, &ok.data).answer
        );
        let mut key = [0u8; 65];
        key[0] = 0x04;
        key[1..33].fill(0xff);
        key[33..].fill(0xff);
        reduce_key(&mut key);
        assert_eq!(key[1..33], arith::sub_be(&[0xff; 32], &P).0);
        assert_eq!(key[33..], arith::sub_be(&[0xff; 32], &P).0);

        // C4: a hybrid key off the curve with the other parity's byte,
        // which dcroxide rejects for its oddness, is rejected as off the
        // curve, by itself and inside a raw verify request; on the curve,
        // the oddness stands.
        let g = base_mul(&k256::Scalar::ONE);
        let (x, y) = (crate::r#gen::x_of(&g), crate::r#gen::y_of(&g));
        let off = arith::add_be(&y, &arith::be_from_u64(2)).0;
        let wrong = 0x06 | u8::from(!crate::r#gen::y_is_odd(&g));
        let off_key = crate::r#gen::with_format(wrong, &x, &off);
        let on_key = crate::r#gen::with_format(wrong, &x, &y);
        let not_on_curve = |answer: &Answer| matches!(answer, Answer::Reject { kind: Kind::Dcrd(k), .. } if k == "ErrPubKeyNotOnCurve");
        for req in [
            cmd::pubkey_parse(&off_key),
            cmd::ecdsa_verify_raw(&off_key, &hash, &r, &s),
        ] {
            let ours = ours::answer(req.cmd, &req.data).answer;
            assert!(
                matches!(&ours, Answer::Reject { kind: Kind::Dcrd(k), .. } if k == "ErrPubKeyMismatchedOddness"),
                "{ours:?}"
            );
            let broken = curve_before_oddness(req.cmd, &req.data).answer;
            assert!(not_on_curve(&broken), "{:?}: {broken:?}", req.cmd);
        }
        for req in [
            cmd::pubkey_parse(&on_key),
            cmd::ecdsa_verify_raw(&on_key, &hash, &r, &s),
            cmd::schnorr_pubkey_parse(&off_key),
        ] {
            assert_eq!(
                curve_before_oddness(req.cmd, &req.data).answer,
                ours::answer(req.cmd, &req.data).answer,
                "{:?}",
                req.cmd
            );
        }

        // C6: a valid signature with r at or above N, SV-rGEN-true's and one
        // with r = N itself, is refused with ErrUnequalRValues as its
        // reason; a valid one with r below N, SV-honest's, and one dcroxide
        // refuses with r at or above N, SV-rGEN-odd's, pass as dcroxide
        // gives them, reason included.
        let flipped = OursAnswer {
            answer: Answer::Verdict(false),
            detail: Detail::Schnorr(Err("ErrUnequalRValues")),
        };
        let schnorr = |name: &str, i: u64| {
            let class = find_class(name).unwrap_or_else(|| panic!("no class {name}"));
            generate(class, 0x5eed, i).requests[0].data.clone()
        };
        for i in 0..4 {
            let valid = schnorr("SV-rGEN-true", i);
            assert_eq!(
                ours::answer(Cmd::SchnorrVerify, &valid),
                OursAnswer {
                    answer: Answer::Verdict(true),
                    detail: Detail::Schnorr(Ok(())),
                }
            );
            assert_eq!(r_below_n(&valid), flipped, "SV-rGEN-true {i}");
            let odd = schnorr("SV-rGEN-odd", i);
            let ours_odd = ours::answer(Cmd::SchnorrVerify, &odd);
            assert_eq!(ours_odd.detail, Detail::Schnorr(Err("ErrSigRYIsOdd")));
            assert_eq!(r_below_n(&odd), ours_odd, "SV-rGEN-odd {i}");
            let honest = schnorr("SV-honest", i);
            assert!(honest[65..97] < N[..], "SV-honest {i}: r below N");
            assert_eq!(
                r_below_n(&honest),
                ours::answer(Cmd::SchnorrVerify, &honest),
                "SV-honest {i}"
            );
        }
        let at_n = schnorr_with_r(&N);
        assert_eq!(
            ours::answer(at_n.cmd, &at_n.data).answer,
            Answer::Verdict(true)
        );
        assert_eq!(r_below_n(&at_n.data), flipped, "r = N");

        // C9: a hash below N is signed as it is; one at or above N as its
        // value less N, N itself as zero.
        let at = |h: &[u8; 32]| sign_reduced_hash(&[d, *h].concat()).answer;
        assert_eq!(
            at(&hash),
            ours::answer(Cmd::EcdsaSign, &[d, hash].concat()).answer
        );
        let one = arith::be_from_u64(1);
        assert_eq!(
            at(&arith::add_be(&N, &one).0),
            ours::answer(Cmd::EcdsaSign, &[d, one].concat()).answer
        );
        assert_eq!(
            at(&N),
            ours::answer(Cmd::EcdsaSign, &[d, [0; 32]].concat()).answer
        );
        assert_ne!(
            at(&N),
            ours::answer(Cmd::EcdsaSign, &[d, N].concat()).answer
        );

        assert_eq!(raw_key_range(&[]), None);
        assert_eq!(raw_key_range(&[3, 1, 2]), None);
        assert_eq!(raw_key_range(&[2, 1, 2]), Some(1..3));
    }

    /// A `schnorr_verify` request that verifies with r = R.x for the point
    /// R of x coordinate `x` and an even y: s = 1, a fixed hash, and the
    /// key solved for, Q = e⁻¹·(R − G).
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
    )]
    fn schnorr_with_r(x: &[u8; 32]) -> cmd::Request {
        let big_r = crate::r#gen::decompress(x, false).expect("an x coordinate");
        let h = [7u8; 32];
        let e = crate::r#gen::schnorr::challenge(x, &h).expect("a challenge below N");
        let e_inv = Option::<k256::Scalar>::from(e.invert()).expect("a nonzero challenge");
        let q = crate::r#gen::finite(
            &((k256::ProjectivePoint::from(big_r) - k256::ProjectivePoint::GENERATOR) * e_inv),
        )
        .expect("a finite key");
        cmd::schnorr_verify(
            &compressed(&q),
            &h,
            &crate::r#gen::schnorr::signature(x, &arith::be_from_u64(1)),
        )
    }

    /// A stand-in answers only its own commands.
    #[test]
    fn a_stand_in_refuses_other_commands() {
        let canary = find_canary("C9").expect("C9");
        assert!(canary.stand_in().covers(Cmd::EcdsaSign));
        assert!(!canary.stand_in().covers(Cmd::EcdsaVerify));
        let result = std::panic::catch_unwind(|| canary.stand_in().answer(Cmd::EcdsaVerify, &[]));
        assert!(result.is_err());
        let result =
            std::panic::catch_unwind(|| model_answer(Break::None, Cmd::PubkeyParse, &[2; 33]));
        assert!(result.is_err());
    }
}
