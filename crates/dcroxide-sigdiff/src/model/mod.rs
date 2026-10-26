// SPDX-License-Identifier: ISC
//! Reference models of dcrd's signature algorithms, written on this crate's
//! own arithmetic, that say which of dcrd's steps decides a constructed
//! case.
//!
//! dcrd's ECDSA and Schnorr verification return only a boolean, so a class
//! built to reach one branch (the r + N comparison, the point at infinity,
//! a doubling) is checked against a model that re-derives the deciding step
//! from the request bytes, independently of the code under test.  The run
//! asks [`view`] for a case's outcomes on the producer thread, before the
//! case is submitted, and [`crate::compare::compare`] holds them against
//! each request's [`Intent`].

pub mod ecdsa;

use crate::class::{Case, Intent};
use crate::cmd::Request;

/// The step of dcrd's ECDSA verify (`ecdsa/signature.go`, `Verify`) that
/// decides a case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EcdsaBranch {
    /// Step 1: r or s is zero; reject.
    Step1Zero,
    /// Step 6: u1·G + u2·Q is the point at infinity; reject.
    Step6Infinity,
    /// Step 8: r equals the x coordinate of X; accept.
    Step8Accept,
    /// Step 9: r is at or above P − N, so r + N would wrap; reject.
    Step9Reject,
    /// Step 10: r + N equals the x coordinate of X; accept.
    Step10Accept,
    /// Step 10: r + N does not equal it either; reject.
    Step10Reject,
}

impl EcdsaBranch {
    /// Whether dcrd's verdict at this step is `true`.
    pub fn accepts(self) -> bool {
        matches!(self, EcdsaBranch::Step8Accept | EcdsaBranch::Step10Accept)
    }

    /// The step's name, as records print it.
    pub fn name(self) -> &'static str {
        match self {
            EcdsaBranch::Step1Zero => "Step1Zero",
            EcdsaBranch::Step6Infinity => "Step6Infinity",
            EcdsaBranch::Step8Accept => "Step8Accept",
            EcdsaBranch::Step9Reject => "Step9Reject",
            EcdsaBranch::Step10Accept => "Step10Accept",
            EcdsaBranch::Step10Reject => "Step10Reject",
        }
    }
}

/// What a model says about one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelOutcome {
    /// The ECDSA model: the deciding step, and whether u1·G and u2·Q were
    /// equal, so that dcrd's addition doubled.
    Ecdsa {
        /// The step that decides.
        branch: EcdsaBranch,
        /// Whether the sum's two summands were the same point.
        doubled: bool,
    },
    /// The Schnorr model: dcrd's internal reason (`Ok` for a valid
    /// signature, else the `ErrorKind` name), and whether s·G and e·Q were
    /// equal.
    Schnorr {
        /// The reason.
        reason: Result<(), &'static str>,
        /// Whether the sum's two summands were the same point.
        doubled: bool,
    },
}

/// The models' view of one case: one entry per request, computed only for
/// requests whose intent is [`Intent::Branch`] or [`Intent::Schnorr`],
/// whose keys are valid by construction; `None` elsewhere.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ModelView {
    /// The outcome of each request, in request order.
    pub per_request: Vec<Option<ModelOutcome>>,
}

/// The models' view of `case`.
pub fn view(case: &Case) -> ModelView {
    ModelView {
        per_request: case
            .requests
            .iter()
            .zip(&case.intents)
            .map(|(request, intent)| outcome(request, intent))
            .collect(),
    }
}

/// The model outcome for one request.  The ECDSA model answers the
/// requests built for a branch ([`ecdsa::request_outcome`]); no model is
/// consulted for any other intent.  A request the model cannot decode, and
/// a Schnorr reason until the Schnorr model is in place, get `None`, which
/// [`crate::compare::compare`] reports as an intent failure, so a class
/// cannot pass unchecked.
fn outcome(request: &Request, intent: &Intent) -> Option<ModelOutcome> {
    match intent {
        Intent::Branch(_) => ecdsa::request_outcome(request),
        _ => None,
    }
}
