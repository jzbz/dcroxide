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
//! each request's [`Intent`].  The compact recovery model
//! ([`ecdsa::recover`]) answers with dcrd's key or kind, and the Ed25519
//! model ([`ed25519`]) parses and verifies with dcrd's rules and texts;
//! the recovery and Ed25519 classes' unit tests hold their intents to
//! them.
//!
//! Each model also takes a [`Break`]: one step changed the way a plausible
//! bug would change it.  The canaries ([`crate::canary`]) put a broken
//! model in dcroxide's place to show that the classes built for that step
//! fail when it is wrong; with [`Break::None`] the models are dcrd's
//! algorithms, which the intents and the canaries' model baseline use.

pub mod ecdsa;
pub mod ed25519;
pub mod schnorr;

use k256::{AffinePoint, ProjectivePoint};

use crate::arith::{double_mod_p, neg_mod_p};
use crate::class::{Case, Intent};
use crate::cmd::Request;
use crate::r#gen::{finite, from_xy, x_of, y_of};

/// A step of one of dcrd's algorithms changed the way a plausible bug
/// would change it, for a canary.  Each model reads only the switches that
/// name it and runs dcrd's algorithm under every other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Break {
    /// None: dcrd's algorithms.
    None,
    /// ECDSA verify without steps 9 and 10: a signature step 8 does not
    /// accept is rejected, so r + N is never compared (C1).
    EcdsaNoRPlusN,
    /// ECDSA verify that accepts when u1·G + u2·Q is the point at infinity
    /// (C10).
    EcdsaAcceptsInfinity,
    /// ECDSA verify that adds u1·G and u2·Q with incomplete affine
    /// addition ([`add`]) (C11).
    EcdsaIncompleteAdd,
    /// ECDSA verify without step 9's guard: step 10 compares (r + N) mod P
    /// with X.x, which wraps for r ≥ P − N (C17).
    EcdsaNoStep9,
    /// Compact recovery that ignores the recovery code's overflow bit, so
    /// x is r under every header (C3).
    RecoverIgnoresOverflow,
    /// Compact recovery that adds u1·G and u2·X with incomplete affine
    /// addition (C13).
    RecoverIncompleteAdd,
    /// Compact recovery that returns a key when Q is the point at infinity
    /// (C14).
    RecoverAcceptsInfinity,
    /// EC-Schnorr-DCRv0 verify that adds s·G and e·Q with incomplete affine
    /// addition (C12).
    SchnorrIncompleteAdd,
    /// EC-Schnorr-DCRv0 verify that compares R.x mod N with r mod N (C18).
    SchnorrRModN,
    /// Ed25519 verify that negates the scalar rather than the point:
    /// s·B + (L − k)·A (C7).
    Ed25519ScalarNegation,
    /// Ed25519 verify whose challenge hashes the key's input bytes rather
    /// than its canonical encoding (C8).
    Ed25519HashInputKey,
    /// Ed25519 verify that compares R as a decoded point rather than as
    /// bytes (C15).
    Ed25519CompareDecodedR,
    /// Ed25519 verify that rejects an S of zero or at or above L, as
    /// signature parsing does (C16).
    Ed25519SRange,
}

/// The affine coordinates of a sum a model computed, big-endian and below
/// P: those of a point of the curve, or, from an incomplete addition
/// ([`add`]), coordinates that are not one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Coords {
    /// x.
    pub x: [u8; 32],
    /// y.
    pub y: [u8; 32],
}

impl Coords {
    /// A finite point's coordinates.
    pub fn of(p: &AffinePoint) -> Coords {
        Coords {
            x: x_of(p),
            y: y_of(p),
        }
    }

    /// Whether y is odd.
    pub fn y_is_odd(&self) -> bool {
        self.y[31] & 1 == 1
    }

    /// The point of the curve these coordinates name, if they name one.
    pub fn point(&self) -> Option<AffinePoint> {
        from_xy(&self.x, &self.y)
    }

    /// SEC1 compressed: 02 or 03 by y's parity, then x.
    pub fn compressed(&self) -> [u8; 33] {
        let mut out = [0u8; 33];
        out[0] = 0x02 | u8::from(self.y_is_odd());
        out[1..].copy_from_slice(&self.x);
        out
    }

    /// SEC1 uncompressed: 04, x, y.
    pub fn uncompressed(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[0] = 0x04;
        out[1..33].copy_from_slice(&self.x);
        out[33..].copy_from_slice(&self.y);
        out
    }
}

/// a + b, or `None` for the point at infinity.  dcrd's addition is
/// complete: it doubles a point added to itself and gives the point at
/// infinity for a point added to its negation.  With `incomplete`, two
/// finite points of equal x are added by the textbook affine formula with
/// the inverse of zero taken as zero: the slope is zero, so the sum is
/// (−2·x₁ mod P, −y₁ mod P), which is never a point of the curve (that
/// would take 9·x₁³ = 0).  Every other sum is the same either way.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "k256 point operations only: modular group arithmetic, no integer operator here"
)]
pub fn add(a: &ProjectivePoint, b: &ProjectivePoint, incomplete: bool) -> Option<Coords> {
    if incomplete
        && let (Some(a), Some(b)) = (finite(a), finite(b))
        && x_of(&a) == x_of(&b)
    {
        return Some(Coords {
            x: neg_mod_p(&double_mod_p(&x_of(&a))),
            y: neg_mod_p(&y_of(&a)),
        });
    }
    finite(&(a + b)).map(|p| Coords::of(&p))
}

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
/// requests built for a branch ([`ecdsa::request_outcome`]), the Schnorr
/// model those built for a reason ([`schnorr::request_outcome`]); no model
/// is consulted for any other intent.  A request the model cannot decode
/// gets `None`, which [`crate::compare::compare`] reports as an intent
/// failure, so a class cannot pass unchecked.
fn outcome(request: &Request, intent: &Intent) -> Option<ModelOutcome> {
    match intent {
        Intent::Branch(_) => ecdsa::request_outcome(request),
        Intent::Schnorr(_) => schnorr::request_outcome(request),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arith::{P, add_be, sub_be};
    use crate::r#gen::{base_mul, compressed, uncompressed, y_is_odd};
    use k256::Scalar;

    /// Incomplete addition differs from dcrd's only for two finite points
    /// of equal x: a doubling and a point plus its negation both give
    /// (−2x, −y), off the curve, where dcrd's give 2·A and the point at
    /// infinity.
    #[test]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
    )]
    fn incomplete_addition_breaks_only_equal_x() {
        let a = ProjectivePoint::from(base_mul(&Scalar::from(5u64)));
        let b = ProjectivePoint::from(base_mul(&Scalar::from(7u64)));
        let o = ProjectivePoint::IDENTITY;
        let affine = a.to_affine();
        // −2x and −y, computed apart from the helpers add uses: −y is the
        // negated point's y.
        let x = x_of(&affine);
        let (sum, carry) = add_be(&x, &x);
        let two_x = if carry || sum >= P {
            sub_be(&sum, &P).0
        } else {
            sum
        };
        let broken = Coords {
            x: sub_be(&P, &two_x).0,
            y: y_of(&(-a).to_affine()),
        };
        assert_eq!(add(&a, &a, false), Some(Coords::of(&(a + a).to_affine())));
        assert_eq!(add(&a, &a, true), Some(broken));
        assert_eq!(add(&a, &-a, false), None);
        assert_eq!(add(&a, &-a, true), Some(broken));
        assert_eq!(broken.point(), None, "never a point of the curve");
        for incomplete in [false, true] {
            assert_eq!(
                add(&a, &b, incomplete),
                Some(Coords::of(&(a + b).to_affine()))
            );
            assert_eq!(add(&o, &a, incomplete), Some(Coords::of(&affine)));
            assert_eq!(add(&a, &o, incomplete), Some(Coords::of(&affine)));
            assert_eq!(add(&o, &o, incomplete), None);
        }

        let c = Coords::of(&affine);
        assert_eq!(c.point(), Some(affine));
        assert_eq!(c.compressed(), compressed(&affine));
        assert_eq!(c.uncompressed(), uncompressed(&affine));
        assert_eq!(c.y_is_odd(), y_is_odd(&affine));
    }
}
