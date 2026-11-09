// SPDX-License-Identifier: ISC
//! The crate's points at its API edge: [`Affine`], always on the curve,
//! never infinity, both coordinates normalized, and [`Point`], an opaque
//! Jacobian point with an infinity flag, the result of [`ecmult_var`].
//! All inputs are public; everything is variable time.

use crate::field::Fe;
use crate::group::{Ge, Gej};
use crate::scalar::Scalar;

/// A curve point in affine coordinates: on the curve, never infinity, and
/// both coordinates **normalized** (canonical limbs, value below p).
/// Every constructor establishes it and debug builds assert it; every
/// reader (`y_is_odd`, `to_be_bytes`, equality) relies on it.
#[derive(Clone, Copy, Debug)]
pub struct Affine(Ge);

impl PartialEq for Affine {
    /// Equality of the normalized limbs; nothing derived reaches the
    /// field's debug bookkeeping.
    fn eq(&self, other: &Self) -> bool {
        self.0.x.raw().n == other.0.x.raw().n && self.0.y.raw().n == other.0.y.raw().n
    }
}

impl Eq for Affine {}

impl Affine {
    /// Debug builds: not infinity, both coordinates claimed normalized.
    #[inline(always)]
    fn check(&self) {
        debug_assert!(!self.0.infinity);
        #[cfg(debug_assertions)]
        assert!(self.0.x.is_normalized_claim() && self.0.y.is_normalized_claim());
    }

    /// From a group element that is on the curve, not infinity and
    /// normalized (debug-asserted).
    #[inline(always)]
    #[must_use]
    fn from_ge_unchecked(g: Ge) -> Self {
        let r = Self(g);
        r.check();
        r
    }

    /// The inner group element (tests).
    #[cfg(test)]
    #[must_use]
    pub(crate) fn as_ge(&self) -> &Ge {
        &self.0
    }

    /// The point (x, y), each given big-endian; `None` unless both are
    /// below p and y^2 = x^3 + 7 (`ge_set_xy` and `ge_is_valid_var`).
    #[must_use]
    pub fn from_be_coordinates(x: &[u8; 32], y: &[u8; 32]) -> Option<Self> {
        let x = Fe::set_b32_limit(x)?;
        let y = Fe::set_b32_limit(y)?;
        let g = Ge::set_xy(&x, &y);
        if !g.is_valid_var() {
            return None;
        }
        Some(Self::from_ge_unchecked(g))
    }

    /// Key decompression, as dcrd's `DecompressY`: the point whose x is
    /// given big-endian and whose y has the parity `y_odd`, or `None` when
    /// x is not below p (checked before any field arithmetic) or x^3 + 7 is
    /// not a square.  libsecp256k1's `ge_set_xo_var`, normalizing y before
    /// reading its parity and again after negating it.
    #[must_use]
    pub fn decompress_var(x: &[u8; 32], y_odd: bool) -> Option<Self> {
        let x = Fe::set_b32_limit(x)?;
        let g = Ge::set_xo_var(&x, y_odd)?;
        Some(Self::from_ge_unchecked(g))
    }

    /// (x, y), each big-endian.
    #[must_use]
    pub fn to_be_bytes(&self) -> ([u8; 32], [u8; 32]) {
        self.check();
        (self.0.x.get_b32(), self.0.y.get_b32())
    }

    /// Whether y is odd.
    #[must_use]
    pub fn y_is_odd(&self) -> bool {
        self.check();
        self.0.y.is_odd()
    }
}

/// A curve point in Jacobian coordinates with an explicit infinity flag:
/// what [`ecmult_var`] returns.  Opaque; it answers whether it is infinity
/// and whether its affine x is a given value, without an inversion.
#[derive(Clone, Copy, Debug)]
pub struct Point(Gej);

impl Point {
    /// Wraps a Jacobian point (tests).
    #[cfg(test)]
    #[must_use]
    pub(crate) fn from_gej(g: Gej) -> Self {
        Self(g)
    }

    /// The inner Jacobian point (tests).
    #[cfg(test)]
    #[must_use]
    pub(crate) fn as_gej(&self) -> &Gej {
        &self.0
    }

    /// Whether this is the point at infinity (the flag).
    #[inline(always)]
    #[must_use]
    pub fn is_infinity(&self) -> bool {
        self.0.is_infinity()
    }

    /// Whether the affine x of this point equals x, given big-endian:
    /// libsecp256k1's `gej_eq_x_var`, X == x * Z^2, with no inversion.
    /// False at infinity.  x is parsed with the limit check and not
    /// reduced, so x >= p gives false, and builds with debug assertions
    /// stop on it, since no caller passes one: ECDSA verification passes r
    /// below N, and r + N only once r is below P - N.
    #[inline]
    #[must_use]
    pub fn x_equals_var(&self, x_be: &[u8; 32]) -> bool {
        if self.0.is_infinity() {
            return false;
        }
        let Some(x) = Fe::set_b32_limit(x_be) else {
            debug_assert!(false, "x_equals_var: x >= p");
            return false;
        };
        self.0.eq_x_var(&x)
    }
}

/// ng*G + na*A, by libsecp256k1's Straus loop over the static window-12
/// tables of G and 2^128*G.  `None` only if the wNAF builder declines a
/// half of the GLV split, which libsecp256k1's bound proof rules out;
/// callers fall back, and the tests require `Some`.
#[inline]
#[must_use]
pub fn ecmult_var(a: &Affine, na: &Scalar, ng: &Scalar) -> Option<Point> {
    a.check();
    crate::ecmult::ecmult_var(&a.0, na, ng).map(Point)
}
