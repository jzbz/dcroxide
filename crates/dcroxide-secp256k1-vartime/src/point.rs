// SPDX-License-Identifier: ISC
//! [`Affine`], the crate's curve point at its API edge: always on the
//! curve, never infinity, both coordinates normalized.  All inputs are
//! public; everything is variable time.

use crate::field::Fe;
use crate::group::Ge;

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
