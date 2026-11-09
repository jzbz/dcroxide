// SPDX-License-Identifier: ISC AND MIT
//
// Derived from libsecp256k1 src/group_impl.h and src/group.h (both
// Copyright (c) 2013, 2014 Pieter Wuille), as vendored by secp256k1-sys
// 0.14.1.  MIT; see NOTICE.
//
//! secp256k1 group elements in affine coordinates, [`Ge`], with the
//! functions key decompression and the curve check need: `ge_set_xy`,
//! `ge_set_xo_var` and `ge_is_valid_var`.  The Jacobian type, the addition
//! and doubling formulas and the storage form arrive with the multiply.
//!
//! One deviation from libsecp256k1: [`Ge::set_xo_var`] normalizes y again
//! after the conditional negation (libsecp256k1 leaves it at magnitude 2,
//! group_impl.h:358-361, and normalizes later, when it serializes), as
//! dcrd's `DecompressY` does with `Negate(1).Normalize()` (curve.go,
//! :1341-1342 at the parity pin), so both coordinates of a decompressed
//! point are normalized when x is.
//!
//! Every function here is variable time and meant for public data.

use crate::field::Fe;

/// `SECP256K1_GE_X_MAGNITUDE_MAX` (group.h:49).
const GE_X_MAGNITUDE_MAX: u8 = 4;
/// `SECP256K1_GE_Y_MAGNITUDE_MAX` (group.h:50).
const GE_Y_MAGNITUDE_MAX: u8 = 3;

/// The curve constant b of y^2 = x^3 + b (`SECP256K1_B`, group_impl.h:73).
const CURVE_B: u16 = 7;

/// A point in affine coordinates (`secp256k1_ge`, group.h:16-20).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Ge {
    /// x (magnitude <= 4).
    pub(crate) x: Fe,
    /// y (magnitude <= 3).
    pub(crate) y: Fe,
    /// Whether this is the point at infinity (x, y then meaningless).
    pub(crate) infinity: bool,
}

impl Ge {
    /// `ge_verify` (group_impl.h:78-85).  No-op in builds without debug
    /// assertions.
    #[inline(always)]
    pub(crate) fn verify(&self) {
        self.x.verify();
        self.y.verify();
        self.x.verify_magnitude(GE_X_MAGNITUDE_MAX);
        self.y.verify_magnitude(GE_Y_MAGNITUDE_MAX);
    }

    /// `ge_set_xy` (group_impl.h:132-141).
    #[inline(always)]
    #[must_use]
    pub(crate) fn set_xy(x: &Fe, y: &Fe) -> Self {
        x.verify();
        y.verify();
        let r = Self {
            x: *x,
            y: *y,
            infinity: false,
        };
        r.verify();
        r
    }

    /// `ge_set_xo_var` (group_impl.h:347-365): the point with x-coordinate
    /// `x` and y of parity `odd`, or `None` if x^3 + 7 is not a square.
    /// **y is normalized again after the conditional negation**, as dcrd's
    /// `DecompressY` does, so both output coordinates are normalized when
    /// `x` is.
    ///
    /// Precondition (libsecp256k1's, implicit there): magnitude(x) <= 4,
    /// the affine x bound (group.h:49), because x is stored as the output's
    /// x unchanged.  Debug builds check it on entry.  The only caller,
    /// [`crate::Affine::decompress_var`], passes a normalized x.
    #[inline]
    #[must_use]
    pub(crate) fn set_xo_var(x: &Fe, odd: bool) -> Option<Self> {
        x.verify();
        x.verify_magnitude(GE_X_MAGNITUDE_MAX);

        let rx = *x;
        let x2 = x.sqr();
        let mut x3 = x.mul(&x2);
        x3.add_int(CURVE_B);
        let (mut y, ret) = x3.sqrt();
        if !ret {
            return None;
        }
        y.normalize_var();
        if y.is_odd() != odd {
            y = y.negate(1);
            // The negation leaves magnitude 2; normalize again, as dcrd does.
            y.normalize_var();
        }
        let r = Self {
            x: rx,
            y,
            infinity: false,
        };
        r.verify();
        Some(r)
    }

    /// `ge_is_valid_var` (group_impl.h:446-458): on the curve y^2 = x^3 + 7
    /// and not infinity.
    #[inline]
    #[must_use]
    pub(crate) fn is_valid_var(&self) -> bool {
        self.verify();
        if self.infinity {
            return false;
        }
        // y^2 = x^3 + 7
        let y2 = self.y.sqr();
        let mut x3 = self.x.sqr().mul(&self.x);
        x3.add_int(CURVE_B);
        y2.equal(&x3)
    }
}
