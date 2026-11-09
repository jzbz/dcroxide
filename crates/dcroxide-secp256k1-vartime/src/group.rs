// SPDX-License-Identifier: ISC AND MIT
//
// Derived from libsecp256k1 src/group_impl.h and src/group.h (both
// Copyright (c) 2013, 2014 Pieter Wuille), as vendored by secp256k1-sys
// 0.14.1.  MIT; see NOTICE.
//
//! secp256k1 group elements: [`Ge`] (affine, with an infinity flag),
//! [`Gej`] (Jacobian, (x, y) = (X/Z^2, Y/Z^3), with an infinity flag) and
//! [`GeStorage`] (a normalized affine point in 4x64 form, the generator
//! tables' entry).
//!
//! The formulas are libsecp256k1's, ported operation for operation so that
//! the branches libsecp256k1's Sage prover checks
//! (`sage/prove_group_implementations.sage`) are the branches that run.
//! Every special case is kept: the accumulator at infinity, the addend at
//! infinity, equal points (the addition doubles) and opposite points (the
//! sum is infinity).  Infinity is a flag, never a coordinate test.
//!
//! Doubling has no other case on secp256k1: 2Q is infinity only for Q at
//! infinity, since a point with y = 0 would need x^3 = -7, and -7 has no
//! cube root mod p (group_impl.h:498-507).  The effective-affine key table
//! cannot meet equal x either: an addition there adds 2Q to (2i-1)Q for
//! 2i-1 <= 13, and (2i-1)Q = +-2Q would need (2i+1)Q or (2i-3)Q to be
//! infinity, impossible in a group of prime order above 15.  That is debug-asserted where the table is built, never
//! checked in release.
//!
//! Two deviations from libsecp256k1, both normalizations dcrd also makes:
//!
//! - [`Ge::set_xo_var`] normalizes y again after the conditional negation
//!   (libsecp256k1 leaves it at magnitude 2, group_impl.h:358-361, and
//!   normalizes later, when it serializes), as dcrd's `DecompressY` does
//!   with `Negate(1).Normalize()` (curve.go, :1341-1342 at the parity
//!   pin), so both coordinates of a decompressed point are normalized when
//!   x is.
//! - `Ge::set_gej_var`, behind `Point::to_affine_var`, normalizes x and y
//!   (libsecp256k1 leaves magnitude 1, group_impl.h:186-191), as dcrd's
//!   `ToAffine` does.
//!
//! Every function here is variable time and meant for public data.  In
//! test builds each formula records the branch it took
//! (`crate::tests::branches`), so the Straus loop's tests can count the
//! special cases per call site; nothing is recorded in other builds.

#[cfg(test)]
use crate::field::BETA;
use crate::field::{Fe, FeStorage};

/// `SECP256K1_GE_X_MAGNITUDE_MAX` (group.h:49).
const GE_X_MAGNITUDE_MAX: u8 = 4;
/// `SECP256K1_GE_Y_MAGNITUDE_MAX` (group.h:50).
const GE_Y_MAGNITUDE_MAX: u8 = 3;

/// `SECP256K1_GEJ_X_MAGNITUDE_MAX` (group.h:51).
pub(crate) const GEJ_X_MAGNITUDE_MAX: u8 = 4;
/// `SECP256K1_GEJ_Y_MAGNITUDE_MAX` (group.h:52).
const GEJ_Y_MAGNITUDE_MAX: u8 = 4;
/// `SECP256K1_GEJ_Z_MAGNITUDE_MAX` (group.h:53).
const GEJ_Z_MAGNITUDE_MAX: u8 = 1;

/// The curve constant b of y^2 = x^3 + b (`SECP256K1_B`, group_impl.h:73).
const CURVE_B: u16 = 7;

/// Records the branch a formula took (test builds only).
macro_rules! note {
    ($b:ident) => {
        #[cfg(test)]
        crate::tests::branches::note(crate::tests::branches::Branch::$b);
    };
}

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

/// A point in Jacobian coordinates (`secp256k1_gej`, group.h:28-33):
/// (x, y) = (X/Z^2, Y/Z^3).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Gej {
    /// X (magnitude <= 4).
    pub(crate) x: Fe,
    /// Y (magnitude <= 4).
    pub(crate) y: Fe,
    /// Z (magnitude <= 1).
    pub(crate) z: Fe,
    /// Whether this is the point at infinity (X, Y, Z then meaningless).
    pub(crate) infinity: bool,
}

/// A normalized affine point in storage form (`secp256k1_ge_storage`,
/// group.h:38-41): x and y as little-endian 64-bit limbs.  The generated
/// tables are arrays of these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GeStorage {
    /// x, normalized, little-endian 64-bit limbs.
    pub(crate) x: [u64; 4],
    /// y, normalized, little-endian 64-bit limbs.
    pub(crate) y: [u64; 4],
}

impl Ge {
    /// The point at infinity (`ge_set_infinity`, group_impl.h:331-337).
    pub(crate) const INFINITY: Self = Self {
        x: Fe::ZERO,
        y: Fe::ZERO,
        infinity: true,
    };

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

    /// `ge_set_gej_zinv` (group_impl.h:99-114): the affine point of the
    /// Jacobian (a.x, a.y, 1/zi).  a must not be infinity.
    #[inline(always)]
    #[must_use]
    pub(crate) fn set_gej_zinv(a: &Gej, zi: &Fe) -> Self {
        a.verify();
        zi.verify();
        debug_assert!(!a.infinity);

        let zi2 = zi.sqr();
        let zi3 = zi2.mul(zi);
        let r = Self {
            x: a.x.mul(&zi2),
            y: a.y.mul(&zi3),
            infinity: a.infinity,
        };
        r.verify();
        r
    }

    /// `ge_set_ge_zinv` (group_impl.h:116-130): (self.x, self.y) taken as a
    /// Jacobian point with Z = 1/zi, made affine.  self must not be
    /// infinity.
    #[inline(always)]
    #[must_use]
    pub(crate) fn set_ge_zinv(&self, zi: &Fe) -> Self {
        let a = self;
        a.verify();
        zi.verify();
        debug_assert!(!a.infinity);

        let zi2 = zi.sqr();
        let zi3 = zi2.mul(zi);
        let r = Self {
            x: a.x.mul(&zi2),
            y: a.y.mul(&zi3),
            infinity: a.infinity,
        };
        r.verify();
        r
    }

    /// `ge_neg` (group_impl.h:149-157).  Tests only.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn neg(&self) -> Self {
        self.verify();
        let mut r = *self;
        r.y.normalize_weak();
        r.y = r.y.negate(1);
        r.verify();
        r
    }

    /// `ge_set_gej_var` (group_impl.h:177-196), plus `normalize_var` on x
    /// and y: infinity, or both coordinates normalized.  One field
    /// inversion; `None` only past its iteration cap.
    #[must_use]
    pub(crate) fn set_gej_var(a: &Gej) -> Option<Self> {
        a.verify();

        if a.is_infinity() {
            return Some(Self::INFINITY);
        }
        let z = a.z.inv_var()?;
        let z2 = z.sqr();
        let z3 = z.mul(&z2);
        let mut x = a.x.mul(&z2);
        let mut y = a.y.mul(&z3);
        // Normalized here, as dcrd's ToAffine does.
        x.normalize_var();
        y.normalize_var();
        let r = Self::set_xy(&x, &y);
        r.verify();
        Some(r)
    }

    /// `ge_set_all_gej_var` (group_impl.h:236-287): the batch conversion,
    /// one field inversion for all (Montgomery's trick).  Infinity gives
    /// infinity; the outputs keep libsecp256k1's magnitude 1, not
    /// normalized ([`Ge::to_storage`] normalizes).  `None` only past the
    /// inversion's cap.  The table generator only.
    ///
    /// # Panics
    ///
    /// If `r` and `a` differ in length.
    #[cfg(test)]
    #[allow(clippy::arithmetic_side_effects, reason = "i -= 1 only while i > 0")]
    pub(crate) fn set_all_gej_var(r: &mut [Self], a: &[Gej]) -> Option<()> {
        assert_eq!(r.len(), a.len());
        for p in a {
            p.verify();
        }

        let len = a.len();
        let mut last_i = usize::MAX;
        for i in 0..len {
            if a[i].infinity {
                r[i] = Self::INFINITY;
            } else {
                // Use destination's x coordinates as scratch space
                if last_i == usize::MAX {
                    r[i].x = a[i].z;
                } else {
                    r[i].x = r[last_i].x.mul(&a[i].z);
                }
                last_i = i;
            }
        }
        if last_i == usize::MAX {
            return Some(());
        }
        let mut u = r[last_i].x.inv_var()?;

        let mut i = last_i;
        while i > 0 {
            i -= 1;
            if !a[i].infinity {
                r[last_i].x = r[i].x.mul(&u);
                u = u.mul(&a[last_i].z);
                last_i = i;
            }
        }
        debug_assert!(!a[last_i].infinity);
        r[last_i].x = u;

        for i in 0..len {
            if !a[i].infinity {
                r[i] = Self::set_gej_zinv(&a[i], &r[i].x);
            }
        }

        for p in r.iter() {
            p.verify();
        }
        Some(())
    }

    /// `ge_table_set_globalz` (group_impl.h:289-320): brings the table
    /// `a`, whose implied Z coordinates are linked by the ratios `zr` (the
    /// output of `ecmult_odd_multiples_table`), to the Z of its last entry.
    /// The last entry's y is weak-normalized first, so every output y has
    /// magnitude 1 and a lookup can negate it with m = 1; debug builds
    /// check that of every entry.
    #[inline]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "len - 1 only when len > 0; i -= 1 only while i > 0"
    )]
    pub(crate) fn table_set_globalz(a: &mut [Self], zr: &[Fe]) {
        debug_assert_eq!(a.len(), zr.len());
        for (p, z) in a.iter().zip(zr) {
            p.verify();
            z.verify();
        }

        let len = a.len();
        if len > 0 {
            let mut i = len - 1;
            // Ensure all y values are in weak normal form for fast negation of points
            a[i].y.normalize_weak();
            let mut zs = zr[i];

            // Work our way backwards, using the z-ratios to scale the x/y values.
            while i > 0 {
                if i != len - 1 {
                    zs = zs.mul(&zr[i]);
                }
                i -= 1;
                a[i] = a[i].set_ge_zinv(&zs);
            }
        }

        for p in a.iter() {
            p.verify();
            p.y.verify_magnitude(1);
        }
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

    /// `ge_mul_lambda` (group_impl.h:917-924): lambda * a = (beta * x, y).
    /// Tests only: the Straus loop builds lambda*A's entries from x * beta
    /// directly.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn mul_lambda(&self) -> Self {
        self.verify();
        let mut r = *self;
        r.x = r.x.mul(&BETA);
        r.verify();
        r
    }

    /// `ge_to_storage` (group_impl.h:877-888); self must not be infinity.
    /// The table generator and tests only.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn to_storage(self) -> GeStorage {
        self.verify();
        debug_assert!(!self.infinity);
        let mut x = self.x;
        x.normalize();
        let mut y = self.y;
        y.normalize();
        GeStorage {
            x: x.to_storage().n,
            y: y.to_storage().n,
        }
    }

    /// `ge_from_storage` (group_impl.h:890-896): a table entry, both
    /// coordinates normalized.
    #[inline(always)]
    #[must_use]
    pub(crate) fn from_storage(a: &GeStorage) -> Self {
        let r = Self {
            x: Fe::from_storage(&FeStorage { n: a.x }),
            y: Fe::from_storage(&FeStorage { n: a.y }),
            infinity: false,
        };
        r.verify();
        r
    }
}

impl Gej {
    /// The point at infinity (`gej_set_infinity`, group_impl.h:322-329).
    pub(crate) const INFINITY: Self = Self {
        x: Fe::ZERO,
        y: Fe::ZERO,
        z: Fe::ZERO,
        infinity: true,
    };

    /// `gej_verify` (group_impl.h:87-96).  No-op in builds without debug
    /// assertions.
    #[inline(always)]
    pub(crate) fn verify(&self) {
        self.x.verify();
        self.y.verify();
        self.z.verify();
        self.x.verify_magnitude(GEJ_X_MAGNITUDE_MAX);
        self.y.verify_magnitude(GEJ_Y_MAGNITUDE_MAX);
        self.z.verify_magnitude(GEJ_Z_MAGNITUDE_MAX);
    }

    /// `gej_set_ge` (group_impl.h:367-376).
    #[inline(always)]
    #[must_use]
    pub(crate) fn set_ge(a: &Ge) -> Self {
        a.verify();
        let r = Self {
            x: a.x,
            y: a.y,
            z: Fe::ONE,
            infinity: a.infinity,
        };
        r.verify();
        r
    }

    /// `gej_is_infinity` (group_impl.h:440-444): the flag.
    #[inline(always)]
    #[must_use]
    pub(crate) fn is_infinity(&self) -> bool {
        self.verify();
        self.infinity
    }

    /// `gej_neg` (group_impl.h:427-438).  Tests only.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn neg(&self) -> Self {
        self.verify();
        let mut r = *self;
        r.y.normalize_weak();
        r.y = r.y.negate(1);
        r.verify();
        r
    }

    /// `gej_eq_x_var` (group_impl.h:417-425): whether x * Z^2 == X, that
    /// is, whether this point's affine x is `x`, with no inversion.  self
    /// must not be infinity.  `fe_equal`, as libsecp256k1 has it.
    #[inline]
    #[must_use]
    pub(crate) fn eq_x_var(&self, x: &Fe) -> bool {
        x.verify();
        self.verify();
        debug_assert!(!self.infinity);

        let r = self.z.sqr().mul(x);
        r.equal(&self.x)
    }

    /// `gej_double` (group_impl.h:460-493): 3M + 4S.  The infinity flag is
    /// copied; on secp256k1 no other case exists (the module doc).
    #[inline(always)]
    #[must_use]
    pub(crate) fn double(&self) -> Self {
        // Operations: 3 mul, 4 sqr, 8 add/half/mul_int/negate
        let a = self;
        a.verify();

        // Formula used:
        // L = (3/2) * X1^2
        // S = Y1^2
        // T = -X1*S
        // X3 = L^2 + 2*T
        // Y3 = -(L*(X3 + T) + S^2)
        // Z3 = Y1*Z1

        let rz = a.z.mul(&a.y); // Z3 = Y1*Z1 (1)
        let mut s = a.y.sqr(); // S = Y1^2 (1)
        let mut l = a.x.sqr(); // L = X1^2 (1)
        l.mul_int(3); // L = 3*X1^2 (3)
        l.half(); // L = 3/2*X1^2 (2)
        let mut t = s.negate(1); // T = -S (2)
        t = t.mul(&a.x); // T = -X1*S (1)
        let mut rx = l.sqr(); // X3 = L^2 (1)
        rx.add_assign(&t); // X3 = L^2 + T (2)
        rx.add_assign(&t); // X3 = L^2 + 2*T (3)
        s = s.sqr(); // S' = S^2 (1)
        t.add_assign(&rx); // T' = X3 + T (4)
        let mut ry = t.mul(&l); // Y3 = L*(X3 + T) (1)
        ry.add_assign(&s); // Y3 = L*(X3 + T) + S^2 (2)
        let ry = ry.negate(2); // Y3 = -(L*(X3 + T) + S^2) (3)

        let r = Self {
            x: rx,
            y: ry,
            z: rz,
            infinity: a.infinity,
        };
        r.verify();
        r
    }

    /// `gej_double_var` (group_impl.h:495-524): infinity doubles to
    /// infinity (rzr = 1); otherwise [`Gej::double`] with rzr = Y1, weakly
    /// normalized, the ratio of the output's Z to the input's.
    #[inline(always)]
    #[must_use]
    pub(crate) fn double_var(&self, rzr: Option<&mut Fe>) -> Self {
        let a = self;
        a.verify();

        // For secp256k1, 2Q is infinity if and only if Q is infinity. This is because if 2Q = infinity,
        // Q must equal -Q, or that Q.y == -(Q.y), or Q.y is 0. For a point on y^2 = x^3 + 7 to have
        // y=0, x^3 must be -7 mod p. However, -7 has no cube root mod p.
        //
        // Having said this, if this function receives a point on a sextic twist, e.g. by
        // a fault attack, it is possible for y to be 0. This happens for y^2 = x^3 + 6,
        // since -6 does have a cube root mod p. For this point, this function will not set
        // the infinity flag even though the point doubles to infinity, and the result
        // point will be gibberish (z = 0 but infinity = 0).
        if a.infinity {
            if let Some(z) = rzr {
                *z = Fe::ONE;
            }
            note!(AccInfinity);
            return Self::INFINITY;
        }

        if let Some(z) = rzr {
            *z = a.y;
            z.normalize_weak();
        }

        let r = a.double();
        note!(Generic);
        r.verify();
        r
    }

    /// `gej_add_var` (group_impl.h:526-588): Jacobian + Jacobian, 12M + 4S.
    /// rzr, when given, receives the ratio of the output's Z to self's Z,
    /// and must be `None` when self is infinity.  The table generator and
    /// tests only.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn add_var(&self, b: &Self, rzr: Option<&mut Fe>) -> Self {
        // 12 mul, 4 sqr, 11 add/negate/normalizes_to_zero (ignoring special cases)
        let a = self;
        a.verify();
        b.verify();

        if a.infinity {
            debug_assert!(rzr.is_none());
            note!(AccInfinity);
            return *b;
        }
        if b.infinity {
            if let Some(z) = rzr {
                *z = Fe::ONE;
            }
            note!(AddendInfinity);
            return *a;
        }

        let z22 = b.z.sqr();
        let z12 = a.z.sqr();
        let u1 = a.x.mul(&z22);
        let u2 = b.x.mul(&z12);
        let s1 = a.y.mul(&z22).mul(&b.z);
        let s2 = b.y.mul(&z12).mul(&a.z);
        let h = u1.negate(1).add(&u2);
        let i = s2.negate(1).add(&s1);
        if h.normalizes_to_zero_var() {
            if i.normalizes_to_zero_var() {
                let r = a.double_var(rzr);
                note!(Doubling);
                return r;
            }
            if let Some(z) = rzr {
                *z = Fe::ZERO;
            }
            note!(Opposite);
            return Self::INFINITY;
        }

        let mut t = h.mul(&b.z);
        if let Some(z) = rzr {
            *z = t;
        }
        let rz = a.z.mul(&t);

        let h2 = h.sqr().negate(1);
        let mut h3 = h2.mul(&h);
        t = u1.mul(&h2);

        let mut rx = i.sqr();
        rx.add_assign(&h3);
        rx.add_assign(&t);
        rx.add_assign(&t);

        t.add_assign(&rx);
        let mut ry = t.mul(&i);
        h3 = h3.mul(&s1);
        ry.add_assign(&h3);

        let r = Self {
            x: rx,
            y: ry,
            z: rz,
            infinity: false,
        };
        note!(Generic);
        r.verify();
        r
    }

    /// `gej_add_ge_var` (group_impl.h:590-651): Jacobian + affine, 8M + 3S.
    /// The Straus loop's additions of A and lambda*A entries, and the key
    /// table's build.  rzr as in `add_var`: `None` when self is infinity.
    #[inline(always)]
    #[must_use]
    pub(crate) fn add_ge_var(&self, b: &Ge, rzr: Option<&mut Fe>) -> Self {
        // Operations: 8 mul, 3 sqr, 11 add/negate/normalizes_to_zero (ignoring special cases)
        let a = self;
        a.verify();
        b.verify();

        if a.infinity {
            debug_assert!(rzr.is_none());
            note!(AccInfinity);
            return Self::set_ge(b);
        }
        if b.infinity {
            if let Some(z) = rzr {
                *z = Fe::ONE;
            }
            note!(AddendInfinity);
            return *a;
        }

        let z12 = a.z.sqr();
        let u1 = a.x;
        let u2 = b.x.mul(&z12);
        let s1 = a.y;
        let s2 = b.y.mul(&z12).mul(&a.z);
        let h = u1.negate(GEJ_X_MAGNITUDE_MAX).add(&u2);
        let i = s2.negate(1).add(&s1);
        if h.normalizes_to_zero_var() {
            if i.normalizes_to_zero_var() {
                let r = a.double_var(rzr);
                note!(Doubling);
                return r;
            }
            if let Some(z) = rzr {
                *z = Fe::ZERO;
            }
            note!(Opposite);
            return Self::INFINITY;
        }

        if let Some(z) = rzr {
            *z = h;
        }
        let rz = a.z.mul(&h);

        let h2 = h.sqr().negate(1);
        let mut h3 = h2.mul(&h);
        let mut t = u1.mul(&h2);

        let mut rx = i.sqr();
        rx.add_assign(&h3);
        rx.add_assign(&t);
        rx.add_assign(&t);

        t.add_assign(&rx);
        let mut ry = t.mul(&i);
        h3 = h3.mul(&s1);
        ry.add_assign(&h3);

        let r = Self {
            x: rx,
            y: ry,
            z: rz,
            infinity: false,
        };
        note!(Generic);
        r.verify();
        r
    }

    /// `gej_add_zinv_var` (group_impl.h:653-721): self + (b.x, b.y,
    /// 1/bzinv), 9M + 3S.  The Straus loop's additions of G and 2^128*G
    /// entries: the entries are affine, and the accumulator lives on the
    /// isomorphic curve of the key table's global Z, so bzinv = Z.
    #[inline(always)]
    #[must_use]
    pub(crate) fn add_zinv_var(&self, b: &Ge, bzinv: &Fe) -> Self {
        // Operations: 9 mul, 3 sqr, 11 add/negate/normalizes_to_zero (ignoring special cases)
        let a = self;
        a.verify();
        b.verify();
        bzinv.verify();

        if a.infinity {
            let bzinv2 = bzinv.sqr();
            let bzinv3 = bzinv2.mul(bzinv);
            let r = Self {
                x: b.x.mul(&bzinv2),
                y: b.y.mul(&bzinv3),
                z: Fe::ONE,
                infinity: b.infinity,
            };
            note!(AccInfinity);
            r.verify();
            return r;
        }
        if b.infinity {
            note!(AddendInfinity);
            return *a;
        }

        // We need to calculate (rx,ry,rz) = (ax,ay,az) + (bx,by,1/bzinv). Due to
        // secp256k1's isomorphism we can multiply the Z coordinates on both sides
        // by bzinv, and get: (rx,ry,rz*bzinv) = (ax,ay,az*bzinv) + (bx,by,1).
        // This means that (rx,ry,rz) can be calculated as
        // (ax,ay,az*bzinv) + (bx,by,1), when not applying the bzinv factor to rz.
        // The variable az below holds the modified Z coordinate for a, which is used
        // for the computation of rx and ry, but not for rz.
        let az = a.z.mul(bzinv);

        let z12 = az.sqr();
        let u1 = a.x;
        let u2 = b.x.mul(&z12);
        let s1 = a.y;
        let s2 = b.y.mul(&z12).mul(&az);
        let h = u1.negate(GEJ_X_MAGNITUDE_MAX).add(&u2);
        let i = s2.negate(1).add(&s1);
        if h.normalizes_to_zero_var() {
            if i.normalizes_to_zero_var() {
                let r = a.double_var(None);
                note!(Doubling);
                return r;
            }
            note!(Opposite);
            return Self::INFINITY;
        }

        let rz = a.z.mul(&h);

        let h2 = h.sqr().negate(1);
        let mut h3 = h2.mul(&h);
        let mut t = u1.mul(&h2);

        let mut rx = i.sqr();
        rx.add_assign(&h3);
        rx.add_assign(&t);
        rx.add_assign(&t);

        t.add_assign(&rx);
        let mut ry = t.mul(&i);
        h3 = h3.mul(&s1);
        ry.add_assign(&h3);

        let r = Self {
            x: rx,
            y: ry,
            z: rz,
            infinity: false,
        };
        note!(Generic);
        r.verify();
        r
    }
}

/// The secp256k1 generator G (`SECP256K1_G`, group_impl.h:38-43; SEC2
/// 2.7.1), normalized.  Tests and the table generator only.
#[cfg(test)]
pub(crate) const G: Ge = Ge {
    x: Fe::from_be_u32([
        0x79be_667e,
        0xf9dc_bbac,
        0x55a0_6295,
        0xce87_0b07,
        0x029b_fcdb,
        0x2dce_28d9,
        0x59f2_815b,
        0x16f8_1798,
    ]),
    y: Fe::from_be_u32([
        0x483a_da77,
        0x26a3_c465,
        0x5da4_fbfc,
        0x0e11_08a8,
        0xfd17_b448,
        0xa685_5419,
        0x9c47_d08f,
        0xfb10_d4b8,
    ]),
    infinity: false,
};
