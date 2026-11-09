// SPDX-License-Identifier: ISC AND MIT
//
// Derived from libsecp256k1 src/field_impl.h, src/field.h and
// src/field_5x52_impl.h (all Copyright (c) 2013, 2014 Pieter Wuille), as
// vendored by secp256k1-sys 0.14.1.  MIT; see NOTICE.
//
//! [`Fe`]: a [`FeRaw`] plus libsecp256k1's VERIFY-mode bookkeeping
//! (field_impl.h:148-168), which exists only under `cfg(debug_assertions)`,
//! and the field operations built from the raw ones (field_impl.h).
//!
//! Every operation asserts its precondition (magnitude, normalized), sets
//! its postcondition, and runs [`Fe::verify`], a port of `fe_verify` and
//! `fe_impl_verify` (field_impl.h:153-162, field_5x52_impl.h:18-32) that
//! checks the **limbs** against the claimed magnitude, so a wrong hand
//! bound shows on whatever inputs the tests reach.
//!
//! Debug-only code reads values and asserts; it never writes a value, so
//! the arithmetic in every profile is the arithmetic that ships.  There is
//! no derived equality or hashing; [`Fe::equal`] compares values.

use super::{FeRaw, FeStorage};

/// A field element with debug-build magnitude tracking.
#[derive(Clone, Copy, Debug)]
pub struct Fe {
    /// The value.
    raw: FeRaw,
    /// Claimed magnitude, 0..=32 (debug builds only).
    #[cfg(debug_assertions)]
    magnitude: u8,
    /// Claimed normalized (debug builds only).
    #[cfg(debug_assertions)]
    normalized: bool,
}

impl Fe {
    /// 0 (normalized, magnitude 0).
    pub const ZERO: Self = Self::from_raw_const(FeRaw::from_int(0), 0, true);
    /// 1 (normalized, magnitude 1).
    pub const ONE: Self = Self::from_raw_const(FeRaw::from_int(1), 1, true);

    /// A value with its claimed magnitude and normalization, which debug
    /// builds check at first use, by any operation's `verify`.
    /// Crate-internal: a public version would let a caller claim
    /// "normalized" for arbitrary limbs.
    #[inline(always)]
    #[must_use]
    pub(crate) const fn from_raw_const(raw: FeRaw, magnitude: u8, normalized: bool) -> Self {
        #[cfg(not(debug_assertions))]
        let _ = (magnitude, normalized);
        Self {
            raw,
            #[cfg(debug_assertions)]
            magnitude,
            #[cfg(debug_assertions)]
            normalized,
        }
    }

    /// `SECP256K1_FE_CONST` (field.h:50-66): eight big-endian 32-bit words,
    /// normalized, magnitude 1.  The words must encode a value below p,
    /// which is why this is crate-internal.
    #[must_use]
    pub(crate) const fn from_be_u32(d: [u32; 8]) -> Self {
        Self::from_raw_const(FeRaw::from_be_u32(d), 1, true)
    }

    /// The bare limbs.
    #[inline(always)]
    #[must_use]
    pub const fn raw(&self) -> &FeRaw {
        &self.raw
    }

    /// A test-only constructor at a stated magnitude; `verify` checks the
    /// limbs against it.
    #[cfg(test)]
    pub(crate) fn from_limbs(n: [u64; 5], magnitude: u8, normalized: bool) -> Self {
        let r = Self::from_raw_const(FeRaw { n }, magnitude, normalized);
        r.verify();
        r
    }

    /// The claimed magnitude (debug test builds).
    #[cfg(all(debug_assertions, test))]
    #[must_use]
    pub(crate) fn magnitude(&self) -> u8 {
        self.magnitude
    }

    /// Whether the value is claimed normalized (debug builds).
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn is_normalized_claim(&self) -> bool {
        self.normalized
    }

    /// `fe_verify` + `fe_impl_verify` (field_impl.h:153-162,
    /// field_5x52_impl.h:18-32).  No-op in builds without debug assertions.
    #[inline(always)]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "bookkeeping: the magnitude is asserted <= 32 first, so 2m <= \
                  64 and 2m times a limb bound stays below 2^59"
    )]
    pub fn verify(&self) {
        #[cfg(debug_assertions)]
        {
            // Magnitude between 0 and 32.
            assert!(self.magnitude <= 32, "magnitude {} > 32", self.magnitude);
            // If normalized, magnitude must be 0 or 1.
            if self.normalized {
                assert!(
                    self.magnitude <= 1,
                    "normalized with magnitude {}",
                    self.magnitude
                );
            }
            // Implementation-specific checks: limbs within the magnitude.
            let d = &self.raw.n;
            let m: u64 = if self.normalized {
                1
            } else {
                2 * u64::from(self.magnitude)
            };
            let lim = 0xF_FFFF_FFFF_FFFF_u64 * m;
            let lim4 = 0xFFFF_FFFF_FFFF_u64 * m;
            assert!(
                d[0] <= lim && d[1] <= lim && d[2] <= lim && d[3] <= lim && d[4] <= lim4,
                "fe_verify: limbs {d:x?} exceed magnitude {} (normalized {})",
                self.magnitude,
                self.normalized
            );
            if self.normalized
                && d[4] == 0xFFFF_FFFF_FFFF
                && (d[3] & d[2] & d[1]) == 0xF_FFFF_FFFF_FFFF
            {
                assert!(
                    d[0] < 0xF_FFFE_FFFF_FC2F,
                    "fe_verify: normalized value >= p"
                );
            }
        }
    }

    /// `fe_verify_magnitude` (field_impl.h:164-168).
    #[inline(always)]
    pub fn verify_magnitude(&self, m: u8) {
        #[cfg(debug_assertions)]
        {
            assert!(m <= 32);
            assert!(self.magnitude <= m, "magnitude {} > {}", self.magnitude, m);
        }
        #[cfg(not(debug_assertions))]
        let _ = m;
    }

    /// Asserts the value is claimed normalized (debug builds).
    #[inline(always)]
    fn verify_normalized(&self) {
        #[cfg(debug_assertions)]
        assert!(
            self.normalized,
            "operation requires a normalized field element"
        );
    }

    /// `fe_normalize` (field_impl.h:171-179): magnitude 1, normalized, by
    /// the constant-time shape.  Tests and the table generator only.
    #[cfg(test)]
    pub fn normalize(&mut self) {
        self.verify();
        self.raw.normalize();
        #[cfg(debug_assertions)]
        {
            self.magnitude = 1;
            self.normalized = true;
        }
        self.verify();
    }

    /// `fe_normalize_weak` (field_impl.h:182-189): magnitude 1.
    #[inline]
    pub fn normalize_weak(&mut self) {
        self.verify();
        self.raw.normalize_weak();
        #[cfg(debug_assertions)]
        {
            self.magnitude = 1;
        }
        self.verify();
    }

    /// `fe_normalize_var` (field_impl.h:192-200): magnitude 1, normalized.
    #[inline]
    pub fn normalize_var(&mut self) {
        self.verify();
        self.raw.normalize_var();
        #[cfg(debug_assertions)]
        {
            self.magnitude = 1;
            self.normalized = true;
        }
        self.verify();
    }

    /// `fe_normalizes_to_zero` (field_impl.h:203-207).
    #[inline]
    #[must_use]
    pub fn normalizes_to_zero(&self) -> bool {
        self.verify();
        self.raw.normalizes_to_zero()
    }

    /// `fe_normalizes_to_zero_var` (field_impl.h:210-214): whether the
    /// value is 0 mod p, returning early on most nonzero values.
    #[inline]
    #[must_use]
    pub fn normalizes_to_zero_var(&self) -> bool {
        self.verify();
        self.raw.normalizes_to_zero_var()
    }

    /// `fe_add_int` (field_impl.h:228-237): 0 <= a <= 0x7FFF; the magnitude
    /// grows by one.
    #[inline]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "bookkeeping: the magnitude after the addition is asserted \
                  <= 32 by the verify that follows"
    )]
    pub fn add_int(&mut self, a: u16) {
        debug_assert!(a <= 0x7FFF);
        self.verify();
        self.raw.add_int(a);
        #[cfg(debug_assertions)]
        {
            self.magnitude += 1;
            self.normalized = false;
        }
        self.verify();
    }

    /// `fe_is_odd` (field_impl.h:248-253); requires normalized.
    #[inline]
    #[must_use]
    pub fn is_odd(&self) -> bool {
        self.verify();
        self.verify_normalized();
        self.raw.is_odd()
    }

    /// `fe_set_b32_limit` (field_impl.h:275-286): `None` for a value >= p;
    /// otherwise normalized, magnitude 1.
    #[inline]
    #[must_use]
    pub fn set_b32_limit(a: &[u8; 32]) -> Option<Self> {
        let (raw, ok) = FeRaw::set_b32_limit(a);
        if ok {
            let r = Self::from_raw_const(raw, 1, true);
            r.verify();
            Some(r)
        } else {
            None
        }
    }

    /// `fe_get_b32` (field_impl.h:289-294); requires normalized.
    #[inline]
    #[must_use]
    pub fn get_b32(&self) -> [u8; 32] {
        self.verify();
        self.verify_normalized();
        self.raw.get_b32()
    }

    /// `fe_negate` (field.h:211, field_impl.h:297-307): 0 <= m <= 31,
    /// magnitude(a) <= m; output magnitude m + 1.
    #[inline(always)]
    #[must_use]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "bookkeeping: m <= 31 is asserted, so m + 1 <= 32"
    )]
    pub fn negate(&self, m: u8) -> Self {
        self.verify();
        debug_assert!(m <= 31);
        self.verify_magnitude(m);
        let r = Self::from_raw_const(self.raw.negate_unchecked(u32::from(m)), m + 1, false);
        r.verify();
        r
    }

    /// `fe_add` (field_impl.h:323-333): magnitudes add, sum <= 32.
    #[inline(always)]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "bookkeeping: the sum of two magnitudes <= 32 is formed only \
                  after it is asserted <= 32"
    )]
    pub fn add_assign(&mut self, a: &Self) {
        self.verify();
        a.verify();
        #[cfg(debug_assertions)]
        assert!(
            self.magnitude + a.magnitude <= 32,
            "fe_add magnitude {} + {}",
            self.magnitude,
            a.magnitude
        );
        self.raw.add_assign(&a.raw);
        #[cfg(debug_assertions)]
        {
            self.magnitude += a.magnitude;
            self.normalized = false;
        }
        self.verify();
    }

    /// `fe_mul` (field_impl.h:336-349): both magnitudes <= 8; output
    /// magnitude 1, not normalized.
    #[inline(always)]
    #[must_use]
    pub fn mul(&self, b: &Self) -> Self {
        self.verify();
        b.verify();
        self.verify_magnitude(8);
        b.verify_magnitude(8);
        let r = Self::from_raw_const(self.raw.mul(&b.raw), 1, false);
        r.verify();
        r
    }

    /// `fe_sqr` (field_impl.h:352-361): magnitude <= 8; output magnitude 1.
    #[inline(always)]
    #[must_use]
    pub fn sqr(&self) -> Self {
        self.verify();
        self.verify_magnitude(8);
        let r = Self::from_raw_const(self.raw.sqr(), 1, false);
        r.verify();
        r
    }

    /// `fe_mul_int` (field.h:233, field_impl.h:310-320): a times the
    /// magnitude must be at most 32; the magnitude is multiplied by a.
    #[inline(always)]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "bookkeeping: a times the magnitude is asserted <= 32 before \
                  it is formed"
    )]
    pub fn mul_int(&mut self, a: u8) {
        self.verify();
        #[cfg(debug_assertions)]
        assert!(
            u32::from(a) * u32::from(self.magnitude) <= 32,
            "fe_mul_int: {a} times magnitude {}",
            self.magnitude
        );
        self.raw.mul_int_unchecked(u32::from(a));
        #[cfg(debug_assertions)]
        {
            self.magnitude *= a;
            self.normalized = false;
        }
        self.verify();
    }

    /// `self + a`, as [`Fe::add_assign`].
    #[inline(always)]
    #[must_use]
    pub fn add(&self, a: &Self) -> Self {
        let mut r = *self;
        r.add_assign(a);
        r
    }

    /// `fe_half` (field_impl.h:444-453): a/2; magnitude m <= 31 becomes
    /// floor(m/2) + 1.
    #[inline(always)]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "bookkeeping: m <= 31 is asserted, so (m >> 1) + 1 <= 16"
    )]
    pub fn half(&mut self) {
        self.verify();
        self.verify_magnitude(31);
        self.raw.half();
        #[cfg(debug_assertions)]
        {
            self.magnitude = (self.magnitude >> 1) + 1;
            self.normalized = false;
        }
        self.verify();
    }

    /// `fe_to_storage` (field_impl.h:377-382); requires normalized.  Tests
    /// and the table generator only.
    #[cfg(test)]
    #[inline]
    #[must_use]
    pub fn to_storage(self) -> FeStorage {
        self.verify();
        self.verify_normalized();
        self.raw.to_storage()
    }

    /// `fe_from_storage` (field_impl.h:385-391): normalized, magnitude 1.
    #[inline(always)]
    #[must_use]
    pub fn from_storage(a: &FeStorage) -> Self {
        let r = Self::from_raw_const(FeRaw::from_storage(a), 1, true);
        r.verify();
        r
    }

    /// `fe_inv_var` (field_impl.h:407-417, field_5x52_impl.h:463-471):
    /// 1/self, and 0 for 0; normalized, magnitude 1 (0 for a zero-magnitude
    /// input).  `None` only past modinv64's iteration cap, which the
    /// safegcd bound rules out (test builds can force it, so that the
    /// callers' fallbacks are tested).
    #[inline]
    #[must_use]
    pub fn inv_var(&self) -> Option<Self> {
        #[cfg(debug_assertions)]
        let input_is_zero = self.normalizes_to_zero();
        self.verify();
        #[cfg(test)]
        if crate::tests::branches::cap_forced() {
            return None;
        }
        let mut tmp = self.raw;
        tmp.normalize_var();
        let s = crate::modinv64::modinv64_var(&tmp.to_signed62(), &super::MODINFO_FE)?;
        #[cfg(debug_assertions)]
        let m = u8::from(self.magnitude > 0);
        #[cfg(not(debug_assertions))]
        let m = 1;
        let r = Self::from_raw_const(FeRaw::from_signed62(&s), m, true);
        #[cfg(debug_assertions)]
        assert_eq!(r.normalizes_to_zero(), input_is_zero);
        r.verify();
        Some(r)
    }

    /// `fe_equal` (field_impl.h:25-35): magnitude(self) <= 1,
    /// magnitude(b) <= 30.
    #[inline]
    #[must_use]
    pub fn equal(&self, b: &Self) -> bool {
        self.verify();
        b.verify();
        self.verify_magnitude(1);
        b.verify_magnitude(30);
        let mut na = self.negate(1);
        na.add_assign(b);
        na.normalizes_to_zero()
    }

    /// `fe_sqrt` (field_impl.h:37-146): a^((p+1)/4) by libsecp256k1's
    /// addition chain (blocks of 1s of lengths 2, 22, 223; :54-131), then
    /// the check r^2 == a (:135-136).  Input magnitude <= 8.  Returns
    /// (r, true) with r a square root of a (magnitude 1, not normalized) if
    /// a is a square; otherwise (r, false) with r a square root of -a
    /// (field.h:269-278).
    #[must_use]
    pub fn sqrt(&self) -> (Self, bool) {
        let a = self;
        a.verify();
        a.verify_magnitude(8);

        // The binary representation of (p + 1)/4 has 3 blocks of 1s, with lengths in
        // { 2, 22, 223 }. Use an addition chain to calculate 2^n - 1 for each block:
        // 1, [2], 3, 6, 9, 11, [22], 44, 88, 176, 220, [223]

        let sqr_n = |x: &Self, n: usize| {
            let mut t = *x;
            for _ in 0..n {
                t = t.sqr();
            }
            t
        };

        let x2 = a.sqr().mul(a);
        let x3 = x2.sqr().mul(a);
        let x6 = sqr_n(&x3, 3).mul(&x3);
        let x9 = sqr_n(&x6, 3).mul(&x3);
        let x11 = sqr_n(&x9, 2).mul(&x2);
        let x22 = sqr_n(&x11, 11).mul(&x11);
        let x44 = sqr_n(&x22, 22).mul(&x22);
        let x88 = sqr_n(&x44, 44).mul(&x44);
        let x176 = sqr_n(&x88, 88).mul(&x88);
        let x220 = sqr_n(&x176, 44).mul(&x44);
        let x223 = sqr_n(&x220, 3).mul(&x3);

        // The final result is then assembled using a sliding window over the blocks.
        let mut t1 = sqr_n(&x223, 23).mul(&x22);
        t1 = sqr_n(&t1, 6).mul(&x2);
        t1 = t1.sqr();
        let r = t1.sqr();

        // Check that a square root was actually calculated
        let t1 = r.sqr();
        let ret = t1.equal(a);

        #[cfg(debug_assertions)]
        if !ret {
            let mut t = t1.negate(1);
            t.normalize_var();
            assert!(t.equal(a), "fe_sqrt: r^2 is neither a nor -a");
        }
        (r, ret)
    }
}
