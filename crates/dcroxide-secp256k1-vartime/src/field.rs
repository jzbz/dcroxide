// SPDX-License-Identifier: ISC AND MIT
//
// Derived from libsecp256k1 src/field_5x52_impl.h, src/field_5x52.h and
// src/field.h (all Copyright (c) 2013, 2014 Pieter Wuille), as vendored by
// secp256k1-sys 0.14.1.  MIT; see NOTICE.
//
//! The secp256k1 base field in libsecp256k1's 5x52 representation.
//!
//! [`FeRaw`] is the bare value: five u64 limbs in base 2^52, value mod
//! p = 2^256 - 0x1000003D1, the `secp256k1_fe_impl_*` functions of
//! field_5x52_impl.h.  [`Fe`] (in `verify.rs`) wraps it with libsecp256k1's
//! VERIFY-mode bookkeeping (field_impl.h:148-168), kept under
//! `cfg(debug_assertions)` only.  Everything here is variable time and
//! meant for public data.
//!
//! Magnitude m bounds the limbs: n\[0..3\] <= 2m(2^52-1), n\[4\] <=
//! 2m(2^48-1); normalized means canonical limbs and value < p
//! (field_5x52.h:23-31).
//!
//! What the crate uses is here: bytes in and out, addition, small
//! additions and multiples, negation, halving, multiplication, squaring,
//! the weak and variable-time normalizations, both zero tests, the square
//! root and the 4x64 storage form the generator tables use.  The inverse,
//! the constant-time normalization and the conversion to storage form are
//! compiled for the tests and the table generator only, until the affine
//! conversion of recovery and Schnorr verification calls them.
//!
//! `FeRaw` keeps the C's signatures (a flag beside the value, `u32`
//! magnitudes, `as` widenings in the kernel) so that it reads beside
//! libsecp256k1; `Fe` gives the Rust ones (`Option`, `u8` magnitudes).

mod mul;
mod verify;

pub use verify::Fe;

/// 2^52 - 1.
const M52: u64 = 0xF_FFFF_FFFF_FFFF;
/// 2^48 - 1.
const M48: u64 = 0xFFFF_FFFF_FFFF;
/// 2^256 mod p.
const C: u64 = 0x1_0000_03D1;
/// p's low limb.
const P0: u64 = 0xF_FFFE_FFFF_FC2F;

/// A field element in 5x52 form with no bookkeeping (`secp256k1_fe` without
/// its VERIFY fields, field_5x52.h:14-32).
#[derive(Clone, Copy, Debug)]
pub struct FeRaw {
    /// Limbs, little-endian, base 2^52.
    pub n: [u64; 5],
}

/// A normalized field element in 4x64 storage form
/// (`secp256k1_fe_storage`, field_5x52.h:45-47), little-endian limbs: the
/// form of the generator tables' coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeStorage {
    /// Limbs, little-endian, base 2^64.
    pub n: [u64; 4],
}

impl FeRaw {
    /// `SECP256K1_FE_CONST_INNER` (field_5x52.h:37-43): eight big-endian
    /// 32-bit words d7..d0, as five 52-bit limbs.
    #[must_use]
    pub const fn from_be_u32(d: [u32; 8]) -> Self {
        let (d7, d6, d5, d4, d3, d2, d1, d0) = (
            d[0] as u64,
            d[1] as u64,
            d[2] as u64,
            d[3] as u64,
            d[4] as u64,
            d[5] as u64,
            d[6] as u64,
            d[7] as u64,
        );
        Self {
            n: [
                d0 | ((d1 & 0xF_FFFF) << 32),
                (d1 >> 20) | (d2 << 12) | ((d3 & 0xFF) << 44),
                (d3 >> 8) | ((d4 & 0xFFF_FFFF) << 24),
                (d4 >> 28) | (d5 << 4) | ((d6 & 0xFFFF) << 36),
                (d6 >> 16) | (d7 << 16),
            ],
        }
    }

    /// `fe_impl_set_int` (field_5x52_impl.h:201-204).
    #[inline]
    #[must_use]
    pub const fn from_int(a: u16) -> Self {
        Self {
            n: [a as u64, 0, 0, 0, 0],
        }
    }

    /// `fe_impl_normalize` (field_5x52_impl.h:43-78), with the final
    /// reduction always applied.  Input magnitude <= 32 (t4 < 2^54, so x <
    /// 2^6 and x * C < 2^39).  Tests and the table generator only.
    #[cfg(test)]
    #[inline]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "field_5x52_impl.h:43-78: input magnitude <= 32 gives limbs \
                  < 2^58, x < 2^6 and x*C < 2^39, so no addition, product or \
                  shift leaves u64"
    )]
    pub fn normalize(&mut self) {
        let [mut t0, mut t1, mut t2, mut t3, mut t4] = self.n;

        // Reduce t4 at the start so there will be at most a single carry from the first pass
        let mut x = t4 >> 48;
        t4 &= M48;

        // The first pass ensures the magnitude is 1, ...
        t0 += x * C;
        t1 += t0 >> 52;
        t0 &= M52;
        t2 += t1 >> 52;
        t1 &= M52;
        let mut m = t1;
        t3 += t2 >> 52;
        t2 &= M52;
        m &= t2;
        t4 += t3 >> 52;
        t3 &= M52;
        m &= t3;

        // ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element)
        debug_assert!(t4 >> 49 == 0);

        // At most a single final reduction is needed; check if the value is >= the field characteristic
        x = (t4 >> 48) | u64::from((t4 == M48) & (m == M52) & (t0 >= P0));

        // Apply the final reduction (for constant-time behaviour, we do it always)
        t0 += x * C;
        t1 += t0 >> 52;
        t0 &= M52;
        t2 += t1 >> 52;
        t1 &= M52;
        t3 += t2 >> 52;
        t2 &= M52;
        t4 += t3 >> 52;
        t3 &= M52;

        // If t4 didn't carry to bit 48 already, then it should have after any final reduction
        debug_assert!(t4 >> 48 == x);

        // Mask off the possible multiple of 2^256 from the final reduction
        t4 &= M48;

        self.n = [t0, t1, t2, t3, t4];
    }

    /// `fe_impl_normalize_weak` (field_5x52_impl.h:80-97): magnitude 1,
    /// not normalized.  Input magnitude <= 32.
    #[inline]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "field_5x52_impl.h:80-97: input magnitude <= 32 gives limbs \
                  < 2^58, x < 2^6 and x*C < 2^39, so no addition, product or \
                  shift leaves u64"
    )]
    pub fn normalize_weak(&mut self) {
        let [mut t0, mut t1, mut t2, mut t3, mut t4] = self.n;

        // Reduce t4 at the start so there will be at most a single carry from the first pass
        let x = t4 >> 48;
        t4 &= M48;

        // The first pass ensures the magnitude is 1, ...
        t0 += x * C;
        t1 += t0 >> 52;
        t0 &= M52;
        t2 += t1 >> 52;
        t1 &= M52;
        t3 += t2 >> 52;
        t2 &= M52;
        t4 += t3 >> 52;
        t3 &= M52;

        // ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element)
        debug_assert!(t4 >> 49 == 0);

        self.n = [t0, t1, t2, t3, t4];
    }

    /// `fe_impl_normalize_var` (field_5x52_impl.h:99-135): canonical limbs,
    /// value below p.  Input magnitude <= 32, so t4 < 2^54, x < 2^6 and
    /// x * C < 2^39.
    #[inline]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "field_5x52_impl.h:99-135: input magnitude <= 32 gives limbs \
                  < 2^58, x < 2^6 and x*C < 2^39, so no addition, product or \
                  shift leaves u64"
    )]
    pub fn normalize_var(&mut self) {
        let [mut t0, mut t1, mut t2, mut t3, mut t4] = self.n;

        // Reduce t4 at the start so there will be at most a single carry from the first pass
        let mut x = t4 >> 48;
        t4 &= M48;

        // The first pass ensures the magnitude is 1, ...
        t0 += x * C;
        t1 += t0 >> 52;
        t0 &= M52;
        t2 += t1 >> 52;
        t1 &= M52;
        let mut m = t1;
        t3 += t2 >> 52;
        t2 &= M52;
        m &= t2;
        t4 += t3 >> 52;
        t3 &= M52;
        m &= t3;

        // ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element)
        debug_assert!(t4 >> 49 == 0);

        // At most a single final reduction is needed; check if the value is >= the field characteristic
        x = (t4 >> 48) | u64::from((t4 == M48) & (m == M52) & (t0 >= P0));

        if x != 0 {
            t0 += C;
            t1 += t0 >> 52;
            t0 &= M52;
            t2 += t1 >> 52;
            t1 &= M52;
            t3 += t2 >> 52;
            t2 &= M52;
            t4 += t3 >> 52;
            t3 &= M52;

            // If t4 didn't carry to bit 48 already, then it should have after any final reduction
            debug_assert!(t4 >> 48 == x);

            // Mask off the possible multiple of 2^256 from the final reduction
            t4 &= M48;
        }

        self.n = [t0, t1, t2, t3, t4];
    }

    /// `fe_impl_normalizes_to_zero` (field_5x52_impl.h:137-158): whether
    /// the value is 0 mod p, as a raw 0 or a raw p after one carry pass.
    #[inline]
    #[must_use]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "field_5x52_impl.h:137-158: input magnitude <= 32 gives limbs \
                  < 2^58, x < 2^6 and x*C < 2^39, so no addition, product or \
                  shift leaves u64"
    )]
    pub fn normalizes_to_zero(&self) -> bool {
        let [mut t0, mut t1, mut t2, mut t3, mut t4] = self.n;

        // Reduce t4 at the start so there will be at most a single carry from the first pass
        let x = t4 >> 48;
        t4 &= M48;

        // The first pass ensures the magnitude is 1, ...
        t0 += x * C;
        t1 += t0 >> 52;
        t0 &= M52;
        // z0 tracks a possible raw value of 0, z1 tracks a possible raw value of P
        let mut z0 = t0;
        let mut z1 = t0 ^ 0x1_0000_03D0;
        t2 += t1 >> 52;
        t1 &= M52;
        z0 |= t1;
        z1 &= t1;
        t3 += t2 >> 52;
        t2 &= M52;
        z0 |= t2;
        z1 &= t2;
        t4 += t3 >> 52;
        t3 &= M52;
        z0 |= t3;
        z1 &= t3;
        z0 |= t4;
        z1 &= t4 ^ 0xF_0000_0000_0000;

        // ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element)
        debug_assert!(t4 >> 49 == 0);

        (z0 == 0) | (z1 == M52)
    }

    /// `fe_impl_normalizes_to_zero_var` (field_5x52_impl.h:160-199): as
    /// [`FeRaw::normalizes_to_zero`], returning early when the low limb
    /// already rules out both a raw 0 and a raw p (:179-181).
    #[inline]
    #[must_use]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "field_5x52_impl.h:160-199: input magnitude <= 32 gives limbs \
                  < 2^58, x < 2^6 and x*C < 2^39, so no addition, product or \
                  shift leaves u64"
    )]
    pub fn normalizes_to_zero_var(&self) -> bool {
        let mut t0 = self.n[0];
        let mut t4 = self.n[4];

        // Reduce t4 at the start so there will be at most a single carry from the first pass
        let x = t4 >> 48;

        // The first pass ensures the magnitude is 1, ...
        t0 += x * C;

        // z0 tracks a possible raw value of 0, z1 tracks a possible raw value of P
        let mut z0 = t0 & M52;
        let mut z1 = z0 ^ 0x1_0000_03D0;

        // Fast return path should catch the majority of cases
        if (z0 != 0) & (z1 != M52) {
            return false;
        }

        let mut t1 = self.n[1];
        let mut t2 = self.n[2];
        let mut t3 = self.n[3];

        t4 &= M48;

        t1 += t0 >> 52;
        t2 += t1 >> 52;
        t1 &= M52;
        z0 |= t1;
        z1 &= t1;
        t3 += t2 >> 52;
        t2 &= M52;
        z0 |= t2;
        z1 &= t2;
        t4 += t3 >> 52;
        t3 &= M52;
        z0 |= t3;
        z1 &= t3;
        z0 |= t4;
        z1 &= t4 ^ 0xF_0000_0000_0000;

        // ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element)
        debug_assert!(t4 >> 49 == 0);

        (z0 == 0) | (z1 == M52)
    }

    /// `fe_impl_is_odd` (field_5x52_impl.h:211-213); requires normalized.
    #[inline]
    #[must_use]
    pub fn is_odd(&self) -> bool {
        self.n[0] & 1 == 1
    }

    /// `fe_impl_set_b32_mod` (field_5x52_impl.h:228-263): any 256-bit value,
    /// magnitude 1, not normalized.
    #[inline]
    #[must_use]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "field_5x52_impl.h:228-263: each byte is shifted by at most \
                  48 bits into a 52-bit limb, so no shift leaves u64"
    )]
    pub fn set_b32_mod(a: &[u8; 32]) -> Self {
        let b = |i: usize| u64::from(a[i]);
        Self {
            n: [
                b(31)
                    | (b(30) << 8)
                    | (b(29) << 16)
                    | (b(28) << 24)
                    | (b(27) << 32)
                    | (b(26) << 40)
                    | ((b(25) & 0xF) << 48),
                ((b(25) >> 4) & 0xF)
                    | (b(24) << 4)
                    | (b(23) << 12)
                    | (b(22) << 20)
                    | (b(21) << 28)
                    | (b(20) << 36)
                    | (b(19) << 44),
                b(18)
                    | (b(17) << 8)
                    | (b(16) << 16)
                    | (b(15) << 24)
                    | (b(14) << 32)
                    | (b(13) << 40)
                    | ((b(12) & 0xF) << 48),
                ((b(12) >> 4) & 0xF)
                    | (b(11) << 4)
                    | (b(10) << 12)
                    | (b(9) << 20)
                    | (b(8) << 28)
                    | (b(7) << 36)
                    | (b(6) << 44),
                b(5) | (b(4) << 8) | (b(3) << 16) | (b(2) << 24) | (b(1) << 32) | (b(0) << 40),
            ],
        }
    }

    /// `fe_impl_set_b32_limit` (field_5x52_impl.h:265-268): the value and
    /// whether it is below p.
    #[inline]
    #[must_use]
    pub fn set_b32_limit(a: &[u8; 32]) -> (Self, bool) {
        let r = Self::set_b32_mod(a);
        let n = &r.n;
        let ok = !((n[4] == M48) & ((n[3] & n[2] & n[1]) == M52) & (n[0] >= P0));
        (r, ok)
    }

    /// `fe_impl_get_b32` (field_5x52_impl.h:270-276); requires normalized.
    #[inline]
    #[must_use]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "field_5x52_impl.h:270-276: shifts by constants below 64 of \
                  normalized limbs; the bits shifted out are the ones the \
                  neighbouring word carries"
    )]
    pub fn get_b32(&self) -> [u8; 32] {
        let a = &self.n;
        let mut r = [0u8; 32];
        r[0..8].copy_from_slice(&((a[4] << 16) | (a[3] >> 36)).to_be_bytes());
        r[8..16].copy_from_slice(&((a[3] << 28) | (a[2] >> 24)).to_be_bytes());
        r[16..24].copy_from_slice(&((a[2] << 40) | (a[1] >> 12)).to_be_bytes());
        r[24..32].copy_from_slice(&((a[1] << 52) | a[0]).to_be_bytes());
        r
    }

    /// `fe_impl_negate_unchecked` (field_5x52_impl.h:278-291): 2(m+1)p - a
    /// limb by limb; m <= 31 and magnitude(a) <= m, so no limb underflows
    /// (:279-285).
    #[inline(always)]
    #[must_use]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "field_5x52_impl.h:279-288: for m <= 31, 2(m+1) times each \
                  limb of p is below 2^58 and at least the magnitude-m bound \
                  on a's limb, so neither the products nor the subtractions \
                  leave u64"
    )]
    pub fn negate_unchecked(&self, m: u32) -> Self {
        let a = &self.n;
        let k = 2 * (u64::from(m) + 1);
        // For all legal values of m (0..31), the following properties hold:
        debug_assert!(P0 * k >= M52 * (k - 2));
        debug_assert!(M48 * k >= M48 * (k - 2));
        // Due to the properties above, the left hand in the subtractions below is never less than
        // the right hand.
        Self {
            n: [
                P0 * k - a[0],
                M52 * k - a[1],
                M52 * k - a[2],
                M52 * k - a[3],
                M48 * k - a[4],
            ],
        }
    }

    /// `fe_impl_mul_int_unchecked` (field_5x52_impl.h:293-299): every
    /// limb times a; a times the magnitude <= 32.
    #[inline(always)]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "field_impl.h:310-320: a times the magnitude is at most 32, \
                  so every limb product stays below 2^58"
    )]
    pub fn mul_int_unchecked(&mut self, a: u32) {
        let a = u64::from(a);
        for l in &mut self.n {
            *l *= a;
        }
    }

    /// `fe_impl_add_int` (field_5x52_impl.h:301-303): a <= 0x7FFF and the
    /// magnitude grows by one.
    #[inline(always)]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "field_impl.h:228-237: a <= 0x7FFF and the result's \
                  magnitude <= 32, so the low limb stays below 2^58"
    )]
    pub fn add_int(&mut self, a: u16) {
        self.n[0] += u64::from(a);
    }

    /// `fe_impl_add` (field_5x52_impl.h:305-311); magnitudes sum to <= 32.
    #[inline(always)]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "field_impl.h:323-333: the magnitudes sum to <= 32, so every \
                  limb sum stays below 2^58"
    )]
    pub fn add_assign(&mut self, a: &Self) {
        self.n[0] += a.n[0];
        self.n[1] += a.n[1];
        self.n[2] += a.n[2];
        self.n[3] += a.n[3];
        self.n[4] += a.n[4];
    }

    /// `fe_impl_mul` (field_5x52_impl.h:313-315).
    #[inline(always)]
    #[must_use]
    pub fn mul(&self, b: &Self) -> Self {
        Self {
            n: mul::mul_inner(&self.n, &b.n),
        }
    }

    /// `fe_impl_sqr` (field_5x52_impl.h:317-319).
    #[inline(always)]
    #[must_use]
    pub fn sqr(&self) -> Self {
        Self {
            n: mul::sqr_inner(&self.n),
        }
    }

    /// `fe_impl_half` (field_5x52_impl.h:335-387): a/2 mod p, by adding p
    /// when a is odd and shifting right; input magnitude m <= 31 gives
    /// output magnitude floor(m/2) + 1, by the C's bounds analysis kept
    /// below.
    #[inline(always)]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "field_5x52_impl.h:335-387: for input magnitude <= 31 each \
                  limb plus at most 2^52 stays below 2^58, and the shifts \
                  are by constants"
    )]
    pub fn half(&mut self) {
        let [mut t0, mut t1, mut t2, mut t3, mut t4] = self.n;
        let one = 1u64;
        let mask = (t0 & one).wrapping_neg() >> 12;

        // Bounds analysis (over the rationals).
        //
        // Let m = r->magnitude
        //     C = 0xFFFFFFFFFFFFFULL * 2
        //     D = 0x0FFFFFFFFFFFFULL * 2
        //
        // Initial bounds: t0..t3 <= C * m
        //                     t4 <= D * m

        t0 += P0 & mask;
        t1 += mask;
        t2 += mask;
        t3 += mask;
        t4 += mask >> 4;

        debug_assert!((t0 & one) == 0);

        // t0..t3: added <= C/2
        //     t4: added <= D/2
        //
        // Current bounds: t0..t3 <= C * (m + 1/2)
        //                     t4 <= D * (m + 1/2)

        self.n[0] = (t0 >> 1) + ((t1 & one) << 51);
        self.n[1] = (t1 >> 1) + ((t2 & one) << 51);
        self.n[2] = (t2 >> 1) + ((t3 & one) << 51);
        self.n[3] = (t3 >> 1) + ((t4 & one) << 51);
        self.n[4] = t4 >> 1;

        // t0..t3: shifted right and added <= C/4 + 1/2
        //     t4: shifted right
        //
        // Current bounds: t0..t3 <= C * (m/2 + 1/2)
        //                     t4 <= D * (m/2 + 1/4)
        //
        // Therefore the output magnitude (M) has to be set such that:
        //     t0..t3: C * M >= C * (m/2 + 1/2)
        //         t4: D * M >= D * (m/2 + 1/4)
        //
        // It suffices for all limbs that, for any input magnitude m:
        //     M >= m/2 + 1/2
        //
        // and since we want the smallest such integer value for M:
        //     M == floor(m/2) + 1
    }

    /// `fe_impl_to_storage` (field_5x52_impl.h:402-407); requires
    /// normalized.  Tests and the table generator only.
    #[cfg(test)]
    #[inline]
    #[must_use]
    pub fn to_storage(self) -> FeStorage {
        let a = &self.n;
        FeStorage {
            n: [
                a[0] | (a[1] << 52),
                (a[1] >> 12) | (a[2] << 40),
                (a[2] >> 24) | (a[3] << 28),
                (a[3] >> 36) | (a[4] << 16),
            ],
        }
    }

    /// `fe_impl_from_storage` (field_5x52_impl.h:409-415): normalized,
    /// since storage holds a normalized value.
    #[inline(always)]
    #[must_use]
    pub const fn from_storage(a: &FeStorage) -> Self {
        Self {
            n: [
                a.n[0] & M52,
                (a.n[0] >> 52) | ((a.n[1] << 12) & M52),
                (a.n[1] >> 40) | ((a.n[2] << 24) & M52),
                (a.n[2] >> 28) | ((a.n[3] << 36) & M52),
                a.n[3] >> 16,
            ],
        }
    }

    /// `fe_from_signed62` (field_5x52_impl.h:417-435): from modinv64's
    /// output, limbs in [0, 2^62), value in [0, p).  Tests and the table
    /// generator only.
    #[cfg(test)]
    #[inline]
    #[must_use]
    pub(crate) fn from_signed62(a: &crate::modinv64::Signed62) -> Self {
        const M52_: u64 = u64::MAX >> 12;
        let [a0, a1, a2, a3, a4] = a.v.map(|x| x as u64);

        // The output from modinv64{_var} should be normalized to range [0,modulus), and
        // have limbs in [0,2^62). The modulus is < 2^256, so the top limb must be below 2^(256-62*4).
        debug_assert!(a0 >> 62 == 0);
        debug_assert!(a1 >> 62 == 0);
        debug_assert!(a2 >> 62 == 0);
        debug_assert!(a3 >> 62 == 0);
        debug_assert!(a4 >> 8 == 0);

        Self {
            n: [
                a0 & M52_,
                ((a0 >> 52) | (a1 << 10)) & M52_,
                ((a1 >> 42) | (a2 << 20)) & M52_,
                ((a2 >> 32) | (a3 << 30)) & M52_,
                (a3 >> 22) | (a4 << 40),
            ],
        }
    }

    /// `fe_to_signed62` (field_5x52_impl.h:437-446); requires normalized.
    /// Tests and the table generator only.
    #[cfg(test)]
    #[inline]
    #[must_use]
    pub(crate) fn to_signed62(self) -> crate::modinv64::Signed62 {
        const M62: u64 = u64::MAX >> 2;
        let [a0, a1, a2, a3, a4] = self.n;
        crate::modinv64::Signed62 {
            v: [
                ((a0 | (a1 << 52)) & M62) as i64,
                (((a1 >> 10) | (a2 << 42)) & M62) as i64,
                (((a2 >> 20) | (a3 << 32)) & M62) as i64,
                (((a3 >> 30) | (a4 << 22)) & M62) as i64,
                (a4 >> 40) as i64,
            ],
        }
    }
}

/// The field's modinv64 parameters (field_5x52_impl.h:448-451): p in
/// signed62 form and p^-1 mod 2^62.  Tests and the table generator only.
#[cfg(test)]
pub(crate) const MODINFO_FE: crate::modinv64::ModInfo = crate::modinv64::ModInfo {
    modulus: crate::modinv64::Signed62 {
        v: [-0x1_0000_03D1, 0, 0, 0, 256],
    },
    modulus_inv62: 0x27C7_F6E2_2DDA_CACF,
};

/// beta, a primitive cube root of unity mod p, so that lambda*(x, y) =
/// (beta*x, y) on the curve (field.h:69-72).  Normalized, magnitude 1.
pub(crate) const BETA: Fe = Fe::from_be_u32([
    0x7ae9_6a2b,
    0x657c_0710,
    0x6e64_479e,
    0xac34_34e9,
    0x9cf0_4975,
    0x12f5_8995,
    0xc139_6c28,
    0x7195_01ee,
]);
