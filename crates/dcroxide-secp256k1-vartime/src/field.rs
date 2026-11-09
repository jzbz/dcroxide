// SPDX-License-Identifier: ISC AND MIT
//
// Derived from libsecp256k1 src/field_5x52_impl.h and src/field_5x52.h
// (both Copyright (c) 2013, 2014 Pieter Wuille), as vendored by
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
//! What this increment needs is here and nothing more: bytes in and out,
//! addition, small additions, negation, multiplication, squaring, the
//! variable-time normalization, the zero test and the square root, which
//! is what key decompression and the curve check reach.  Constant-time
//! and weak normalization, `half`, `mul_int`, the storage form, the
//! comparison and the inverse arrive with the group formulas that call
//! them.
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

impl FeRaw {
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
}
