// SPDX-License-Identifier: ISC AND MIT
//
// Derived from libsecp256k1 src/scalar_4x64_impl.h (Copyright (c) 2013,
// 2014 Pieter Wuille) and src/scalar_impl.h (Copyright (c) 2014 Pieter
// Wuille), as vendored by secp256k1-sys 0.14.1.  MIT; see NOTICE.
//
//! Integers mod the group order N in libsecp256k1's 4x64 representation,
//! the portable C paths of `scalar_4x64_impl.h` (its x86_64 assembly
//! blocks at :352-604 and :683-817 are not ported: the pure-Rust rule
//! forbids them, and the libsecp256k1 the node ran before did not build
//! them either).  Public data only: everything here is variable time where
//! that is convenient.
//!
//! What this increment needs is here and nothing more: bytes in and out,
//! addition, negation, multiplication and the inverse.  The bit access, the
//! 128-bit split, `mul_shift_var` and the GLV split arrive with the
//! multiply that calls them.

use core::ops::{Add, Mul, Neg};

/// N's limbs, little-endian (`SECP256K1_N_0..3`, scalar_4x64_impl.h:16-19).
const N: [u64; 4] = [
    0xBFD2_5E8C_D036_4141,
    0xBAAE_DCE6_AF48_A03B,
    0xFFFF_FFFF_FFFF_FFFE,
    0xFFFF_FFFF_FFFF_FFFF,
];
/// 2^256 - N, limb by limb (`SECP256K1_N_C_0..2`, scalar_4x64_impl.h:22-24).
const N_C_0: u64 = (!N[0]).wrapping_add(1);
const N_C_1: u64 = !N[1];
const N_C_2: u64 = 1;

/// An integer mod the secp256k1 group order N, always fully reduced
/// (below N).  Every operation on it is variable time: it is for public
/// values (signature components, hashes, the scalars of a verification)
/// and never for a private key or a nonce.
#[derive(Clone, Copy, Debug)]
pub struct Scalar {
    /// Limbs, little-endian, the value below N.
    d: [u64; 4],
}

impl PartialEq for Scalar {
    /// `scalar_eq` (scalar_4x64_impl.h:886-891): the limbs are canonical,
    /// so equal values have equal limbs.
    fn eq(&self, other: &Self) -> bool {
        self.d == other.d
    }
}

impl Eq for Scalar {}

/// The accumulator of libsecp256k1's `muladd`/`sumadd`/`extract` macros
/// (scalar_4x64_impl.h:285-349): (c0, c1, c2), 192 bits.
struct Acc {
    c0: u64,
    c1: u64,
    c2: u64,
}

impl Acc {
    /// `muladd(a,b)` (:288-301): add a*b to (c0,c1,c2).
    #[inline(always)]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the macro's bounds: a u64 by u64 product fits u128, its high \
                  half is at most 2^64-2 so adding c0's carry cannot wrap, and \
                  c2 never overflows by the callers' contract (:299), asserted \
                  in debug"
    )]
    fn muladd(&mut self, a: u64, b: u64) {
        let t = u128::from(a) * u128::from(b);
        let mut th = (t >> 64) as u64; // at most 0xFFFFFFFFFFFFFFFE
        let tl = t as u64;
        let (c0, o) = self.c0.overflowing_add(tl); // overflow is handled on the next line
        self.c0 = c0;
        th += u64::from(o); // at most 0xFFFFFFFFFFFFFFFF
        let (c1, o) = self.c1.overflowing_add(th); // overflow is handled on the next line
        self.c1 = c1;
        self.c2 += u64::from(o); // never overflows by contract (verified in the next line)
        debug_assert!((self.c1 >= th) || (self.c2 != 0));
    }

    /// `muladd_fast(a,b)` (:304-316): add a*b to (c0,c1); c1 must not
    /// overflow.
    #[inline(always)]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the macro's bounds: the product fits u128, its high half \
                  plus c0's carry fits u64, and c1 does not overflow by the \
                  callers' contract (:314), asserted in debug"
    )]
    fn muladd_fast(&mut self, a: u64, b: u64) {
        let t = u128::from(a) * u128::from(b);
        let mut th = (t >> 64) as u64; // at most 0xFFFFFFFFFFFFFFFE
        let tl = t as u64;
        let (c0, o) = self.c0.overflowing_add(tl); // overflow is handled on the next line
        self.c0 = c0;
        th += u64::from(o); // at most 0xFFFFFFFFFFFFFFFF
        self.c1 += th; // never overflows by contract (verified in the next line)
        debug_assert!(self.c1 >= th);
    }

    /// `sumadd(a)` (:319-325): add a to (c0,c1,c2).
    #[inline(always)]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "c2 never overflows by the callers' contract (:324)"
    )]
    fn sumadd(&mut self, a: u64) {
        let (c0, over) = self.c0.overflowing_add(a); // overflow is handled on the next line
        self.c0 = c0;
        let (c1, o) = self.c1.overflowing_add(u64::from(over)); // overflow is handled on the next line
        self.c1 = c1;
        self.c2 += u64::from(o); // never overflows by contract
    }

    /// `sumadd_fast(a)` (:328-333): add a to (c0,c1); c1 must not overflow
    /// and c2 must be 0.
    #[inline(always)]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "c1 does not overflow by the callers' contract (:331), \
                  asserted in debug"
    )]
    fn sumadd_fast(&mut self, a: u64) {
        let (c0, o) = self.c0.overflowing_add(a); // overflow is handled on the next line
        self.c0 = c0;
        self.c1 += u64::from(o); // never overflows by contract (verified the next line)
        debug_assert!((self.c1 != 0) | (self.c0 >= a));
        debug_assert!(self.c2 == 0);
    }

    /// `extract(n)` (:336-341): take c0 and shift the accumulator down a
    /// word.
    #[inline(always)]
    fn extract(&mut self) -> u64 {
        let n = self.c0;
        self.c0 = self.c1;
        self.c1 = self.c2;
        self.c2 = 0;
        n
    }

    /// `extract_fast(n)` (:344-349): the same when c2 is 0.
    #[inline(always)]
    fn extract_fast(&mut self) -> u64 {
        let n = self.c0;
        self.c0 = self.c1;
        self.c1 = 0;
        debug_assert!(self.c2 == 0);
        n
    }
}

impl Scalar {
    /// Zero.
    pub const ZERO: Self = Self { d: [0; 4] };
    /// One (tests).
    #[cfg(test)]
    pub(crate) const ONE: Self = Self { d: [1, 0, 0, 0] };

    /// `SECP256K1_SCALAR_VERIFY` (`scalar_verify`, scalar_impl.h:42-46):
    /// the value is below N.  Debug builds only; it reads and never writes.
    #[inline(always)]
    fn verify(&self) {
        debug_assert!(!check_overflow(&self.d), "scalar >= N");
    }

    /// `scalar_set_int` (scalar_4x64_impl.h:32-39), for the tests.
    #[cfg(test)]
    pub(crate) const fn from_u32(v: u32) -> Self {
        Self {
            d: [v as u64, 0, 0, 0],
        }
    }

    /// `scalar_set_b32` (:147-159): big-endian bytes mod N, by one
    /// conditional subtraction (exact, since 2^256 < 2N), and whether the
    /// bytes were at or above N.
    #[inline]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "byte offsets i + k with i in {0, 8, 16, 24} and k <= 7, \
                  below 32"
    )]
    pub(crate) fn set_b32(b32: &[u8; 32]) -> (Self, bool) {
        let rd = |i: usize| {
            u64::from_be_bytes([
                b32[i],
                b32[i + 1],
                b32[i + 2],
                b32[i + 3],
                b32[i + 4],
                b32[i + 5],
                b32[i + 6],
                b32[i + 7],
            ])
        };
        let mut d = [rd(24), rd(16), rd(8), rd(0)];
        let over = check_overflow(&d);
        reduce(&mut d, over);
        let r = Self { d };
        r.verify();
        (r, over)
    }

    /// The scalar with these big-endian bytes, or `None` if they are at or
    /// above N.
    #[inline]
    #[must_use]
    pub fn from_be_bytes(b: &[u8; 32]) -> Option<Self> {
        let (r, over) = Self::set_b32(b);
        if over { None } else { Some(r) }
    }

    /// These big-endian bytes mod N: one conditional subtraction, which is
    /// exact for any 256-bit value since 2^256 < 2N.
    #[inline]
    #[must_use]
    pub fn reduce_be_bytes(b: &[u8; 32]) -> Self {
        Self::set_b32(b).0
    }

    /// The value's 32 big-endian bytes (`scalar_get_b32`, :161-168).
    #[inline]
    #[must_use]
    pub fn to_be_bytes(&self) -> [u8; 32] {
        self.verify();
        let mut b = [0u8; 32];
        b[0..8].copy_from_slice(&self.d[3].to_be_bytes());
        b[8..16].copy_from_slice(&self.d[2].to_be_bytes());
        b[16..24].copy_from_slice(&self.d[1].to_be_bytes());
        b[24..32].copy_from_slice(&self.d[0].to_be_bytes());
        b
    }

    /// Whether the value is zero (`scalar_is_zero`, :170-174).
    #[inline(always)]
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.verify();
        (self.d[0] | self.d[1] | self.d[2] | self.d[3]) == 0
    }

    /// `scalar_negate` (:176-195): -a mod N, with 0 -> 0 through the
    /// `nonzero` mask.
    #[inline]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the C's u128 carry chain: each step adds at most two u64 \
                  terms and a carry below 2^64, so it stays below 2^66; \
                  N[0] + 1 is a constant that does not wrap"
    )]
    fn negate(&self) -> Self {
        let a = &self.d;
        let nonzero = if self.is_zero() { 0 } else { u64::MAX };
        self.verify();
        let mut r = [0u64; 4];
        let mut t = u128::from(!a[0]) + u128::from(N[0] + 1);
        r[0] = (t as u64) & nonzero;
        t >>= 64;
        t += u128::from(!a[1]) + u128::from(N[1]);
        r[1] = (t as u64) & nonzero;
        t >>= 64;
        t += u128::from(!a[2]) + u128::from(N[2]);
        r[2] = (t as u64) & nonzero;
        t >>= 64;
        t += u128::from(!a[3]) + u128::from(N[3]);
        r[3] = (t as u64) & nonzero;
        let r = Self { d: r };
        r.verify();
        r
    }

    /// `scalar_add` (:96-120): a + b mod N, and whether a + b reached N.
    #[inline]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the C's u128 carry chain of two u64 terms and a carry per \
                  limb, below 2^65; the overflow word is a carry bit plus \
                  one, at most 1 for inputs below N (asserted in debug)"
    )]
    fn add_overflow(&self, b: &Self) -> (Self, bool) {
        let (a, bd) = (&self.d, &b.d);
        self.verify();
        b.verify();
        let mut r = [0u64; 4];
        let mut t = u128::from(a[0]) + u128::from(bd[0]);
        r[0] = t as u64;
        t >>= 64;
        t += u128::from(a[1]) + u128::from(bd[1]);
        r[1] = t as u64;
        t >>= 64;
        t += u128::from(a[2]) + u128::from(bd[2]);
        r[2] = t as u64;
        t >>= 64;
        t += u128::from(a[3]) + u128::from(bd[3]);
        r[3] = t as u64;
        t >>= 64;
        let overflow = (t as u64) + u64::from(check_overflow(&r));
        debug_assert!(overflow == 0 || overflow == 1);
        reduce(&mut r, overflow == 1);
        let r = Self { d: r };
        r.verify();
        (r, overflow == 1)
    }

    /// `scalar_mul` (:859-868): `mul_512` then `reduce_512`.
    #[inline]
    fn mul(&self, b: &Self) -> Self {
        self.verify();
        b.verify();
        let l = mul_512(&self.d, &b.d);
        let r = Self { d: reduce_512(&l) };
        r.verify();
        r
    }

    /// `scalar_to_signed62` (:952-962).
    #[inline]
    fn to_signed62(self) -> crate::modinv64::Signed62 {
        const M62: u64 = u64::MAX >> 2;
        let [a0, a1, a2, a3] = self.d;
        self.verify();
        crate::modinv64::Signed62 {
            v: [
                (a0 & M62) as i64,
                (((a0 >> 62) | (a1 << 2)) & M62) as i64,
                (((a1 >> 60) | (a2 << 4)) & M62) as i64,
                (((a2 >> 58) | (a3 << 6)) & M62) as i64,
                (a3 >> 56) as i64,
            ],
        }
    }

    /// `scalar_from_signed62` (:932-950): limbs in [0, 2^62) and a value
    /// below N, as modinv64 returns them.  `None` if the value is not below
    /// N, which only a modinv64 bug could give; the caller falls back.
    #[inline]
    fn from_signed62(a: &crate::modinv64::Signed62) -> Option<Self> {
        let [a0, a1, a2, a3, a4] = a.v.map(|x| x as u64);
        // The output from modinv64{_var} should be normalized to range [0,modulus), and
        // have limbs in [0,2^62). The modulus is < 2^256, so the top limb must be below 2^(256-62*4).
        debug_assert!(a0 >> 62 == 0);
        debug_assert!(a1 >> 62 == 0);
        debug_assert!(a2 >> 62 == 0);
        debug_assert!(a3 >> 62 == 0);
        debug_assert!(a4 >> 8 == 0);
        let d = [
            a0 | (a1 << 62),
            (a1 >> 2) | (a2 << 60),
            (a2 >> 4) | (a3 << 58),
            (a3 >> 6) | (a4 << 56),
        ];
        if check_overflow(&d) {
            None
        } else {
            Some(Self { d })
        }
    }

    /// The inverse mod N, in variable time (`scalar_inverse_var`,
    /// :984-997, by safegcd); zero gives zero, as in libsecp256k1.
    ///
    /// `None` if the safegcd loop passes its cap of 24 outer iterations,
    /// twice the 12 its proof allows, or if the result is not below N.
    /// Neither can happen by that proof; a caller on the consensus path
    /// takes another inverse on `None` instead of trusting this one.
    #[inline]
    #[must_use]
    pub fn try_inverse_var(&self) -> Option<Self> {
        self.verify();
        let s = crate::modinv64::modinv64_var(&self.to_signed62(), &MODINFO_SCALAR)?;
        let r = Self::from_signed62(&s)?;
        debug_assert_eq!(r.is_zero(), self.is_zero());
        Some(r)
    }

    /// `scalar_add` with its overflow flag (tests).
    #[cfg(test)]
    pub(crate) fn add_with_overflow_for_tests(&self, b: &Self) -> (Self, bool) {
        self.add_overflow(b)
    }

    /// The signed62 limbs (tests).
    #[cfg(test)]
    pub(crate) fn to_signed62_for_tests(self) -> crate::modinv64::Signed62 {
        self.to_signed62()
    }

    /// `from_signed62` on limbs a test chose (tests).
    #[cfg(test)]
    pub(crate) fn from_signed62_for_tests(a: &crate::modinv64::Signed62) -> Option<Self> {
        Self::from_signed62(a)
    }

    /// [`Scalar::try_inverse_var`] also returning modinv64's outer
    /// iteration count (tests).
    #[cfg(test)]
    pub(crate) fn inverse_var_counted(&self) -> Option<(Self, u32)> {
        let (s, n) = crate::modinv64::modinv64_var_counted(&self.to_signed62(), &MODINFO_SCALAR)?;
        Some((Self::from_signed62(&s)?, n))
    }
}

impl Add for Scalar {
    type Output = Self;

    /// a + b mod N (`scalar_add`).
    #[inline]
    fn add(self, rhs: Self) -> Self {
        self.add_overflow(&rhs).0
    }
}

impl Mul for Scalar {
    type Output = Self;

    /// a * b mod N (`scalar_mul`).
    #[inline]
    fn mul(self, rhs: Self) -> Self {
        Scalar::mul(&self, &rhs)
    }
}

impl Neg for Scalar {
    type Output = Self;

    /// -a mod N, with -0 = 0 (`scalar_negate`).
    #[inline]
    fn neg(self) -> Self {
        self.negate()
    }
}

/// The scalar modinv64 parameters (`const_modinfo_scalar`,
/// scalar_4x64_impl.h:964-967): N in signed62 form and N^-1 mod 2^62.
pub(crate) const MODINFO_SCALAR: crate::modinv64::ModInfo = crate::modinv64::ModInfo {
    modulus: crate::modinv64::Signed62 {
        v: [0x3FD2_5E8C_D036_4141, 0x2ABB_739A_BD22_80EE, -0x15, 0, 256],
    },
    modulus_inv62: 0x34F2_0099_AA77_4EC1,
};

/// `scalar_check_overflow` (scalar_4x64_impl.h:64-74): whether d >= N.
#[inline(always)]
fn check_overflow(d: &[u64; 4]) -> bool {
    let mut yes = false;
    let mut no = false;
    no |= d[3] < N[3]; // No need for a > check.
    no |= d[2] < N[2];
    yes |= (d[2] > N[2]) & !no;
    no |= d[1] < N[1];
    yes |= (d[1] > N[1]) & !no;
    yes |= (d[0] >= N[0]) & !no;
    yes
}

/// `scalar_reduce` (scalar_4x64_impl.h:76-94): subtract N once if
/// `overflow`, by adding 2^256 - N and dropping the carry out of the top.
#[inline(always)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "the C's u128 carry chain of at most two u64 terms and a carry, \
              below 2^65; o * N_C_i is 0 or N_C_i"
)]
fn reduce(d: &mut [u64; 4], overflow: bool) {
    let o = u64::from(overflow);
    let mut t = u128::from(d[0]) + u128::from(o * N_C_0);
    d[0] = t as u64;
    t >>= 64;
    t += u128::from(d[1]) + u128::from(o * N_C_1);
    d[1] = t as u64;
    t >>= 64;
    t += u128::from(d[2]) + u128::from(o * N_C_2);
    d[2] = t as u64;
    t >>= 64;
    t += u128::from(d[3]);
    d[3] = t as u64;
}

/// `scalar_mul_512`'s C path (scalar_4x64_impl.h:818-849): the full
/// 512-bit product, little-endian.
#[inline(always)]
pub(crate) fn mul_512(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    // 160 bit accumulator.
    let mut c = Acc {
        c0: 0,
        c1: 0,
        c2: 0,
    };
    let mut l8 = [0u64; 8];

    // l8[0..7] = a[0..3] * b[0..3].
    c.muladd_fast(a[0], b[0]);
    l8[0] = c.extract_fast();
    c.muladd(a[0], b[1]);
    c.muladd(a[1], b[0]);
    l8[1] = c.extract();
    c.muladd(a[0], b[2]);
    c.muladd(a[1], b[1]);
    c.muladd(a[2], b[0]);
    l8[2] = c.extract();
    c.muladd(a[0], b[3]);
    c.muladd(a[1], b[2]);
    c.muladd(a[2], b[1]);
    c.muladd(a[3], b[0]);
    l8[3] = c.extract();
    c.muladd(a[1], b[3]);
    c.muladd(a[2], b[2]);
    c.muladd(a[3], b[1]);
    l8[4] = c.extract();
    c.muladd(a[2], b[3]);
    c.muladd(a[3], b[2]);
    l8[5] = c.extract();
    c.muladd_fast(a[3], b[3]);
    l8[6] = c.extract_fast();
    debug_assert!(c.c1 == 0);
    l8[7] = c.c0;
    l8
}

/// `scalar_reduce_512`'s C path (scalar_4x64_impl.h:605-676): a 512-bit
/// value mod N, folding 2^256 = N_C mod N three times and subtracting N
/// at most once.
#[inline(always)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "the C's bounds: m6 <= 1 and p4 <= 2 (asserted in debug), so \
              p4 * N_C_i fits u128 and each step of the final u128 carry \
              chain stays below 2^130; c0 + m6 <= 2"
)]
pub(crate) fn reduce_512(l: &[u64; 8]) -> [u64; 4] {
    let (n0, n1, n2, n3) = (l[4], l[5], l[6], l[7]);

    // Reduce 512 bits into 385.
    // m[0..6] = l[0..3] + n[0..3] * SECP256K1_N_C.
    let mut c = Acc {
        c0: l[0],
        c1: 0,
        c2: 0,
    };
    c.muladd_fast(n0, N_C_0);
    let m0 = c.extract_fast();
    c.sumadd_fast(l[1]);
    c.muladd(n1, N_C_0);
    c.muladd(n0, N_C_1);
    let m1 = c.extract();
    c.sumadd(l[2]);
    c.muladd(n2, N_C_0);
    c.muladd(n1, N_C_1);
    c.sumadd(n0);
    let m2 = c.extract();
    c.sumadd(l[3]);
    c.muladd(n3, N_C_0);
    c.muladd(n2, N_C_1);
    c.sumadd(n1);
    let m3 = c.extract();
    c.muladd(n3, N_C_1);
    c.sumadd(n2);
    let m4 = c.extract();
    c.sumadd_fast(n3);
    let m5 = c.extract_fast();
    debug_assert!(c.c0 <= 1);
    let m6 = c.c0;

    // Reduce 385 bits into 258.
    // p[0..4] = m[0..3] + m[4..6] * SECP256K1_N_C.
    let mut c = Acc {
        c0: m0,
        c1: 0,
        c2: 0,
    };
    c.muladd_fast(m4, N_C_0);
    let p0 = c.extract_fast();
    c.sumadd_fast(m1);
    c.muladd(m5, N_C_0);
    c.muladd(m4, N_C_1);
    let p1 = c.extract();
    c.sumadd(m2);
    c.muladd(m6, N_C_0);
    c.muladd(m5, N_C_1);
    c.sumadd(m4);
    let p2 = c.extract();
    c.sumadd_fast(m3);
    c.muladd_fast(m6, N_C_1);
    c.sumadd_fast(m5);
    let p3 = c.extract_fast();
    let p4 = c.c0 + m6;
    debug_assert!(p4 <= 2);

    // Reduce 258 bits into 256.
    // r[0..3] = p[0..3] + p[4] * SECP256K1_N_C.
    let mut r = [0u64; 4];
    let mut c128 = u128::from(p0) + u128::from(N_C_0) * u128::from(p4);
    r[0] = c128 as u64;
    c128 >>= 64;
    c128 += u128::from(p1) + u128::from(N_C_1) * u128::from(p4);
    r[1] = c128 as u64;
    c128 >>= 64;
    c128 += u128::from(p2) + u128::from(p4);
    r[2] = c128 as u64;
    c128 >>= 64;
    c128 += u128::from(p3);
    r[3] = c128 as u64;
    let cc = (c128 >> 64) as u64;

    // Final reduction of r.
    let over = cc + u64::from(check_overflow(&r));
    debug_assert!(over <= 1);
    reduce(&mut r, over == 1);
    r
}
