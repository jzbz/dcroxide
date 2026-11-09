// SPDX-License-Identifier: ISC AND MIT
//
// Derived from libsecp256k1 src/ecmult_impl.h (Copyright (c) 2013, 2014,
// 2017 Pieter Wuille, Andrew Poelstra, Jonas Nick) and src/ecmult.h
// (Copyright (c) 2013, 2014, 2017 Pieter Wuille, Andrew Poelstra), as
// vendored by secp256k1-sys 0.14.1.  MIT; see NOTICE.
//
//! na*A + ng*G by libsecp256k1's Straus loop over wNAF digits
//! (`ecmult_strauss_wnaf`, ecmult_impl.h:252-363), for one point A:
//!
//! - na is split by the endomorphism (`split_lambda`) into two halves of
//!   about 128 bits, each written as a wNAF of window [`WINDOW_A`].  A's
//!   odd multiples 1A, 3A, ..., 15A are built on an isomorphic curve and
//!   brought to one shared Z, so the loop adds them as affine points
//!   (`gej_add_ge_var`); lambda*A's entries reuse their y with x * beta.
//! - ng is split at bit 128 and each half written as a wNAF of the
//!   generator tables' window, read from the static tables of G and
//!   2^128*G (`crate::g_tables`) and added with `gej_add_zinv_var`, which
//!   accounts for the shared Z.
//! - one chain of doublings serves all four digit strings, at most 129
//!   positions long.
//!
//! The wNAF builder declines a half that does not fit 129 positions
//! (`crate::wnaf`); [`ecmult_var`] passes that `None` up for the caller to
//! fall back.  The loop itself, [`strauss_core`], takes its digit strings,
//! its generator tables and beta as arguments, so that the exhaustive
//! tests run the same function on the order-199 test curve; it is always
//! inlined, so the shipped instance has secp256k1's tables built in.
//!
//! The panics that remain in release builds are slice index checks on the
//! digit strings (i < bits <= 129, the most `try_wnaf` returns) and on the
//! table lookups.  Each table index is (|n| - 1)/2 for an odd digit n with
//! |n| <= 2^(w-1) - 1, which `ecmult_table_verify` asserts in debug builds
//! and the tests' digit-bound property checks for every window, so it is
//! below the table's 2^(w-2) entries.
//!
//! Every input is public; everything here is variable time.

use crate::field::{BETA, Fe};
use crate::g_tables::{PRE_G, PRE_G_128, WINDOW_G};
use crate::group::{Ge, GeStorage, Gej};
use crate::scalar::Scalar;
use crate::wnaf::{WNAF_LEN, try_wnaf};

/// The window of A's wNAF (ecmult_impl.h:31-32, "optimal for 128-bit and
/// 256-bit exponents"; also libsecp256k1's value for the order-199 test
/// curve, :23-24).
pub(crate) const WINDOW_A: u32 = 5;

/// `ECMULT_TABLE_SIZE(WINDOW_A)` (ecmult.h:41): 8 odd multiples.
pub(crate) const TABLE_SIZE_A: usize = 1 << (WINDOW_A - 2);

/// Counts the branch the last formula took at a loop site (test builds
/// only).
macro_rules! site {
    ($s:ident) => {
        #[cfg(test)]
        crate::tests::branches::hit(crate::tests::branches::Site::$s);
    };
}

/// `ecmult_odd_multiples_table` (ecmult_impl.h:73-115) for n =
/// [`TABLE_SIZE_A`]: `pre_a` gets 1a, 3a, ..., 15a as Jacobian points with
/// their Z omitted, on the isomorphic curve Y^2 = X^3 + 7C^6 with C =
/// (2a).z; `zr[i]` is z(pre_a\[i\]) / z(pre_a\[i-1\]), and zr\[0\] = C.
/// Returns z(pre_a\[n-1\]) * C, the shared Z once
/// [`Ge::table_set_globalz`] has run.
///
/// No addition here meets an equal x (the group module doc), so no ratio
/// is zero; builds with debug assertions check it.
#[inline(always)]
pub(crate) fn odd_multiples_table(
    pre_a: &mut [Ge; TABLE_SIZE_A],
    zr: &mut [Fe; TABLE_SIZE_A],
    a: &Gej,
) -> Fe {
    debug_assert!(!a.is_infinity());

    let d = a.double_var(None);

    // Perform the additions using an isomorphic curve Y^2 = X^3 + 7*C^6 where C := d.z.
    // The isomorphism, phi, maps a secp256k1 point (x, y) to the point (x*C^2, y*C^3) on the other curve.
    // In Jacobian coordinates phi maps (x, y, z) to (x*C^2, y*C^3, z) or, equivalently to (x, y, z/C).
    //
    //     phi(x, y, z) = (x*C^2, y*C^3, z) = (x, y, z/C)
    //   d_ge := phi(d) = (d.x, d.y, 1)
    //     a_i := phi(a) = (a.x*C^2, a.y*C^3, a.z)
    //
    // The group addition functions work correctly on these isomorphic curves.
    // In particular phi(d) is easy to represent in affine coordinates under this isomorphism.
    // This lets us use the faster secp256k1_gej_add_ge_var group addition function that we wouldn't be able to use otherwise.
    let d_ge = Ge::set_xy(&d.x, &d.y);
    pre_a[0] = Ge::set_gej_zinv(a, &d.z);
    let mut a_i = Gej::set_ge(&pre_a[0]);
    a_i.z = a.z;

    // pre_a[0] is the point (a.x*C^2, a.y*C^3, a.z*C) which is equivalent to a.
    // Set zr[0] to C, which is the ratio between the omitted z(pre_a[0]) value and a.z.
    zr[0] = d.z;

    for i in 1..TABLE_SIZE_A {
        a_i = a_i.add_ge_var(&d_ge, Some(&mut zr[i]));
        pre_a[i] = Ge::set_xy(&a_i.x, &a_i.y);
    }
    debug_assert!(
        zr.iter().all(|z| !z.normalizes_to_zero_var()),
        "the odd-multiples table met an equal x"
    );

    // Multiply the last z-coordinate by C to undo the isomorphism.
    // Since the z-coordinates of the pre_a values are implied by the zr array of z-coordinate ratios,
    // undoing the isomorphism here undoes the isomorphism for all pre_a values.
    a_i.z.mul(&d.z)
}

/// `ecmult_table_verify` (ecmult_impl.h:117-123): n odd and |n| <=
/// 2^(w-1) - 1.  No-op in builds without debug assertions.
#[inline(always)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "2 <= w <= 16: 1 << (w-1) and its negation fit an i32"
)]
fn table_verify(n: i32, w: u32) {
    debug_assert!(n & 1 == 1);
    debug_assert!(n > -(1 << (w - 1)));
    debug_assert!(n < (1 << (w - 1)));
}

/// `ecmult_table_get_ge` (ecmult_impl.h:125-133): the entry for digit n,
/// y negated for a negative n.
#[inline(always)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "n is an odd wNAF digit with |n| <= 2^(w-1) - 1 \
              (table_verify), so (n-1)/2 and (-n-1)/2 are table indices"
)]
fn table_get_ge(pre: &[Ge; TABLE_SIZE_A], n: i32, w: u32) -> Ge {
    table_verify(n, w);
    if n > 0 {
        pre[((n - 1) / 2) as usize]
    } else {
        let mut r = pre[((-n - 1) / 2) as usize];
        r.y = r.y.negate(1);
        r
    }
}

/// `ecmult_table_get_ge_lambda` (ecmult_impl.h:135-143): lambda times the
/// entry for digit n, as (x * beta, y), y negated for a negative n.
#[inline(always)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "as table_get_ge: the index is in the table"
)]
fn table_get_ge_lambda(pre: &[Ge; TABLE_SIZE_A], x: &[Fe; TABLE_SIZE_A], n: i32, w: u32) -> Ge {
    table_verify(n, w);
    if n > 0 {
        let k = ((n - 1) / 2) as usize;
        Ge::set_xy(&x[k], &pre[k].y)
    } else {
        let k = ((-n - 1) / 2) as usize;
        let mut r = Ge::set_xy(&x[k], &pre[k].y);
        r.y = r.y.negate(1);
        r
    }
}

/// `ecmult_table_get_ge_storage` (ecmult_impl.h:145-153): the generator
/// table entry for digit n, y negated for a negative n.
#[inline(always)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "as table_get_ge: the index is below the table's 2^(w-2) entries"
)]
fn table_get_ge_storage(pre: &[GeStorage], n: i32, w: u32) -> Ge {
    table_verify(n, w);
    if n > 0 {
        Ge::from_storage(&pre[((n - 1) / 2) as usize])
    } else {
        let mut r = Ge::from_storage(&pre[((-n - 1) / 2) as usize]);
        r.y = r.y.negate(1);
        r
    }
}

/// The four wNAF digit strings of one multiply (`strauss_point_state` and
/// the generator's halves, ecmult_impl.h:238-262).
pub(crate) struct Digits {
    /// na_1, window [`WINDOW_A`].
    pub(crate) na_1: [i8; WNAF_LEN],
    /// Positions used by `na_1`.
    pub(crate) bits_na_1: usize,
    /// na_lam, window [`WINDOW_A`].
    pub(crate) na_lam: [i8; WNAF_LEN],
    /// Positions used by `na_lam`.
    pub(crate) bits_na_lam: usize,
    /// ng_1, the generator tables' window.
    pub(crate) ng_1: [i16; WNAF_LEN],
    /// Positions used by `ng_1`.
    pub(crate) bits_ng_1: usize,
    /// ng_128, the generator tables' window.
    pub(crate) ng_128: [i16; WNAF_LEN],
    /// Positions used by `ng_128`.
    pub(crate) bits_ng_128: usize,
}

impl Digits {
    /// All strings empty.
    pub(crate) const fn new() -> Self {
        Self {
            na_1: [0; WNAF_LEN],
            bits_na_1: 0,
            na_lam: [0; WNAF_LEN],
            bits_na_lam: 0,
            ng_1: [0; WNAF_LEN],
            bits_ng_1: 0,
            ng_128: [0; WNAF_LEN],
            bits_ng_128: 0,
        }
    }
}

/// The body of `ecmult_strauss_wnaf` (ecmult_impl.h:252-363) for one point,
/// once the scalars are split and written as wNAFs.  `a` is `None` when na
/// is zero (the C skips the point, :270-272, and its strings must be
/// empty).  `pre_g` and `pre_g_128` hold the odd multiples of G and
/// 2^128*G for window `w_g`; `beta` is the field's cube root of unity that
/// matches the lambda na was split by.
#[inline(always)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "loop indices below bits <= 129; j below TABLE_SIZE_A"
)]
pub(crate) fn strauss_core(
    a: Option<&Gej>,
    d: &Digits,
    pre_g: &[GeStorage],
    pre_g_128: &[GeStorage],
    w_g: u32,
    beta: &Fe,
) -> Gej {
    let mut pre_a = [Ge::INFINITY; TABLE_SIZE_A];
    let mut aux = [Fe::ZERO; TABLE_SIZE_A];
    let mut z = Fe::ONE;
    let mut bits = 0usize;

    let have_a = if let Some(a) = a {
        debug_assert!(d.bits_na_1 <= WNAF_LEN && d.bits_na_lam <= WNAF_LEN);
        bits = bits.max(d.bits_na_1).max(d.bits_na_lam);

        // Calculate odd multiples of a.
        // All multiples are brought to the same Z 'denominator', which is stored
        // in Z. Due to secp256k1' isomorphism we can do all operations pretending
        // that the Z coordinate was 1, use affine addition formulae, and correct
        // the Z coordinate of the result once at the end.
        // The exception is the precomputed G table points, which are actually
        // affine. Compared to the base used for other points, they have a Z ratio
        // of 1/Z, so we can use secp256k1_gej_add_zinv_var, which uses the same
        // isomorphism to efficiently add with a known Z inverse.
        z = odd_multiples_table(&mut pre_a, &mut aux, a);

        // Bring them to the same Z denominator.
        Ge::table_set_globalz(&mut pre_a, &aux);

        for j in 0..TABLE_SIZE_A {
            aux[j] = pre_a[j].x.mul(beta);
        }
        true
    } else {
        debug_assert!(d.bits_na_1 == 0 && d.bits_na_lam == 0);
        false
    };

    bits = bits.max(d.bits_ng_1).max(d.bits_ng_128);
    debug_assert!(bits <= WNAF_LEN);
    debug_assert!(pre_g.len() == 1 << (w_g - 2) && pre_g_128.len() == pre_g.len());

    let mut r = Gej::INFINITY;

    for i in (0..bits).rev() {
        r = r.double_var(None);
        site!(Double);
        if have_a {
            let n = i32::from(d.na_1[i]);
            if i < d.bits_na_1 && n != 0 {
                let tmpa = table_get_ge(&pre_a, n, WINDOW_A);
                r = r.add_ge_var(&tmpa, None);
                site!(A);
            }
            let n = i32::from(d.na_lam[i]);
            if i < d.bits_na_lam && n != 0 {
                let tmpa = table_get_ge_lambda(&pre_a, &aux, n, WINDOW_A);
                r = r.add_ge_var(&tmpa, None);
                site!(LambdaA);
            }
        }
        let n = i32::from(d.ng_1[i]);
        if i < d.bits_ng_1 && n != 0 {
            let tmpa = table_get_ge_storage(pre_g, n, w_g);
            r = r.add_zinv_var(&tmpa, &z);
            site!(G);
        }
        let n = i32::from(d.ng_128[i]);
        if i < d.bits_ng_128 && n != 0 {
            let tmpa = table_get_ge_storage(pre_g_128, n, w_g);
            r = r.add_zinv_var(&tmpa, &z);
            site!(G128);
        }
    }

    if !r.is_infinity() {
        r.z = r.z.mul(&z);
    }
    r
}

/// `ecmult` (ecmult_impl.h:365-375, through `ecmult_strauss_wnaf`):
/// na*A + ng*G with the static window-12 tables of G and 2^128*G.  `None`
/// only if the wNAF builder declines a half, which the split's bound
/// proof rules out; the caller falls back.
#[inline]
pub(crate) fn ecmult_var(a: &Ge, na: &Scalar, ng: &Scalar) -> Option<Gej> {
    let mut d = Digits::new();
    let aj;
    let a_opt = if na.is_zero() || a.infinity {
        None
    } else {
        // split na into na_1 and na_lam (where na = na_1 + na_lam*lambda, and na_1 and na_lam are ~128 bit)
        let (na_1, na_lam) = na.split_lambda();

        // build wnaf representation for na_1 and na_lam.
        d.bits_na_1 = try_wnaf(&mut d.na_1, &na_1, WINDOW_A)?;
        d.bits_na_lam = try_wnaf(&mut d.na_lam, &na_lam, WINDOW_A)?;
        aj = Gej::set_ge(a);
        Some(&aj)
    };

    // split ng into ng_1 and ng_128 (where gn = gn_1 + gn_128*2^128, and gn_1 and gn_128 are ~128 bit)
    let (ng_1, ng_128) = ng.split_128();

    // Build wnaf representation for ng_1 and ng_128
    d.bits_ng_1 = try_wnaf(&mut d.ng_1, &ng_1, WINDOW_G)?;
    d.bits_ng_128 = try_wnaf(&mut d.ng_128, &ng_128, WINDOW_G)?;

    Some(strauss_core(a_opt, &d, &PRE_G, &PRE_G_128, WINDOW_G, &BETA))
}
