// SPDX-License-Identifier: ISC AND MIT
//
// Derived from libsecp256k1 src/modinv64_impl.h and src/modinv64.h
// (Copyright (c) 2020 Peter Dettman), as vendored by secp256k1-sys 0.14.1.
// MIT; see NOTICE.
//
//! Variable-time modular inversion by safegcd (Bernstein-Yang), a port of
//! libsecp256k1's `modinv64_var` with 62-bit signed limbs (modinv64_impl.h;
//! design note: libsecp256k1's doc/safegcd_implementation.md).  The scalar
//! inverse uses it; the field inverse will, with its own modulus.
//!
//! Differences from the C:
//! - the driver loop is capped at [`MAX_OUTER`] outer iterations (twice the
//!   proven [`PROVEN_OUTER`], modinv64_impl.h:688) and returns `None` past
//!   it, instead of looping until g = 0 with the bound checked only under
//!   VERIFY, and `divsteps_62_var`'s inner loop at [`MAX_PASSES`] passes
//!   per 62 divsteps, so a port bug cannot hang a verifying thread on an
//!   attacker's input (ADR-0016);
//! - shifts are plain `<<`/`>>` (a shift amount >= 64 panics in debug), never
//!   `wrapping_shl`; every place the C relies on u64 wraparound is written
//!   `wrapping_*`;
//! - `normalize_62`'s `volatile` (:91) is for constant time and is dropped;
//! - the VERIFY invariants are `debug_assert!`s, with `mul_62`/`mul_cmp_62`
//!   and the determinant check ported for them (:41-81).

/// A signed 62-bit limb integer: sum(v\[i\] * 2^(62*i)) (modinv64.h:16-21).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Signed62 {
    /// Limbs.
    pub(crate) v: [i64; 5],
}

/// A modulus and its inverse mod 2^62 (modinv64.h:23-29).
#[derive(Clone, Copy, Debug)]
pub(crate) struct ModInfo {
    /// The modulus in signed62 form; odd, in [3, 2^256].
    pub(crate) modulus: Signed62,
    /// modulus^-1 mod 2^62.
    pub(crate) modulus_inv62: u64,
}

/// A 2x2 transition matrix scaled by 2^62 (modinv64_impl.h:20-27).
#[derive(Clone, Copy, Debug)]
struct Trans2x2 {
    u: i64,
    v: i64,
    q: i64,
    r: i64,
}

/// libsecp's proven bound on outer iterations (modinv64_impl.h:688,
/// "never need more than 12*62 = 744 divsteps"); debug builds assert it.
pub(crate) const PROVEN_OUTER: u32 = 12;

/// Release cap on outer iterations: twice [`PROVEN_OUTER`].
pub(crate) const MAX_OUTER: u32 = 2 * PROVEN_OUTER;

/// Release cap on the passes of `divsteps_62_var`'s inner loop.  Every pass
/// after the first starts from an even g, which the previous pass's update
/// left with its bottom bit clear, so it does at least one of the 62
/// divsteps; the 62 take at most 63 passes.
pub(crate) const MAX_PASSES: u32 = 63;

const M62: u64 = u64::MAX >> 2;

#[cfg(debug_assertions)]
mod check {
    //! Ports of the VERIFY helpers (modinv64_impl.h:29-82).
    use super::{M62, Signed62, Trans2x2};

    /// `modinv64_mul_62` (:41-54): a*factor, all but the top limb in
    /// [0, 2^62).
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "i128 accumulators of 63-bit by 64-bit products; libsecp's bound"
    )]
    fn mul_62(a: &Signed62, alen: usize, factor: i64) -> Signed62 {
        let mut r = Signed62 { v: [0; 5] };
        let mut c: i128 = 0;
        for i in 0..4 {
            if i < alen {
                c += i128::from(a.v[i]) * i128::from(factor);
            }
            r.v[i] = ((c as u64) & M62) as i64;
            c >>= 62;
        }
        if 4 < alen {
            c += i128::from(a.v[4]) * i128::from(factor);
        }
        assert_eq!(i128::from(c as i64), c, "mul_62 top limb overflow");
        r.v[4] = c as i64;
        r
    }

    /// `modinv64_mul_cmp_62` (:57-72): sign of a - b*factor.
    pub(super) fn mul_cmp_62(
        a: &Signed62,
        alen: usize,
        b: &Signed62,
        factor: i64,
    ) -> core::cmp::Ordering {
        let am = mul_62(a, alen, 1);
        let bm = mul_62(b, 5, factor);
        for i in 0..4 {
            assert!(am.v[i] >> 62 == 0);
            assert!(bm.v[i] >> 62 == 0);
        }
        for i in (0..5).rev() {
            if am.v[i] < bm.v[i] {
                return core::cmp::Ordering::Less;
            }
            if am.v[i] > bm.v[i] {
                return core::cmp::Ordering::Greater;
            }
        }
        core::cmp::Ordering::Equal
    }

    /// `modinv64_det_check_pow2` (:75-81) with abs = 0: det t == 2^n.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "products of |entries| <= 2^62 fit i128"
    )]
    pub(super) fn det_is_pow2(t: &Trans2x2, n: u32) -> bool {
        let det = i128::from(t.u) * i128::from(t.r) - i128::from(t.v) * i128::from(t.q);
        det == 1i128 << n
    }

    /// |v| for v > i64::MIN (:32-36).
    pub(super) fn abs(v: i64) -> i64 {
        assert!(v > i64::MIN);
        v.abs()
    }
}

/// `modinv64_normalize_62` (modinv64_impl.h:88-154): r in (-2*modulus,
/// modulus) with limbs in (-2^62, 2^62) becomes r (negated if sign < 0)
/// mod modulus in [0, modulus), limbs in [0, 2^62).
#[allow(
    clippy::arithmetic_side_effects,
    reason = "libsecp's bounds (:104-108): limbs in (-2^62, 2^62) plus a \
              modulus limb (|.| < 2^62) cannot overflow i64; negation of a \
              value > -2^63"
)]
fn normalize_62(r: &mut Signed62, sign: i64, modinfo: &ModInfo) {
    let m62 = M62 as i64;
    let [mut r0, mut r1, mut r2, mut r3, mut r4] = r.v;

    #[cfg(debug_assertions)]
    {
        use core::cmp::Ordering::{Greater, Less};
        // Verify that all limbs are in range (-2^62,2^62).
        for &x in &r.v {
            assert!(x >= -m62 && x <= m62);
        }
        assert!(check::mul_cmp_62(r, 5, &modinfo.modulus, -2) == Greater); // r > -2*modulus
        assert!(check::mul_cmp_62(r, 5, &modinfo.modulus, 1) == Less); // r < modulus
    }

    // In a first step, add the modulus if the input is negative, and then negate if requested.
    // This brings r from range (-2*modulus,modulus) to range (-modulus,modulus). As all input
    // limbs are in range (-2^62,2^62), this cannot overflow an int64_t. Note that the right
    // shifts below are signed sign-extending shifts.
    let mut cond_add = r4 >> 63;
    let m = &modinfo.modulus.v;
    r0 += m[0] & cond_add;
    r1 += m[1] & cond_add;
    r2 += m[2] & cond_add;
    r3 += m[3] & cond_add;
    r4 += m[4] & cond_add;
    let cond_negate = sign >> 63;
    r0 = (r0 ^ cond_negate) - cond_negate;
    r1 = (r1 ^ cond_negate) - cond_negate;
    r2 = (r2 ^ cond_negate) - cond_negate;
    r3 = (r3 ^ cond_negate) - cond_negate;
    r4 = (r4 ^ cond_negate) - cond_negate;
    // Propagate the top bits, to bring limbs back to range (-2^62,2^62).
    r1 += r0 >> 62;
    r0 &= m62;
    r2 += r1 >> 62;
    r1 &= m62;
    r3 += r2 >> 62;
    r2 &= m62;
    r4 += r3 >> 62;
    r3 &= m62;

    // In a second step add the modulus again if the result is still negative, bringing
    // r to range [0,modulus).
    cond_add = r4 >> 63;
    r0 += m[0] & cond_add;
    r1 += m[1] & cond_add;
    r2 += m[2] & cond_add;
    r3 += m[3] & cond_add;
    r4 += m[4] & cond_add;
    // And propagate again.
    r1 += r0 >> 62;
    r0 &= m62;
    r2 += r1 >> 62;
    r1 &= m62;
    r3 += r2 >> 62;
    r2 &= m62;
    r4 += r3 >> 62;
    r3 &= m62;

    r.v = [r0, r1, r2, r3, r4];

    #[cfg(debug_assertions)]
    {
        use core::cmp::Ordering::Less;
        for &x in &r.v {
            assert!(x >> 62 == 0);
        }
        assert!(check::mul_cmp_62(r, 5, &modinfo.modulus, 0) != Less); // r >= 0
        assert!(check::mul_cmp_62(r, 5, &modinfo.modulus, 1) == Less); // r < modulus
    }
}

/// `modinv64_divsteps_62_var` (modinv64_impl.h:239-310): the transition
/// matrix and new eta for 62 divsteps, variable time.  `None` if the inner
/// loop would pass [`MAX_PASSES`], which only a port bug or an even f0
/// could make it do; the driver passes that up.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "eta and i are bounded (|eta| <= 745, 0 <= i <= 62, :262), and \
              the pass counter by MAX_PASSES; every u64 operation the C lets \
              wrap is written wrapping_*"
)]
fn divsteps_62_var(mut eta: i64, f0: u64, g0: u64, t: &mut Trans2x2) -> Option<i64> {
    // Transformation matrix; see comments in modinv64_divsteps_62.
    let (mut u, mut v, mut q, mut r): (u64, u64, u64, u64) = (1, 0, 0, 1);
    let (mut f, mut g) = (f0, g0);
    let mut i: u32 = 62;
    let mut passes: u32 = 0;

    loop {
        if passes == MAX_PASSES {
            return None;
        }
        passes += 1;
        // Use a sentinel bit to count zeros only up to i.
        debug_assert!(i < 64);
        let zeros = (g | (u64::MAX << i)).trailing_zeros();
        debug_assert!(zeros <= 62);
        // Perform zeros divsteps at once; they all just divide g by two.
        g >>= zeros;
        u <<= zeros;
        v <<= zeros;
        eta -= i64::from(zeros);
        i -= zeros;
        // We're done once we've done 62 divsteps.
        if i == 0 {
            break;
        }
        debug_assert!(f & 1 == 1);
        debug_assert!(g & 1 == 1);
        debug_assert!(u.wrapping_mul(f0).wrapping_add(v.wrapping_mul(g0)) == f << (62 - i));
        debug_assert!(q.wrapping_mul(f0).wrapping_add(r.wrapping_mul(g0)) == g << (62 - i));
        // Bounds on eta that follow from the bounds on iteration count (max 12*62 divsteps).
        debug_assert!((-745..=745).contains(&eta));
        // If eta is negative, negate it and replace f,g with g,-f.
        let (m, w) = if eta < 0 {
            eta = -eta;
            let tmp = f;
            f = g;
            g = tmp.wrapping_neg();
            let tmp = u;
            u = q;
            q = tmp.wrapping_neg();
            let tmp = v;
            v = r;
            r = tmp.wrapping_neg();
            // Use a formula to cancel out up to 6 bits of g. Also, no more than i can be cancelled
            // out (as we'd be done before that point), and no more than eta+1 can be done as its
            // sign will flip again once that happens.
            let limit = if (eta as u32) + 1 > i {
                i
            } else {
                (eta as u32) + 1
            };
            debug_assert!(limit > 0 && limit <= 62);
            // m is a mask for the bottom min(limit, 6) bits.
            let m = (u64::MAX >> (64 - limit)) & 63;
            // Find what multiple of f must be added to g to cancel its bottom min(limit, 6)
            // bits.
            (
                m,
                f.wrapping_mul(g)
                    .wrapping_mul(f.wrapping_mul(f).wrapping_sub(2))
                    & m,
            )
        } else {
            // In this branch, use a simpler formula that only lets us cancel up to 4 bits of g, as
            // eta tends to be smaller here.
            let limit = if (eta as u32) + 1 > i {
                i
            } else {
                (eta as u32) + 1
            };
            debug_assert!(limit > 0 && limit <= 62);
            // m is a mask for the bottom min(limit, 4) bits.
            let m = (u64::MAX >> (64 - limit)) & 15;
            // Find what multiple of f must be added to g to cancel its bottom min(limit, 4)
            // bits.
            let w = f.wrapping_add((f.wrapping_add(1) & 4) << 1);
            (m, w.wrapping_neg().wrapping_mul(g) & m)
        };
        g = g.wrapping_add(f.wrapping_mul(w));
        q = q.wrapping_add(u.wrapping_mul(w));
        r = r.wrapping_add(v.wrapping_mul(w));
        debug_assert!(g & m == 0);
    }
    // Return data in t and return value.
    t.u = u as i64;
    t.v = v as i64;
    t.q = q as i64;
    t.r = r as i64;

    // The determinant of t must be a power of two. This guarantees that multiplication with t
    // does not change the gcd of f and g, apart from adding a power-of-2 factor to it (which
    // will be divided out again). As each divstep's individual matrix has determinant 2, the
    // aggregate of 62 of them will have determinant 2^62.
    #[cfg(debug_assertions)]
    assert!(check::det_is_pow2(t, 62));

    Some(eta)
}

/// [`divsteps_62_var`] on its own, for tests that hand it what the driver
/// never does.
#[cfg(test)]
pub(crate) fn divsteps_62_var_for_tests(eta: i64, f0: u64, g0: u64) -> Option<i64> {
    let mut t = Trans2x2 {
        u: 0,
        v: 0,
        q: 0,
        r: 0,
    };
    divsteps_62_var(eta, f0, g0, &mut t)
}

/// `modinv64_update_de_62` (modinv64_impl.h:411-494): (t/2^62) * [d, e]
/// mod modulus; d, e in (-2*modulus, modulus) on input and output.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "libsecp's bounds (:404-409, :422-423): |u|+|v|, |q|+|r| <= 2^62 \
              and limbs < 2^62 keep the i128 accumulators in range; md, me \
              stay within i64; the C's wrapping u64 product is wrapping_mul"
)]
fn update_de_62(d: &mut Signed62, e: &mut Signed62, t: &Trans2x2, modinfo: &ModInfo) {
    let [d0, d1, d2, d3, d4] = d.v;
    let [e0, e1, e2, e3, e4] = e.v;
    let (u, v, q, r) = (t.u, t.v, t.q, t.r);
    let mv = &modinfo.modulus.v;
    #[cfg(debug_assertions)]
    {
        use core::cmp::Ordering::{Greater, Less};
        assert!(check::mul_cmp_62(d, 5, &modinfo.modulus, -2) == Greater); // d > -2*modulus
        assert!(check::mul_cmp_62(d, 5, &modinfo.modulus, 1) == Less); // d <    modulus
        assert!(check::mul_cmp_62(e, 5, &modinfo.modulus, -2) == Greater); // e > -2*modulus
        assert!(check::mul_cmp_62(e, 5, &modinfo.modulus, 1) == Less); // e <    modulus
        assert!(check::abs(u) <= (1i64 << 62) - check::abs(v)); // |u|+|v| <= 2^62
        assert!(check::abs(q) <= (1i64 << 62) - check::abs(r)); // |q|+|r| <= 2^62
    }

    let mul = |a: i64, b: i64| i128::from(a) * i128::from(b);

    // [md,me] start as zero; plus [u,q] if d is negative; plus [v,r] if e is negative.
    let sd = d4 >> 63;
    let se = e4 >> 63;
    let mut md = (u & sd) + (v & se);
    let mut me = (q & sd) + (r & se);
    // Begin computing t*[d,e].
    let mut cd = mul(u, d0) + mul(v, e0);
    let mut ce = mul(q, d0) + mul(r, e0);
    // Correct md,me so that t*[d,e]+modulus*[md,me] has 62 zero bottom bits.
    md -= (modinfo
        .modulus_inv62
        .wrapping_mul(cd as u64)
        .wrapping_add(md as u64)
        & M62) as i64;
    me -= (modinfo
        .modulus_inv62
        .wrapping_mul(ce as u64)
        .wrapping_add(me as u64)
        & M62) as i64;
    // Update the beginning of computation for t*[d,e]+modulus*[md,me] now md,me are known.
    cd += mul(mv[0], md);
    ce += mul(mv[0], me);
    // Verify that the low 62 bits of the computation are indeed zero, and then throw them away.
    debug_assert!((cd as u64) & M62 == 0);
    cd >>= 62;
    debug_assert!((ce as u64) & M62 == 0);
    ce >>= 62;
    // Compute limb 1 of t*[d,e]+modulus*[md,me], and store it as output limb 0 (= down shift).
    cd += mul(u, d1) + mul(v, e1);
    ce += mul(q, d1) + mul(r, e1);
    if mv[1] != 0 {
        // Optimize for the case where limb of modulus is zero.
        cd += mul(mv[1], md);
        ce += mul(mv[1], me);
    }
    d.v[0] = ((cd as u64) & M62) as i64;
    cd >>= 62;
    e.v[0] = ((ce as u64) & M62) as i64;
    ce >>= 62;
    // Compute limb 2 of t*[d,e]+modulus*[md,me], and store it as output limb 1.
    cd += mul(u, d2) + mul(v, e2);
    ce += mul(q, d2) + mul(r, e2);
    if mv[2] != 0 {
        // Optimize for the case where limb of modulus is zero.
        cd += mul(mv[2], md);
        ce += mul(mv[2], me);
    }
    d.v[1] = ((cd as u64) & M62) as i64;
    cd >>= 62;
    e.v[1] = ((ce as u64) & M62) as i64;
    ce >>= 62;
    // Compute limb 3 of t*[d,e]+modulus*[md,me], and store it as output limb 2.
    cd += mul(u, d3) + mul(v, e3);
    ce += mul(q, d3) + mul(r, e3);
    if mv[3] != 0 {
        // Optimize for the case where limb of modulus is zero.
        cd += mul(mv[3], md);
        ce += mul(mv[3], me);
    }
    d.v[2] = ((cd as u64) & M62) as i64;
    cd >>= 62;
    e.v[2] = ((ce as u64) & M62) as i64;
    ce >>= 62;
    // Compute limb 4 of t*[d,e]+modulus*[md,me], and store it as output limb 3.
    cd += mul(u, d4) + mul(v, e4);
    ce += mul(q, d4) + mul(r, e4);
    cd += mul(mv[4], md);
    ce += mul(mv[4], me);
    d.v[3] = ((cd as u64) & M62) as i64;
    cd >>= 62;
    e.v[3] = ((ce as u64) & M62) as i64;
    ce >>= 62;
    // What remains is limb 5 of t*[d,e]+modulus*[md,me]; store it as output limb 4.
    debug_assert!(i128::from(cd as i64) == cd && i128::from(ce as i64) == ce);
    d.v[4] = cd as i64;
    e.v[4] = ce as i64;

    #[cfg(debug_assertions)]
    {
        use core::cmp::Ordering::{Greater, Less};
        assert!(check::mul_cmp_62(d, 5, &modinfo.modulus, -2) == Greater); // d > -2*modulus
        assert!(check::mul_cmp_62(d, 5, &modinfo.modulus, 1) == Less); // d <    modulus
        assert!(check::mul_cmp_62(e, 5, &modinfo.modulus, -2) == Greater); // e > -2*modulus
        assert!(check::mul_cmp_62(e, 5, &modinfo.modulus, 1) == Less); // e <    modulus
    }
}

/// `modinv64_update_fg_62_var` (modinv64_impl.h:553-585): (t/2^62) * [f, g]
/// over the low `len` limbs.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "libsecp's bounds: f, g in (-modulus, modulus], |u|+|v|, |q|+|r| \
              <= 2^62, so the i128 accumulators stay in range"
)]
fn update_fg_62_var(len: usize, f: &mut Signed62, g: &mut Signed62, t: &Trans2x2) {
    let (u, v, q, r) = (t.u, t.v, t.q, t.r);
    let mul = |a: i64, b: i64| i128::from(a) * i128::from(b);
    debug_assert!(len > 0);
    // Start computing t*[f,g].
    let (fi, gi) = (f.v[0], g.v[0]);
    let mut cf = mul(u, fi) + mul(v, gi);
    let mut cg = mul(q, fi) + mul(r, gi);
    // Verify that the bottom 62 bits of the result are zero, and then throw them away.
    debug_assert!((cf as u64) & M62 == 0);
    cf >>= 62;
    debug_assert!((cg as u64) & M62 == 0);
    cg >>= 62;
    // Now iteratively compute limb i=1..len of t*[f,g], and store them in output limb i-1 (shifting
    // down by 62 bits).
    for i in 1..len {
        let (fi, gi) = (f.v[i], g.v[i]);
        cf += mul(u, fi) + mul(v, gi);
        cg += mul(q, fi) + mul(r, gi);
        f.v[i - 1] = ((cf as u64) & M62) as i64;
        cf >>= 62;
        g.v[i - 1] = ((cg as u64) & M62) as i64;
        cg >>= 62;
    }
    // What remains is limb (len) of t*[f,g]; store it as output limb (len-1).
    debug_assert!(i128::from(cf as i64) == cf && i128::from(cg as i64) == cg);
    f.v[len - 1] = cf as i64;
    g.v[len - 1] = cg as i64;
}

/// `modinv64_var` (modinv64_impl.h:637-710): x^-1 mod modulus, variable
/// time; x in [0, modulus), 0 gives 0, output limbs in [0, 2^62).  `None`
/// if the loop would exceed [`MAX_OUTER`] outer iterations, or a batch of
/// divsteps [`MAX_PASSES`] passes.
#[inline]
#[must_use]
pub(crate) fn modinv64_var(x: &Signed62, modinfo: &ModInfo) -> Option<Signed62> {
    modinv64_var_capped(x, modinfo, MAX_OUTER).map(|(r, _)| r)
}

/// [`modinv64_var`], also returning the number of outer iterations taken
/// (tests assert it never exceeds [`PROVEN_OUTER`]).
#[cfg(test)]
#[must_use]
pub(crate) fn modinv64_var_counted(x: &Signed62, modinfo: &ModInfo) -> Option<(Signed62, u32)> {
    modinv64_var_capped(x, modinfo, MAX_OUTER)
}

/// The driver with an explicit outer-iteration cap (production passes
/// [`MAX_OUTER`]; a test passes a smaller cap to exercise the `None` path,
/// which no representable input reaches with the real cap).
#[allow(
    clippy::arithmetic_side_effects,
    reason = "len in 1..=5 and the iteration counter <= cap; the top \
              limb shift is the C's (u64)fn << 62, written on u64"
)]
#[must_use]
pub(crate) fn modinv64_var_capped(
    x: &Signed62,
    modinfo: &ModInfo,
    cap: u32,
) -> Option<(Signed62, u32)> {
    // Start with d=0, e=1, f=modulus, g=x, eta=-1.
    let mut d = Signed62 { v: [0; 5] };
    let mut e = Signed62 { v: [1, 0, 0, 0, 0] };
    let mut f = modinfo.modulus;
    let mut g = *x;
    let mut len: usize = 5;
    let mut eta: i64 = -1; // eta = -delta; delta is initially 1
    let mut iters: u32 = 0;

    // Do iterations of 62 divsteps each until g=0.
    loop {
        if iters >= cap {
            return None;
        }
        iters += 1;
        // Compute transition matrix and new eta after 62 divsteps.
        let mut t = Trans2x2 {
            u: 0,
            v: 0,
            q: 0,
            r: 0,
        };
        eta = divsteps_62_var(eta, f.v[0] as u64, g.v[0] as u64, &mut t)?;
        // Update d,e using that transition matrix.
        update_de_62(&mut d, &mut e, &t, modinfo);
        // Update f,g using that transition matrix.
        #[cfg(debug_assertions)]
        {
            use core::cmp::Ordering::{Greater, Less};
            assert!(check::mul_cmp_62(&f, len, &modinfo.modulus, -1) == Greater); // f > -modulus
            assert!(check::mul_cmp_62(&f, len, &modinfo.modulus, 1) != Greater); // f <= modulus
            assert!(check::mul_cmp_62(&g, len, &modinfo.modulus, -1) == Greater); // g > -modulus
            assert!(check::mul_cmp_62(&g, len, &modinfo.modulus, 1) == Less); // g <  modulus
        }

        update_fg_62_var(len, &mut f, &mut g, &t);
        // If the bottom limb of g is zero, there is a chance that g=0.
        if g.v[0] == 0 {
            let mut cond: i64 = 0;
            // Check if the other limbs are also 0.
            for j in 1..len {
                cond |= g.v[j];
            }
            // If so, we're done.
            if cond == 0 {
                break;
            }
        }

        // Determine if len>1 and limb (len-1) of both f and g is 0 or -1.
        let fn_ = f.v[len - 1];
        let gn = g.v[len - 1];
        let mut cond: i64 = ((len as i64) - 2) >> 63;
        cond |= fn_ ^ (fn_ >> 63);
        cond |= gn ^ (gn >> 63);
        // If so, reduce length, propagating the sign of f and g's top limb into the one below.
        if cond == 0 {
            f.v[len - 2] |= ((fn_ as u64) << 62) as i64;
            g.v[len - 2] |= ((gn as u64) << 62) as i64;
            len -= 1;
        }

        debug_assert!(
            iters < PROVEN_OUTER,
            "modinv64_var: more than 12 outer iterations"
        ); // We should never need more than 12*62 = 744 divsteps
        #[cfg(debug_assertions)]
        {
            use core::cmp::Ordering::{Greater, Less};
            assert!(check::mul_cmp_62(&f, len, &modinfo.modulus, -1) == Greater); // f > -modulus
            assert!(check::mul_cmp_62(&f, len, &modinfo.modulus, 1) != Greater); // f <= modulus
            assert!(check::mul_cmp_62(&g, len, &modinfo.modulus, -1) == Greater); // g > -modulus
            assert!(check::mul_cmp_62(&g, len, &modinfo.modulus, 1) == Less); // g <  modulus
        }
    }

    // At this point g is 0 and (if g was not originally 0) f must now equal +/- GCD of
    // the initial f, g values i.e. +/- 1, and d now contains +/- the modular inverse.
    #[cfg(debug_assertions)]
    {
        use core::cmp::Ordering::Equal;
        let one = Signed62 { v: [1, 0, 0, 0, 0] };
        // g == 0
        assert!(check::mul_cmp_62(&g, len, &one, 0) == Equal);
        // |f| == 1, or (x == 0 and d == 0 and f == modulus)
        assert!(
            check::mul_cmp_62(&f, len, &one, -1) == Equal
                || check::mul_cmp_62(&f, len, &one, 1) == Equal
                || (check::mul_cmp_62(x, 5, &one, 0) == Equal
                    && check::mul_cmp_62(&d, 5, &one, 0) == Equal
                    && check::mul_cmp_62(&f, len, &modinfo.modulus, 1) == Equal)
        );
    }

    // Optionally negate d, normalize to [0,modulus), and return it.
    normalize_62(&mut d, f.v[len - 1], modinfo);
    Some((d, iters))
}
