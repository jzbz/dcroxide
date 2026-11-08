// SPDX-License-Identifier: ISC
//! The variable-time sum a*G + b*P behind ECDSA verification (step 5),
//! compact recovery (step 9) and EC-Schnorr-DCRv0 verification (step 7).
//!
//! dcrd computes each of these sums as `ScalarBaseMultNonConst` plus
//! `ScalarMultNonConst` plus `AddNonConst` (ecdsa/signature.go:256-258 and
//! :978-980, schnorr/signature.go:196-198).  The value is one group element,
//! so any correct algorithm gives dcrd's answer.  k256's
//! `mul_by_generator_and_mul_add_vartime` gives it too, but builds four
//! 8-entry tables on every call, two of them for G.  This module keeps G's
//! tables static instead and runs its own interleaved (Straus) wNAF loop
//! over k256's public point operations:
//!
//! - b is split by GLV into r1 + r2*lambda, each half below 2^128 in
//!   magnitude (k256's `decompose_scalar`, the same arithmetic, which k256
//!   keeps `pub(super)`), and runs over a per-call table of P, 3P, ..., 15P
//!   (window 5) and its image under `endomorphism()`, lambda*P;
//! - a is split by bits into lo + hi*2^128, and the halves run over static
//!   affine tables of the odd multiples of G and of 2^128*G (window 12,
//!   1024 points each, 176 KiB for both on 64-bit targets in release
//!   builds), built once on first use.
//!
//! What stays k256's: field, scalar and point arithmetic, `endomorphism`,
//! inversion and batch normalization.  Every addition and doubling is a
//! complete Renes-Costello-Batina formula
//! (`k256-0.14.0/src/arithmetic/projective.rs:95-131`, mixed :141-176,
//! doubling :181-217), so no branch here handles P + P, P + (-P) or the
//! identity: dcrd's `AddNonConst` doubles or returns infinity as its
//! operands require, and the complete formulas give the same element.
//! secp256k1's cofactor is 1, so every point that can reach this module,
//! an attacker's key or the point recovery decompresses from an attacker's
//! r among them, lies in the one group of order N, where `endomorphism()`
//! (x -> beta*x) is multiplication by lambda; dcrd's `ScalarMultNonConst`
//! relies on the same (curve.go:1102-1182).
//!
//! Variable time on public inputs only: the loop branches and indexes on
//! both scalars, as dcrd's `NonConst` functions do.  Signing never comes
//! here; it keeps the constant-time `ProjectivePoint::GENERATOR * k`.
//!
//! `no_std` with `alloc`: the tables are boxed, and their first-use cell is
//! once_cell's `race::OnceBox`, which needs pointer-width atomic
//! compare-and-swap.  A target without it (thumbv6m, say) does not build
//! this crate.

// The flagged operators are k256 scalar and point arithmetic (modular
// group arithmetic, where overflow is not a representable state) and the
// wNAF's position and digit arithmetic, bounded as each function says.
#![allow(clippy::arithmetic_side_effects)]

use alloc::boxed::Box;
use alloc::vec::Vec;

use k256::elliptic_curve::bigint::U128;
use k256::elliptic_curve::ops::{MulByGeneratorVartime, Retrieve};
use k256::elliptic_curve::point::BatchNormalize;
use k256::elliptic_curve::scalar::{FromUintUnchecked, IsHigh};
use k256::{AffinePoint, ProjectivePoint, Scalar, U256};
use once_cell::race::OnceBox;

/// wNAF window of the static tables of G and 2^128*G: 2^(W_G-2) = 1024
/// odd multiples each.  Digits reach 2^(W_G-1) - 1 = 2047 in magnitude.
const W_G: u32 = 12;

/// wNAF window of the per-call tables of P and lambda*P, k256's and
/// libsecp256k1's choice: 2^(W_Q-2) = 8 odd multiples each.
const W_Q: u32 = 5;

/// Odd multiples in each per-call table, 2^(W_Q-2).
const Q_TABLE_LEN: usize = 1 << (W_Q - 2);

/// Odd multiples in each static table, 2^(W_G-2).
const G_TABLE_LEN: usize = 1 << (W_G - 2);

/// Points normalized per batch inversion when the static tables are built.
const NORMALIZE_CHUNK: usize = 64;

/// wNAF digit positions for a value below 2^128: the 128 bit positions and
/// one more for the carry out of the top window.
const WNAF_LEN: usize = 129;

// The GLV constants of `k256-0.14.0/src/arithmetic/mul/glv.rs:10-37`, as
// integers.  Each is below N, so `Scalar::from_uint_unchecked` takes it as
// it is.  The tests tie them to k256's beta and to the lattice they come
// from.

/// -lambda mod N, where lambda is the eigenvalue of `endomorphism()`.
const MINUS_LAMBDA: U256 =
    U256::from_be_hex("ac9c52b33fa3cf1f5ad9e3fd77ed9ba4a880b9fc8ec739c2e0cfc810b51283cf");
/// -b1 mod N, of the lattice basis (a1, b1), (a2, b2).
const MINUS_B1: U256 =
    U256::from_be_hex("00000000000000000000000000000000e4437ed6010e88286f547fa90abfe4c3");
/// -b2 mod N.
const MINUS_B2: U256 =
    U256::from_be_hex("fffffffffffffffffffffffffffffffe8a280ac50774346dd765cda83db1562c");
/// round(2^384 * b2 / N).
const GLV_G1: U256 =
    U256::from_be_hex("3086d221a7d46bcde86c90e49284eb153daa8a1471e8ca7fe893209a45dbb031");
/// round(2^384 * -b1 / N).
const GLV_G2: U256 =
    U256::from_be_hex("e4437ed6010e88286f547fa90abfe4c4221208ac9df506c61571b4ae8ac47f71");

/// round(k * g / 2^384), the value of k256's
/// `WideScalar::mul_shift_vartime(k, g, 384)`
/// (`k256-0.14.0/src/arithmetic/scalar/wide64.rs:64-119`, `pub(crate)`).
///
/// `hi` holds bits 256 to 511 of the product, so its top half is the
/// quotient and its bit 127, product bit 383, rounds.  The split works on
/// whole `U128` halves, whatever the limb width, so the code is the same
/// on 32- and 64-bit targets.  The result is at most 2^128, so neither the
/// add nor the caller's `from_uint_unchecked` wraps.
fn mul_shift_384(k: &U256, g: &U256) -> U256 {
    let (_lo, hi) = k.widening_mul(g);
    let (_, top): (U128, U128) = hi.split();
    U256::from_u128(u128::from(top)).wrapping_add(&U256::from_u64(u64::from(hi.bit_vartime(127))))
}

/// k's GLV split (r1, r2) with r1 + r2*lambda = k mod N: k256's
/// `decompose_scalar` (`k256-0.14.0/src/arithmetic/mul/glv.rs:149-156`)
/// step for step, the same constants and the same rounding.
///
/// k256's proof (glv.rs:43-146, after libsecp256k1's) shows that for
/// every k below N, r1 or -r1 and r2 or -r2 is below 2^128; the tests
/// check this function's output against the same steps in unbounded
/// integers.
fn glv_split(k: &Scalar) -> (Scalar, Scalar) {
    let ku = k.retrieve();
    let c1 = Scalar::from_uint_unchecked(mul_shift_384(&ku, &GLV_G1))
        * Scalar::from_uint_unchecked(MINUS_B1);
    let c2 = Scalar::from_uint_unchecked(mul_shift_384(&ku, &GLV_G2))
        * Scalar::from_uint_unchecked(MINUS_B2);
    let r2 = c1 + c2;
    let r1 = *k + r2 * Scalar::from_uint_unchecked(MINUS_LAMBDA);
    (r1, r2)
}

/// A scalar's low and high 128 bits, through crypto-bigint's split into
/// `U128` halves: no limb indexing, so no dependence on the limb width.
fn halves(s: &Scalar) -> (u128, u128) {
    let (lo, hi): (U128, U128) = s.retrieve().split();
    (u128::from(lo), u128::from(hi))
}

/// A GLV half folded to its magnitude: (|r|, whether r was negated), or
/// `None` when the magnitude is 2^128 or more.  The GLV bound makes `None`
/// unreachable; it is the predicate of the guard in [`mul_g_add_vartime`].
fn half128(r: Scalar) -> Option<(u128, bool)> {
    let neg = bool::from(r.is_high());
    let r = if neg { -r } else { r };
    let (lo, hi) = halves(&r);
    (hi == 0).then_some((lo, neg))
}

/// `count` (at most 16) bits of `k` from bit `bit` up; zero from bit 128 on.
fn bits(k: u128, bit: usize, count: u32) -> i32 {
    if bit >= 128 {
        0
    } else {
        ((k >> bit) as u32 & ((1u32 << count) - 1)) as i32
    }
}

/// The width-`w` NAF of `k` (2 <= w <= 16), libsecp256k1's `ecmult_wnaf`
/// over 129 positions: `out[i]` is the digit of 2^i, zero or odd with
/// magnitude at most 2^(w-1) - 1, nonzero digits at least `w` positions
/// apart, and sum(out[i] * 2^i) = k.  Returns the digits and one past the
/// highest nonzero digit, 0 for k = 0.
///
/// Digits are i16: at w = 12 they reach 2047.  A window opens only where
/// the bit differs from the carry, so every window's word is odd.  A carry
/// out of the top window lands on position 128, where the bit is 0 and the
/// window is one bit wide, so its digit is 1 and no carry survives it.
fn wnaf128(k: u128, w: u32) -> ([i16; WNAF_LEN], usize) {
    let mut out = [0i16; WNAF_LEN];
    let mut bit = 0usize;
    let mut carry = 0i32;
    let mut last = 0usize;
    while bit < WNAF_LEN {
        if bits(k, bit, 1) == carry {
            bit += 1;
            continue;
        }
        let now = core::cmp::min(w as usize, WNAF_LEN - bit) as u32;
        let mut word = bits(k, bit, now) + carry;
        carry = (word >> (w - 1)) & 1;
        word -= carry << w;
        out[bit] = word as i16;
        last = bit + 1;
        bit += now as usize;
    }
    debug_assert_eq!(carry, 0, "wNAF carry past position 128");
    (out, last)
}

/// The static tables: `lo[i] = (2i+1)*G` and `hi[i] = (2i+1)*2^128*G` for
/// i below `G_TABLE_LEN`, affine, so each addition is k256's mixed formula.
struct GTables {
    /// Odd multiples of G.
    lo: Box<[AffinePoint]>,
    /// Odd multiples of 2^128*G.
    hi: Box<[AffinePoint]>,
}

/// `n` affine odd multiples of `base`, normalized `NORMALIZE_CHUNK` at a
/// time through k256's array `BatchNormalize` (one inversion per chunk; the
/// slice form would need k256's `alloc` feature).  Built in a `Vec`, so
/// the table is never on the stack.  No entry is the identity: each is
/// (2i+1)*base with 2i+1 far below N.
fn odd_multiples_affine(base: ProjectivePoint, n: usize) -> Box<[AffinePoint]> {
    let mut out = Vec::with_capacity(n);
    let b2 = base.double();
    let mut cur = base;
    let mut chunk = [ProjectivePoint::IDENTITY; NORMALIZE_CHUNK];
    let mut filled = 0;
    for _ in 0..n {
        chunk[filled] = cur;
        filled += 1;
        cur += &b2;
        if filled == NORMALIZE_CHUNK {
            out.extend_from_slice(&<ProjectivePoint as BatchNormalize<
                [ProjectivePoint; NORMALIZE_CHUNK],
            >>::batch_normalize_vartime(&chunk));
            filled = 0;
        }
    }
    out.extend(chunk[..filled].iter().map(ProjectivePoint::to_affine));
    out.into_boxed_slice()
}

/// Both static tables, with 2^128*G from 128 doublings of G.
fn build_g_tables() -> GTables {
    let g = ProjectivePoint::GENERATOR;
    let mut g128 = g;
    for _ in 0..128 {
        g128 = g128.double();
    }
    GTables {
        lo: odd_multiples_affine(g, G_TABLE_LEN),
        hi: odd_multiples_affine(g128, G_TABLE_LEN),
    }
}

/// The static tables' cell, filled on first use, so only a process that
/// verifies or recovers pays their memory; dcrd loads its base-point table
/// lazily behind a `sync.Once` for the same reason (loadprecomputed.go:80-90).
/// Racing threads may each build a copy; one compare-and-swap wins, the
/// others drop theirs, and every caller gets the winner's.  The content is
/// deterministic, so whichever thread wins, the tables are the same.
static G_TABLES: OnceBox<GTables> = OnceBox::new();

/// The static tables, built on first use.
fn g_tables() -> &'static GTables {
    G_TABLES.get_or_init(|| Box::new(build_g_tables()))
}

/// a*G + b*P in variable time: the value k256's
/// `ProjectivePoint::mul_by_generator_and_mul_add_vartime(a, b, p)`
/// returns, and dcrd's `ScalarBaseMultNonConst(a)`, `ScalarMultNonConst(b,
/// P)` and `AddNonConst` give.  Public inputs only: it branches and indexes
/// on both scalars.
///
/// The guard: [`try_mul_g_add_vartime`] declines only when a GLV half of b
/// is 2^128 or more, which k256's proof rules out for every b.  Should it
/// ever happen, this returns k256's own combined pass, the code before this
/// module, so the answer is the same as before on every input, proven or
/// not; k256 itself takes each half's low 128 bits unchecked
/// (`k256-0.14.0/src/arithmetic/mul/glv.rs:176-182`).  An assertion would
/// be an outage under `panic = "abort"`; debug builds still assert, and the
/// tests call the fast path directly and require it.
pub(crate) fn mul_g_add_vartime(a: &Scalar, b: &Scalar, p: &ProjectivePoint) -> ProjectivePoint {
    let r = try_mul_g_add_vartime(a, b, p);
    debug_assert!(r.is_some(), "GLV half at or above 2^128");
    r.unwrap_or_else(|| ProjectivePoint::mul_by_generator_and_mul_add_vartime(a, b, p))
}

/// a*G + b*P, or `None` when a GLV half of b is 2^128 or more (unreachable,
/// see [`mul_g_add_vartime`]).  The bound is checked before the static
/// tables are touched.
///
/// Each half's sign is folded into its digits' signs, not into the table.
/// a = 0, b = 0 or both leave the matching digit strings empty, so the sum
/// of the rest comes out, and the identity when both are zero.  Table
/// indices are |d| >> 1 with |d| at most 2^(w-1) - 1: at most 7 into the
/// per-call tables and 1023 into the static ones.
fn try_mul_g_add_vartime(a: &Scalar, b: &Scalar, p: &ProjectivePoint) -> Option<ProjectivePoint> {
    // The signed halves r1, r2 and their magnitudes m1, m2, with n1, n2
    // saying whether each was negated.
    let (r1, r2) = glv_split(b);
    let (m1, n1) = half128(r1)?;
    let (m2, n2) = half128(r2)?;
    let gt = g_tables();

    let (d1, l1) = wnaf128(m1, W_Q);
    let (d2, l2) = wnaf128(m2, W_Q);

    // a needs no GLV split: its halves are its bits, each below 2^128.
    let (a_lo, a_hi) = halves(a);
    let (e1, le1) = wnaf128(a_lo, W_G);
    let (e2, le2) = wnaf128(a_hi, W_G);

    // P, 3P, ..., 15P (one doubling, seven additions), and their images
    // under the endomorphism, lambda*P, ..., 15*lambda*P.
    let mut t = [*p; Q_TABLE_LEN];
    let p2 = p.double();
    for i in 1..Q_TABLE_LEN {
        t[i] = t[i - 1] + p2;
    }
    let tl = t.map(|q| q.endomorphism());

    let len = l1.max(l2).max(le1).max(le2);
    let mut acc = ProjectivePoint::IDENTITY;
    for i in (0..len).rev() {
        acc = acc.double();
        let d = d1[i];
        if d != 0 {
            let q = &t[usize::from(d.unsigned_abs() >> 1)];
            if (d < 0) != n1 {
                acc -= q;
            } else {
                acc += q;
            }
        }
        let d = d2[i];
        if d != 0 {
            let q = &tl[usize::from(d.unsigned_abs() >> 1)];
            if (d < 0) != n2 {
                acc -= q;
            } else {
                acc += q;
            }
        }
        let e = e1[i];
        if e != 0 {
            let q = &gt.lo[usize::from(e.unsigned_abs() >> 1)];
            if e < 0 {
                acc -= q;
            } else {
                acc += q;
            }
        }
        let e = e2[i];
        if e != 0 {
            let q = &gt.hi[usize::from(e.unsigned_abs() >> 1)];
            if e < 0 {
                acc -= q;
            } else {
                acc += q;
            }
        }
    }
    Some(acc)
}

#[cfg(test)]
mod tests {
    use super::*;

    use dcroxide_testutil::SplitMix64;
    use k256::FieldBytes;
    use k256::elliptic_curve::Field;
    use k256::elliptic_curve::bigint::{NonZero, U512};
    use k256::elliptic_curve::group::Group;
    use k256::elliptic_curve::ops::Reduce;
    use k256::elliptic_curve::point::DecompressPoint;
    use k256::elliptic_curve::subtle::Choice;

    use crate::secp256k1::GROUP_ORDER_BYTES;

    /// A scalar from big-endian hex below N.
    fn sc(h: &str) -> Scalar {
        Scalar::from_uint_unchecked(U256::from_be_hex(h))
    }

    /// A u128 as a scalar.
    fn sc128(v: u128) -> Scalar {
        Scalar::from_uint_unchecked(U256::from_u128(v))
    }

    /// A uniform scalar: 256 random bits reduced once.
    fn rand_scalar(rng: &mut SplitMix64) -> Scalar {
        let mut b = [0u8; 32];
        rng.fill(&mut b);
        <Scalar as Reduce<FieldBytes>>::reduce(&b.into())
    }

    /// A uniform nonzero scalar.
    fn rand_nonzero(rng: &mut SplitMix64) -> Scalar {
        loop {
            let s = rand_scalar(rng);
            if !bool::from(s.is_zero()) {
                return s;
            }
        }
    }

    /// A random u128.
    fn rand_u128(rng: &mut SplitMix64) -> u128 {
        (u128::from(rng.next_u64()) << 64) | u128::from(rng.next_u64())
    }

    /// N as an integer.
    fn order() -> U256 {
        U256::from_be_slice(&GROUP_ORDER_BYTES)
    }

    /// lambda, the eigenvalue of `endomorphism()`.
    fn lambda() -> Scalar {
        -Scalar::from_uint_unchecked(MINUS_LAMBDA)
    }

    /// 2^128 as a scalar.
    fn two128() -> Scalar {
        Scalar::from_uint_unchecked(U256::ONE.shl_vartime(128))
    }

    /// k*P by MSB-first double-and-add over k's bytes: no GLV, no wNAF, no
    /// table, so independent of everything this module and k256's combined
    /// pass share.
    fn naive(k: &Scalar, p: &ProjectivePoint) -> ProjectivePoint {
        let mut acc = ProjectivePoint::IDENTITY;
        for byte in k.to_bytes() {
            for bit in (0..8).rev() {
                acc = acc.double();
                if (byte >> bit) & 1 == 1 {
                    acc += p;
                }
            }
        }
        acc
    }

    /// The fast path, which must be taken.
    fn fast(a: &Scalar, b: &Scalar, p: &ProjectivePoint) -> ProjectivePoint {
        try_mul_g_add_vartime(a, b, p).expect("fast path: GLV halves below 2^128")
    }

    #[test]
    fn g_tables_match_k256() {
        let gt = g_tables();
        assert!(core::ptr::eq(gt, g_tables()), "one table, built once");
        assert_eq!(gt.lo.len(), G_TABLE_LEN);
        assert_eq!(gt.hi.len(), G_TABLE_LEN);

        let g = ProjectivePoint::GENERATOR;
        // 2^128*G by k256's scalar multiplication, not by the module's
        // doublings, so the two are compared.
        let g128 = g * two128();
        for (base, table) in [(g, &gt.lo), (g128, &gt.hi)] {
            let b2 = base.double();
            let mut chain = base;
            for (i, entry) in table.iter().enumerate() {
                let entry = ProjectivePoint::from(*entry);
                assert!(
                    !bool::from(entry.is_identity()),
                    "entry {i} is the identity"
                );
                let odd = Scalar::from(2 * i as u64 + 1);
                assert_eq!(entry, base * odd, "entry {i} against k256's multiple");
                assert_eq!(entry, chain, "entry {i} against the chain");
                chain += b2;
            }
        }
    }

    #[test]
    fn glv_constants_bind_to_k256() {
        let lam = lambda();
        let g = ProjectivePoint::GENERATOR;
        assert_eq!(g.endomorphism(), g * lam, "lambda is beta's eigenvalue");
        assert_eq!(lam * lam * lam, Scalar::ONE, "lambda^3 = 1");
        assert_ne!(lam, Scalar::ONE);

        // The lattice basis of libsecp256k1's scalar_impl.h: b1 = -MINUS_B1,
        // b2 = a1 = N - MINUS_B2.
        let a1 = sc("000000000000000000000000000000003086d221a7d46bcde86c90e49284eb15");
        let a2 = sc("0000000000000000000000000000000114ca50f7a8e2f3f657c1108d9d44cfd8");
        let b1 = -Scalar::from_uint_unchecked(MINUS_B1);
        let b2 = a1;
        assert_eq!(
            MINUS_B2.wrapping_add(&a1.retrieve()),
            order(),
            "b2 = N - MINUS_B2"
        );
        assert_eq!(a1 + b1 * lam, Scalar::ZERO, "a1 + b1*lambda = 0");
        assert_eq!(a2 + b2 * lam, Scalar::ZERO, "a2 + b2*lambda = 0");

        // g1 = round(2^384 * b2 / N) and g2 = round(2^384 * -b1 / N), with
        // round(x / N) = floor((x + (N-1)/2) / N) for odd N.
        let n: U512 = order().resize();
        let half_n = n.shr_vartime(1);
        let nz = NonZero::<U512>::new_unwrap(n);
        for (b, g_const) in [(b2.retrieve(), GLV_G1), (MINUS_B1, GLV_G2)] {
            let x: U512 = b.resize();
            let (q, _) = x.shl_vartime(384).wrapping_add(&half_n).div_rem(&nz);
            let want: U512 = g_const.resize();
            assert_eq!(q, want);
        }
    }

    /// k's GLV split by `glv_split`'s steps in unbounded integers (U512,
    /// where no product or sum wraps): c = (k*g >> 384) + bit 383 of k*g
    /// for g1 and g2, r2 = c1*(-b1) + c2*(-b2) mod N and r1 = k +
    /// r2*(-lambda) mod N.  It shares only the constants with the module,
    /// and `glv_constants_bind_to_k256` ties those to k256 and the lattice.
    fn glv_model(k: &Scalar) -> (Scalar, Scalar) {
        let n: U512 = order().resize();
        let nz = NonZero::<U512>::new_unwrap(n);
        let mod_n = |x: U512| x.div_rem(&nz).1;
        let wide = |x: U256| -> U512 { x.resize() };
        let k = wide(k.retrieve());
        let round = |g: U256| {
            let prod = k.wrapping_mul(&wide(g));
            prod.shr_vartime(384)
                .wrapping_add(&U512::from_u64(u64::from(prod.bit_vartime(383))))
        };
        let c1b1 = mod_n(round(GLV_G1).wrapping_mul(&wide(MINUS_B1)));
        let c2b2 = mod_n(round(GLV_G2).wrapping_mul(&wide(MINUS_B2)));
        let r2 = mod_n(c1b1.wrapping_add(&c2b2));
        let r1 = mod_n(k.wrapping_add(&mod_n(r2.wrapping_mul(&wide(MINUS_LAMBDA)))));
        let scalar = |x: U512| Scalar::from_uint_unchecked(x.resize());
        (scalar(r1), scalar(r2))
    }

    #[test]
    fn glv_split_identity_and_bound() {
        // Ten scalars: (N-1)/2, where |r1| peaks, (N+1)/2, 1, N-1, 2^127,
        // 2^128, N - 2^128, lambda, -lambda and one arbitrary scalar.
        // Each split is checked against the model and against literal
        // halves, so the split is checked step for step, not only for its
        // identity and bound.
        let pinned = [
            (
                "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
                "00000000000000000000000000000000a2a8918ca85bafe22016d0b917e4dd76",
                "fffffffffffffffffffffffffffffffe60d0868c82ab920e7c5e672a9418c46a",
            ),
            (
                "0000000000000000000000000000000100000000000000000000000000000000",
                "fffffffffffffffffffffffffffffffea5e48bef0665ac4568114dff32f17169",
                "fffffffffffffffffffffffffffffffe8a280ac50774346dd765cda83db1562c",
            ),
            (
                "ce17883dafff60e8a14c07134e57e9ebcc66b1ddad3095621e0eb27d3b1e8c2e",
                "fffffffffffffffffffffffffffffffe488d1d7baec15c2788281eb84ad65394",
                "fffffffffffffffffffffffffffffffe3049b46adad7264093f1d6460193da8c",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                "0000000000000000000000000000000000000000000000000000000000000001",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                "5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000001",
            ),
            (
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                "0000000000000000000000000000000080000000000000000000000000000000",
                "0000000000000000000000000000000080000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1",
                "fffffffffffffffffffffffffffffffe18064b5a06ecf0599fbb8dd3b85163cb",
                "0000000000000000000000000000000059de565a2c9d0e2d4373f7623c1d7cd7",
            ),
            (
                "fffffffffffffffffffffffffffffffdbaaedce6af48a03bbfd25e8cd0364141",
                "0000000000000000000000000000000014ca50f7a8e2f3f657c1108d9d44cfd8",
                "000000000000000000000000000000003086d221a7d46bcde86c90e49284eb15",
            ),
            (
                "ac9c52b33fa3cf1f5ad9e3fd77ed9ba4a880b9fc8ec739c2e0cfc810b51283cf",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
            ),
        ];
        for (k, r1, r2) in pinned {
            assert_eq!(glv_split(&sc(k)), glv_model(&sc(k)), "model split of {k}");
            assert_eq!(glv_split(&sc(k)), (sc(r1), sc(r2)), "pinned split of {k}");
        }

        let lam = lambda();
        let one = Scalar::ONE;
        let two = Scalar::from(2u64);
        let half = sc("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0");
        let t127 = sc128(1 << 127);
        let max128 = sc128(u128::MAX);
        let t128 = two128();
        let mut ks = vec![
            Scalar::ZERO,
            one,
            two,
            -one,
            -two,
            lam,
            -lam,
            lam + one,
            lam - one,
            half,
            half + one,
            half - one,
            half + two,
            t127,
            max128,
            t128,
            t128 + one,
            -t128,
            lam * max128,
            sc("ce17883dafff60e8a14c07134e57e9ebcc66b1ddad3095621e0eb27d3b1e8c2e"),
        ];
        let mut rng = SplitMix64::from_entropy("ecmult glv split");
        for _ in 0..4096 {
            // Lattice-corner style: halves near 2^128 with random signs.
            let mut r1 = sc128(rand_u128(&mut rng));
            let mut r2 = sc128(rand_u128(&mut rng));
            if rng.next_u64() & 1 == 1 {
                r1 = -r1;
            }
            if rng.next_u64() & 1 == 1 {
                r2 = -r2;
            }
            ks.push(r1 + r2 * lam);
            ks.push(rand_scalar(&mut rng));
        }
        for k in &ks {
            let (r1, r2) = glv_split(k);
            assert_eq!((r1, r2), glv_model(k), "model split of {:?}", k.to_bytes());
            assert_eq!(
                r1 + r2 * lam,
                *k,
                "r1 + r2*lambda = k for {:?}",
                k.to_bytes()
            );
            assert!(
                half128(r1).is_some(),
                "r1 below 2^128 for {:?}",
                k.to_bytes()
            );
            assert!(
                half128(r2).is_some(),
                "r2 below 2^128 for {:?}",
                k.to_bytes()
            );
        }
    }

    #[test]
    fn half128_rejects_wide_halves() {
        let max128 = sc128(u128::MAX);
        let t128 = two128();
        assert_eq!(half128(Scalar::ZERO), Some((0, false)));
        assert_eq!(half128(Scalar::ONE), Some((1, false)));
        assert_eq!(half128(-Scalar::ONE), Some((1, true)));
        assert_eq!(half128(max128), Some((u128::MAX, false)));
        assert_eq!(half128(-max128), Some((u128::MAX, true)));

        let t200 = Scalar::from_uint_unchecked(U256::ONE.shl_vartime(200));
        let half = sc("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0");
        for wide in [t128, -t128, t200, -t200, half, half + Scalar::ONE] {
            assert_eq!(half128(wide), None, "{:?}", wide.to_bytes());
        }
    }

    /// The edge scalars of the multiply tests.
    fn edge_scalars() -> Vec<Scalar> {
        let lam = lambda();
        let one = Scalar::ONE;
        let t128 = two128();
        let half = sc("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0");
        vec![
            Scalar::ZERO,
            one,
            Scalar::from(2u64),
            -one,
            -Scalar::from(2u64),
            lam,
            -lam,
            sc128(1 << 127),
            sc128(u128::MAX),
            t128,
            t128 + one,
            half,
            half + one,
            Scalar::from(2047u64),
            Scalar::from(2049u64),
            Scalar::from(2047u64) * t128,
            Scalar::from(4095u64) * t128,
            t128 * lam,
            sc("ce17883dafff60e8a14c07134e57e9ebcc66b1ddad3095621e0eb27d3b1e8c2e"),
        ]
    }

    #[test]
    fn mul_matches_k256_on_edges() {
        let g = ProjectivePoint::GENERATOR;
        let mut rng = SplitMix64(0x6563_6d75_6c74_0005);
        let key = g * rand_nonzero(&mut rng);
        let points = [
            (g, true),
            (-g, false),
            (g.endomorphism(), false),
            (g * two128(), false),
            (g * Scalar::from(2047u64), false),
            (key, true),
        ];
        let edges = edge_scalars();
        for (p, with_naive) in points {
            for a in &edges {
                for b in &edges {
                    let ours = fast(a, b, &p);
                    let combined = ProjectivePoint::mul_by_generator_and_mul_add_vartime(a, b, &p);
                    assert_eq!(ours, combined, "k256's combined pass");
                    assert_eq!(ours, g * a + p * b, "k256's lincomb");
                    if with_naive {
                        assert_eq!(ours, naive(a, &g) + naive(b, &p), "double-and-add");
                    }
                    assert_eq!(mul_g_add_vartime(a, b, &p), ours);
                }
            }
        }
    }

    #[test]
    fn mul_identity_and_doubling() {
        let g = ProjectivePoint::GENERATOR;
        let mut rng = SplitMix64(0x6563_6d75_6c74_0006);
        for _ in 0..32 {
            let k = rand_nonzero(&mut rng);
            let p = g * k;
            let b = rand_nonzero(&mut rng);
            // a*G = -b*P: the sum is the identity, where dcrd's
            // AddNonConst returns infinity.
            assert!(bool::from(fast(&(-(b * k)), &b, &p).is_identity()));
            // a*G = b*P: the sum is 2*a*G, where dcrd's AddNonConst
            // doubles.
            assert_eq!(fast(&(b * k), &b, &p), (g * (b * k)).double());
            // Schnorr's legal zeros.
            assert_eq!(fast(&Scalar::ZERO, &b, &p), p * b);
            assert_eq!(fast(&b, &Scalar::ZERO, &p), g * b);
            assert!(bool::from(
                fast(&Scalar::ZERO, &Scalar::ZERO, &p).is_identity()
            ));
        }
        // P = identity, which no call site passes: still total.
        let id = ProjectivePoint::IDENTITY;
        let a = rand_nonzero(&mut rng);
        assert_eq!(fast(&a, &a, &id), g * a);
    }

    #[test]
    fn mul_matches_k256_seeded() {
        let g = ProjectivePoint::GENERATOR;
        let mut rng = SplitMix64::from_entropy("ecmult seeded");
        for i in 0..1024 {
            let (a, b, p) = match i % 4 {
                // Verification: u1 = e/s, u2 = r/s, a key Q.
                0 => {
                    let w = rand_nonzero(&mut rng).invert_vartime().unwrap();
                    let e = rand_scalar(&mut rng);
                    let r = rand_nonzero(&mut rng);
                    (e * w, r * w, g * rand_nonzero(&mut rng))
                }
                // Recovery: u1 = -(e/r), u2 = s/r, X decompressed from a
                // random x that has a root.
                1 => {
                    let w = rand_nonzero(&mut rng).invert_vartime().unwrap();
                    let e = rand_scalar(&mut rng);
                    let s = rand_nonzero(&mut rng);
                    let x = loop {
                        let mut xb = [0u8; 32];
                        rng.fill(&mut xb);
                        let odd = Choice::from((rng.next_u64() & 1) as u8);
                        if let Some(x) =
                            Option::<AffinePoint>::from(AffinePoint::decompress(&xb.into(), odd))
                        {
                            break x;
                        }
                    };
                    (-(e * w), s * w, ProjectivePoint::from(x))
                }
                // Schnorr: a = s, zero one time in eight; b = e.
                2 => {
                    let s = if rng.next_u64().is_multiple_of(8) {
                        Scalar::ZERO
                    } else {
                        rand_scalar(&mut rng)
                    };
                    (s, rand_scalar(&mut rng), g * rand_nonzero(&mut rng))
                }
                // Uniform.
                _ => (
                    rand_scalar(&mut rng),
                    rand_scalar(&mut rng),
                    g * rand_nonzero(&mut rng),
                ),
            };
            assert_eq!(
                fast(&a, &b, &p),
                ProjectivePoint::mul_by_generator_and_mul_add_vartime(&a, &b, &p),
                "case {i}: a {:?} b {:?}",
                a.to_bytes(),
                b.to_bytes()
            );
        }
    }

    /// Checks one wNAF against every property `wnaf128` promises.
    fn check_wnaf(k: u128, w: u32) {
        let (out, len) = wnaf128(k, w);
        let max = (1i32 << (w - 1)) - 1;
        let mut sum = Scalar::ZERO;
        let mut prev: Option<usize> = None;
        let mut top = 0;
        for (i, &d) in out.iter().enumerate().rev() {
            sum = sum.double();
            if d == 0 {
                continue;
            }
            let m = i32::from(d).abs();
            assert!(m % 2 == 1 && m <= max, "k {k:#x} w {w}: digit {d} at {i}");
            if d < 0 {
                sum -= Scalar::from(m as u64);
            } else {
                sum += Scalar::from(m as u64);
            }
            if let Some(p) = prev {
                assert!(p - i >= w as usize, "k {k:#x} w {w}: digits at {p} and {i}");
            } else {
                top = i + 1;
            }
            prev = Some(i);
        }
        assert_eq!(sum, sc128(k), "k {k:#x} w {w}: digits sum to k");
        assert_eq!(len, top, "k {k:#x} w {w}: length");
    }

    #[test]
    fn wnaf128_properties() {
        let mut fixed = vec![
            0,
            1,
            2,
            3,
            u128::MAX,
            1 << 127,
            (1 << 127) - 1,
            0x5555_5555_5555_5555_5555_5555_5555_5555,
            0xaaaa_aaaa_aaaa_aaaa_aaaa_aaaa_aaaa_aaaa,
        ];
        // Runs of w-1, w and w+1 ones ending at bit 127, for w = 5 and 12:
        // the w-1 run fills the top window exactly, and the w and w+1 runs
        // carry to position 128.
        for w in [5u32, 12] {
            for run in [w - 1, w, w + 1] {
                fixed.push(u128::MAX << (128 - run));
            }
        }
        for w in 2..=16 {
            for &k in &fixed {
                check_wnaf(k, w);
            }
        }
        let mut rng = SplitMix64(0x6563_6d75_6c74_0008);
        for _ in 0..4096 {
            let k = rand_u128(&mut rng);
            check_wnaf(k, W_Q);
            check_wnaf(k, W_G);
        }
    }
}
