// SPDX-License-Identifier: ISC AND MIT
//
// Derived from libsecp256k1 src/field_5x52_int128_impl.h
// (Copyright (c) 2013, 2014 Pieter Wuille), as vendored by secp256k1-sys
// 0.14.1.  MIT; see NOTICE.
//
//! The 5x52 multiplication and squaring kernels, a literal port of
//! `secp256k1_fe_mul_inner` and `secp256k1_fe_sqr_inner`
//! (field_5x52_int128_impl.h:18-152, :154-272) with native u128 in place of
//! int128_native_impl.h.  The bracket comments are the C's, verbatim; each
//! `VERIFY_BITS` is a `debug_assert!`.

/// 2^52 - 1.
const M: u64 = 0xF_FFFF_FFFF_FFFF;
/// 2^256 mod p, shifted left by 4 (0x1000003D1 << 4), as the C's `R`.
const R: u64 = 0x10_0000_3D10;

/// `VERIFY_BITS(x, n)`: x < 2^n (field_5x52_int128_impl.h:15).
macro_rules! vb {
    ($x:expr, $n:expr) => {
        debug_assert!(($x) >> ($n) == 0, "VERIFY_BITS({}, {})", stringify!($x), $n)
    };
}

/// r = a * b mod p (not normalized).  Inputs: limbs 0..3 < 2^56, limb 4 <
/// 2^52 (magnitude <= 8).  Output: limbs 0..3 < 2^52, limb 4 < 2^49
/// (field_5x52_int128_impl.h:18-152).
#[inline(always)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "libsecp's bounds (field_5x52_int128_impl.h:24-150): inputs \
              limbs < 2^56 (top < 2^52), so d < 2^116 and c < 2^115 at every \
              step and r[4] < 2^49; no u64 or u128 operation overflows"
)]
pub(crate) fn mul_inner(a: &[u64; 5], b: &[u64; 5]) -> [u64; 5] {
    let (a0, a1, a2, a3, a4) = (a[0], a[1], a[2], a[3], a[4]);
    let mut r = [0u64; 5];
    let mut c: u128;
    let mut d: u128;

    vb!(a[0], 56);
    vb!(a[1], 56);
    vb!(a[2], 56);
    vb!(a[3], 56);
    vb!(a[4], 52);
    vb!(b[0], 56);
    vb!(b[1], 56);
    vb!(b[2], 56);
    vb!(b[3], 56);
    vb!(b[4], 52);

    //  [... a b c] is a shorthand for ... + a<<104 + b<<52 + c<<0 mod n.
    //  for 0 <= x <= 4, px is a shorthand for sum(a[i]*b[x-i], i=0..x).
    //  for 4 <= x <= 8, px is a shorthand for sum(a[i]*b[x-i], i=(x-4)..4)
    //  Note that [x 0 0 0 0 0] = [x*R].

    d = a0 as u128 * b[3] as u128;
    d += a1 as u128 * b[2] as u128;
    d += a2 as u128 * b[1] as u128;
    d += a3 as u128 * b[0] as u128;
    vb!(d, 114);
    // [d 0 0 0] = [p3 0 0 0]
    c = a4 as u128 * b[4] as u128;
    vb!(c, 112);
    // [c 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0]
    d += R as u128 * (c as u64) as u128;
    c >>= 64;
    vb!(d, 115);
    vb!(c, 48);
    // [(c<<12) 0 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0]
    let t3 = (d as u64) & M;
    d >>= 52;
    vb!(t3, 52);
    vb!(d, 63);
    // [(c<<12) 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 0 p3 0 0 0]

    d += a0 as u128 * b[4] as u128;
    d += a1 as u128 * b[3] as u128;
    d += a2 as u128 * b[2] as u128;
    d += a3 as u128 * b[1] as u128;
    d += a4 as u128 * b[0] as u128;
    vb!(d, 115);
    // [(c<<12) 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0]
    d += (R << 12) as u128 * (c as u64) as u128;
    vb!(d, 116);
    // [d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0]
    let mut t4 = (d as u64) & M;
    d >>= 52;
    vb!(t4, 52);
    vb!(d, 64);
    // [d t4 t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0]
    let tx = t4 >> 48;
    t4 &= M >> 4;
    vb!(tx, 4);
    vb!(t4, 48);
    // [d t4+(tx<<48) t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0]

    c = a0 as u128 * b[0] as u128;
    vb!(c, 112);
    // [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 0 p4 p3 0 0 p0]
    d += a1 as u128 * b[4] as u128;
    d += a2 as u128 * b[3] as u128;
    d += a3 as u128 * b[2] as u128;
    d += a4 as u128 * b[1] as u128;
    vb!(d, 114);
    // [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0]
    let mut u0 = (d as u64) & M;
    d >>= 52;
    vb!(u0, 52);
    vb!(d, 62);
    // [d u0 t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0]
    // [d 0 t4+(tx<<48)+(u0<<52) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0]
    u0 = (u0 << 4) | tx;
    vb!(u0, 56);
    // [d 0 t4+(u0<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0]
    c += u0 as u128 * (R >> 4) as u128;
    vb!(c, 113);
    // [d 0 t4 t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0]
    r[0] = (c as u64) & M;
    c >>= 52;
    vb!(r[0], 52);
    vb!(c, 61);
    // [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 0 p0]

    c += a0 as u128 * b[1] as u128;
    c += a1 as u128 * b[0] as u128;
    vb!(c, 114);
    // [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 p1 p0]
    d += a2 as u128 * b[4] as u128;
    d += a3 as u128 * b[3] as u128;
    d += a4 as u128 * b[2] as u128;
    vb!(d, 114);
    // [d 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0]
    c += ((d as u64) & M) as u128 * R as u128;
    d >>= 52;
    vb!(c, 115);
    vb!(d, 62);
    // [d 0 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0]
    r[1] = (c as u64) & M;
    c >>= 52;
    vb!(r[1], 52);
    vb!(c, 63);
    // [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 0 p1 p0]

    c += a0 as u128 * b[2] as u128;
    c += a1 as u128 * b[1] as u128;
    c += a2 as u128 * b[0] as u128;
    vb!(c, 114);
    // [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 p2 p1 p0]
    d += a3 as u128 * b[4] as u128;
    d += a4 as u128 * b[3] as u128;
    vb!(d, 114);
    // [d 0 0 t4 t3 c t1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
    c += R as u128 * (d as u64) as u128;
    d >>= 64;
    vb!(c, 115);
    vb!(d, 50);
    // [(d<<12) 0 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]

    r[2] = (c as u64) & M;
    c >>= 52;
    vb!(r[2], 52);
    vb!(c, 63);
    // [(d<<12) 0 0 0 t4 t3+c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
    c += (R << 12) as u128 * (d as u64) as u128;
    c += t3 as u128;
    vb!(c, 100);
    // [t4 c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
    r[3] = (c as u64) & M;
    c >>= 52;
    vb!(r[3], 52);
    vb!(c, 48);
    // [t4+c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
    r[4] = (c as u64) + t4;
    vb!(r[4], 49);
    // [r4 r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
    r
}

/// r = a^2 mod p (not normalized); same bounds as [`mul_inner`]
/// (field_5x52_int128_impl.h:154-272).
#[inline(always)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "libsecp's bounds (field_5x52_int128_impl.h:160-270): input \
              limbs < 2^56 (top < 2^52), doubled limbs < 2^57, so d < 2^116 \
              and c < 2^115 at every step; no u64 or u128 operation overflows"
)]
pub(crate) fn sqr_inner(a: &[u64; 5]) -> [u64; 5] {
    let (mut a0, a1, a2, a3, mut a4) = (a[0], a[1], a[2], a[3], a[4]);
    let mut r = [0u64; 5];
    let mut c: u128;
    let mut d: u128;

    vb!(a[0], 56);
    vb!(a[1], 56);
    vb!(a[2], 56);
    vb!(a[3], 56);
    vb!(a[4], 52);

    //  [... a b c] is a shorthand for ... + a<<104 + b<<52 + c<<0 mod n.
    //  px is a shorthand for sum(a[i]*a[x-i], i=0..x).
    //  Note that [x 0 0 0 0 0] = [x*R].

    d = (a0 * 2) as u128 * a3 as u128;
    d += (a1 * 2) as u128 * a2 as u128;
    vb!(d, 114);
    // [d 0 0 0] = [p3 0 0 0]
    c = a4 as u128 * a4 as u128;
    vb!(c, 112);
    // [c 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0]
    d += R as u128 * (c as u64) as u128;
    c >>= 64;
    vb!(d, 115);
    vb!(c, 48);
    // [(c<<12) 0 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0]
    let t3 = (d as u64) & M;
    d >>= 52;
    vb!(t3, 52);
    vb!(d, 63);
    // [(c<<12) 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 0 p3 0 0 0]

    a4 *= 2;
    d += a0 as u128 * a4 as u128;
    d += (a1 * 2) as u128 * a3 as u128;
    d += a2 as u128 * a2 as u128;
    vb!(d, 115);
    // [(c<<12) 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0]
    d += (R << 12) as u128 * (c as u64) as u128;
    vb!(d, 116);
    // [d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0]
    let mut t4 = (d as u64) & M;
    d >>= 52;
    vb!(t4, 52);
    vb!(d, 64);
    // [d t4 t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0]
    let tx = t4 >> 48;
    t4 &= M >> 4;
    vb!(tx, 4);
    vb!(t4, 48);
    // [d t4+(tx<<48) t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0]

    c = a0 as u128 * a0 as u128;
    vb!(c, 112);
    // [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 0 p4 p3 0 0 p0]
    d += a1 as u128 * a4 as u128;
    d += (a2 * 2) as u128 * a3 as u128;
    vb!(d, 114);
    // [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0]
    let mut u0 = (d as u64) & M;
    d >>= 52;
    vb!(u0, 52);
    vb!(d, 62);
    // [d u0 t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0]
    // [d 0 t4+(tx<<48)+(u0<<52) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0]
    u0 = (u0 << 4) | tx;
    vb!(u0, 56);
    // [d 0 t4+(u0<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0]
    c += u0 as u128 * (R >> 4) as u128;
    vb!(c, 113);
    // [d 0 t4 t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0]
    r[0] = (c as u64) & M;
    c >>= 52;
    vb!(r[0], 52);
    vb!(c, 61);
    // [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 0 p0]

    a0 *= 2;
    c += a0 as u128 * a1 as u128;
    vb!(c, 114);
    // [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 p1 p0]
    d += a2 as u128 * a4 as u128;
    d += a3 as u128 * a3 as u128;
    vb!(d, 114);
    // [d 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0]
    c += ((d as u64) & M) as u128 * R as u128;
    d >>= 52;
    vb!(c, 115);
    vb!(d, 62);
    // [d 0 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0]
    r[1] = (c as u64) & M;
    c >>= 52;
    vb!(r[1], 52);
    vb!(c, 63);
    // [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 0 p1 p0]

    c += a0 as u128 * a2 as u128;
    c += a1 as u128 * a1 as u128;
    vb!(c, 114);
    // [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 p2 p1 p0]
    d += a3 as u128 * a4 as u128;
    vb!(d, 114);
    // [d 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
    c += R as u128 * (d as u64) as u128;
    d >>= 64;
    vb!(c, 115);
    vb!(d, 50);
    // [(d<<12) 0 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
    r[2] = (c as u64) & M;
    c >>= 52;
    vb!(r[2], 52);
    vb!(c, 63);
    // [(d<<12) 0 0 0 t4 t3+c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]

    c += (R << 12) as u128 * (d as u64) as u128;
    c += t3 as u128;
    vb!(c, 100);
    // [t4 c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
    r[3] = (c as u64) & M;
    c >>= 52;
    vb!(r[3], 52);
    vb!(c, 48);
    // [t4+c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
    r[4] = (c as u64) + t4;
    vb!(r[4], 49);
    // [r4 r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
    r
}
