// SPDX-License-Identifier: ISC
//! The crate's tests, against references of different origin from the
//! port:
//!
//! - a schoolbook multiplication and fold mod p and N, and limb helpers,
//!   over u64 words written here, independent of libsecp256k1 and k256;
//! - crypto-bigint's modular arithmetic on `U256` and `U512`;
//! - k256's `Scalar`, field element and decompression (RustCrypto),
//!   through big-endian bytes;
//! - fiat-crypto's Dettman multiplication and squaring, limb for limb;
//! - k256's point arithmetic, its combined multiply and its `lincomb`;
//! - an affine reference over the schoolbook words, and index arithmetic
//!   on libsecp256k1's small test curves (`points.rs`, `group_tests.rs`);
//! - libsecp256k1's own fixed vectors (`vectors.rs`), tests and ecmult
//!   known-answer hashes, and dcrd's decompression and Jacobian vectors
//!   (`dcrd_vectors.rs`).
//!
//! Inputs come from `dcroxide_testutil::SplitMix64` with fixed seeds, so
//! every run computes the same values and the digest tests can pin them.
//! Volume: `DCROXIDE_VARTIME_CASES` (`cases()`), by default 20,000 in
//! builds with debug assertions, which keeps the dev suite to a few
//! seconds, and 10^6 without, as CI's release run of the crate builds
//! them; CI's soak-asserts run sets 10^6, so the invariant checks see the
//! full volume too.  The scalar tests run that many cases per operation;
//! the field, decompression, group and multiply tests, whose references
//! cost more, a tenth of it or less.  At 10^6 the heavy tests run in full
//! (the field's corner products, the order-199 formulas and Straus loop,
//! the collision grid at [-3, 3], libsecp256k1's ecmult hashes, the
//! affine conversion on boundary points); below it they run a subset
//! their docs name.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "test arithmetic on reference values: indices, counters and \
              bigint helpers whose bounds the tests themselves fix"
)]

pub(crate) mod branches;
mod dcrd_vectors;
mod decompress_tests;
mod ecmult_tests;
mod field_tests;
mod glv_tests;
mod group_tests;
mod points;
mod scalar_tests;
mod table_gen;
mod tables;
mod vectors;

use crypto_bigint::{NonZero, U256, U512};
use dcroxide_testutil::SplitMix64;
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::hazmat::FieldArithmetic;

use crate::field::Fe;

/// Random cases per operation (`DCROXIDE_VARTIME_CASES`, or the default
/// for the build's assertions).
pub(crate) fn cases() -> u64 {
    std::env::var("DCROXIDE_VARTIME_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(if cfg!(debug_assertions) {
            20_000
        } else {
            1_000_000
        })
}

/// Four random words.
pub(crate) fn words(r: &mut SplitMix64) -> [u64; 4] {
    [r.next_u64(), r.next_u64(), r.next_u64(), r.next_u64()]
}

/// 256-bit words with structure: runs of zero or one bits, small or
/// near-2^256 values, single bits set or clear, sparse words, as
/// libsecp256k1's `testrand256_test` aims for.
pub(crate) fn words_structured(r: &mut SplitMix64) -> [u64; 4] {
    let mut w = [0u64; 4];
    match r.below(6) {
        0 => w[0] = r.below(1 << 20),
        1 => w = [u64::MAX - r.below(1 << 20), u64::MAX, u64::MAX, u64::MAX],
        2 => {
            for x in &mut w {
                *x = match r.below(3) {
                    0 => 0,
                    1 => u64::MAX,
                    _ => r.next_u64(),
                };
            }
        }
        3 => {
            let b = r.below(256) as usize;
            w[b / 64] = 1u64 << (b % 64);
        }
        4 => {
            let b = r.below(256) as usize;
            w = [u64::MAX; 4];
            w[b / 64] ^= 1u64 << (b % 64);
        }
        _ => {
            for x in &mut w {
                *x = r.next_u64() & r.next_u64() & r.next_u64();
            }
        }
    }
    w
}

// ---------------------------------------------------------------------------
// Word helpers (little-endian u64 words).

/// N's words, written out here rather than taken from the port.
pub(crate) const NORD: [u64; 4] = [
    0xBFD2_5E8C_D036_4141,
    0xBAAE_DCE6_AF48_A03B,
    0xFFFF_FFFF_FFFF_FFFE,
    0xFFFF_FFFF_FFFF_FFFF,
];

/// p's words, written out here rather than taken from the port.
pub(crate) const P: [u64; 4] = [0xFFFF_FFFE_FFFF_FC2F, u64::MAX, u64::MAX, u64::MAX];

/// a >= b.
pub(crate) fn ge4(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

/// a - b mod 2^256.
pub(crate) fn sub4(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut r = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d, o1) = a[i].overflowing_sub(b[i]);
        let (d, o2) = d.overflowing_sub(borrow);
        r[i] = d;
        borrow = u64::from(o1 | o2);
    }
    r
}

/// The schoolbook 512-bit product.
pub(crate) fn mulw(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let mut r = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let s = u128::from(r[i + j]) + u128::from(a[i]) * u128::from(b[j]) + carry;
            r[i + j] = s as u64;
            carry = s >> 64;
        }
        r[i + 4] = carry as u64;
    }
    r
}

/// sum l\[i\] << 52i (up to about 2^262) as six words.
pub(crate) fn limbs_to_int(l: &[u64; 5]) -> [u64; 6] {
    let mut r = [0u64; 6];
    for (i, &li) in l.iter().enumerate() {
        let sh = 52 * i;
        let (w, b) = (sh / 64, sh % 64);
        let v = u128::from(li) << b;
        let mut carry = 0u128;
        for (k, part) in [v as u64, (v >> 64) as u64].into_iter().enumerate() {
            let s = u128::from(r[w + k]) + u128::from(part) + carry;
            r[w + k] = s as u64;
            carry = s >> 64;
        }
        let mut k = w + 2;
        while carry != 0 {
            let s = u128::from(r[k]) + carry;
            r[k] = s as u64;
            carry = s >> 64;
            k += 1;
        }
    }
    r
}

/// Words mod p, by folding 2^256 = 0x1000003D1 and then subtracting p.
pub(crate) fn reduce_p<const W: usize>(v: &[u64; W]) -> [u64; 4] {
    let mut v = *v;
    loop {
        if v[4..].iter().all(|&x| x == 0) {
            break;
        }
        let mut lo = [0u64; W];
        lo[..4].copy_from_slice(&v[..4]);
        let mut carry = 0u128;
        for (i, x) in lo.iter_mut().enumerate() {
            let h = if i + 4 < W { v[i + 4] } else { 0 };
            let s = u128::from(*x) + u128::from(h) * 0x1_0000_03D1 + carry;
            *x = s as u64;
            carry = s >> 64;
        }
        assert_eq!(carry, 0);
        v = lo;
    }
    let mut r = [v[0], v[1], v[2], v[3]];
    while ge4(&r, &P) {
        r = sub4(&r, &P);
    }
    r
}

/// a * b mod p.
pub(crate) fn mul_p(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    reduce_p(&mulw(a, b))
}

/// a + b mod p.
pub(crate) fn add_p(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut r = [0u64; 5];
    let mut c = 0u128;
    for i in 0..4 {
        let s = u128::from(a[i]) + u128::from(b[i]) + c;
        r[i] = s as u64;
        c = s >> 64;
    }
    r[4] = c as u64;
    reduce_p(&r)
}

/// -a mod p.
pub(crate) fn neg_p(a: &[u64; 4]) -> [u64; 4] {
    let a = reduce_p(a);
    if a == [0; 4] { a } else { sub4(&P, &a) }
}

/// a - b mod p.
pub(crate) fn sub_p(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    add_p(a, &neg_p(b))
}

/// The canonical value of a field element's limbs, by the reference.
pub(crate) fn fe_val(a: &Fe) -> [u64; 4] {
    reduce_p(&limbs_to_int(&a.raw().n))
}

/// A field element from words below p: normalized, magnitude 1.
pub(crate) fn fe_w(w: &[u64; 4]) -> Fe {
    Fe::set_b32_limit(&words_to_be(w)).expect("below p")
}

/// A normalized copy.
pub(crate) fn norm(f: &Fe) -> Fe {
    let mut t = *f;
    t.normalize_var();
    t
}

/// Canonical big-endian bytes of any field element.
pub(crate) fn fe_bytes(f: &Fe) -> [u8; 32] {
    norm(f).get_b32()
}

/// Random words below p, uniform or, every fourth call, structured.
pub(crate) fn words_below_p(r: &mut SplitMix64) -> [u64; 4] {
    loop {
        let w = if r.below(4) == 0 {
            words_structured(r)
        } else {
            words(r)
        };
        if !ge4(&w, &P) {
            return w;
        }
    }
}

/// Words to 32 big-endian bytes.
pub(crate) fn words_to_be(w: &[u64; 4]) -> [u8; 32] {
    let mut b = [0u8; 32];
    for i in 0..4 {
        b[(3 - i) * 8..(4 - i) * 8].copy_from_slice(&w[i].to_be_bytes());
    }
    b
}

/// 32 big-endian bytes to words.
pub(crate) fn be_to_words(b: &[u8; 32]) -> [u64; 4] {
    let mut w = [0u64; 4];
    for i in 0..4 {
        let mut x = [0u8; 8];
        x.copy_from_slice(&b[(3 - i) * 8..(4 - i) * 8]);
        w[i] = u64::from_be_bytes(x);
    }
    w
}

/// 64 hex digits as 32 bytes.
pub(crate) fn hex32(h: &str) -> [u8; 32] {
    dcroxide_testutil::unhex(h)
        .try_into()
        .expect("64 hex digits")
}

// ---------------------------------------------------------------------------
// crypto-bigint

// Through big-endian bytes, so the helpers do not depend on crypto-bigint's
// word width, which is 32 bits on 32-bit targets.

pub(crate) fn cb(w: &[u64; 4]) -> U256 {
    U256::from_be_slice(&words_to_be(w))
}
pub(crate) fn cbw(x: &U256) -> [u64; 4] {
    let b: [u8; 32] = x.to_be_bytes().as_ref().try_into().expect("32 bytes");
    be_to_words(&b)
}
pub(crate) fn cb_n() -> NonZero<U256> {
    NonZero::<U256>::new_unwrap(cb(&NORD))
}
pub(crate) fn cb_p() -> NonZero<U256> {
    NonZero::<U256>::new_unwrap(cb(&P))
}
pub(crate) fn cb512(w: &[u64; 8]) -> U512 {
    let mut b = [0u8; 64];
    for (i, x) in w.iter().enumerate() {
        b[(7 - i) * 8..(8 - i) * 8].copy_from_slice(&x.to_be_bytes());
    }
    U512::from_be_slice(&b)
}

// ---------------------------------------------------------------------------
// k256

pub(crate) fn ksc(w: &[u64; 4]) -> k256::Scalar {
    Option::from(k256::Scalar::from_repr(words_to_be(w).into())).expect("canonical scalar")
}
pub(crate) fn ksc_w(x: &k256::Scalar) -> [u64; 4] {
    be_to_words(&x.to_repr().into())
}

/// k256's field element.
pub(crate) type KFe = <k256::Secp256k1 as FieldArithmetic>::FieldElement;

pub(crate) fn kfe(w: &[u64; 4]) -> KFe {
    Option::from(KFe::from_repr(words_to_be(w).into())).expect("canonical field element")
}
pub(crate) fn kfe_w(x: &KFe) -> [u64; 4] {
    be_to_words(&x.to_repr().into())
}

/// A point's coordinates, big-endian.
pub(crate) type Bytes2 = ([u8; 32], [u8; 32]);

/// k256's decompression.
pub(crate) fn k_decompress(x: &[u8; 32], odd: bool) -> Option<Bytes2> {
    use k256::AffinePoint;
    use k256::elliptic_curve::point::{AffineCoordinates, DecompressPoint};
    use k256::elliptic_curve::subtle::Choice;
    let a: Option<AffinePoint> =
        AffinePoint::decompress(&(*x).into(), Choice::from(u8::from(odd))).into();
    a.map(|a| (a.x().into(), a.y().into()))
}
