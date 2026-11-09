// SPDX-License-Identifier: ISC
//! The crate's tests, against references of different origin from the
//! port:
//!
//! - a schoolbook multiplication and limb helpers over u64 words written
//!   here, independent of libsecp256k1 and k256;
//! - crypto-bigint's modular arithmetic on `U256` and `U512`;
//! - k256's `Scalar` (RustCrypto), through big-endian bytes;
//! - libsecp256k1's own fixed vectors (`vectors.rs`).
//!
//! Inputs come from `dcroxide_testutil::SplitMix64` with fixed seeds, so
//! every run computes the same values and the digest test can pin them.
//! Volume: `DCROXIDE_VARTIME_CASES` random cases per operation, by default
//! 20,000 in builds with debug assertions, which keeps the dev suite to a
//! few seconds, and 10^6 without, as CI's release run of the crate builds
//! them; CI's soak-asserts run sets 10^6, so the invariant checks see the
//! full volume too.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "test arithmetic on reference values: indices, counters and \
              bigint helpers whose bounds the tests themselves fix"
)]

mod scalar_tests;
mod vectors;

use crypto_bigint::{NonZero, U256, U512};
use dcroxide_testutil::SplitMix64;
use k256::elliptic_curve::PrimeField;

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
