// SPDX-License-Identifier: ISC
//! The generators, and the helpers they share: drawing values with bounded
//! retries, keys and honest signatures on this crate's own `k256`
//! arithmetic, the four ECDSA key presentations, minimal DER, and the
//! integer index arithmetic that picks a case's stratum and presentation.
//!
//! Nothing here calls the code under test.  Honest signatures take a
//! random nonce from the entropy, never RFC6979 and never dcroxide's
//! signer, so the inputs cannot change when the signer is rewritten.
//!
//! Every retry loop is bounded ([`Draw::retry`]), so a generator driven by
//! an exhausted [`crate::entropy::ByteEntropy`] (all zeros) still returns.
//! A loop that runs out substitutes a fixed fallback (the scalar one, the
//! generator, x = 1) and marks the draw; [`Draw::finish`] then labels the
//! case `fallback`, with every intent [`Intent::Any`] and the
//! [`Tag::Fallback`] tag, which the run counts apart and leaves out of
//! every mix.  With SplitMix64 the fallback is unreachable in practice.

pub mod der;
pub mod ecdsa;
pub mod kwrap_points;
pub mod pubkey;

use std::borrow::Cow;

use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::group::Group;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::point::{AffineCoordinates, DecompressPoint};
use k256::elliptic_curve::scalar::IsHigh;
use k256::elliptic_curve::subtle::Choice;
use k256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};

use crate::arith::{self, HALF_N, N};
use crate::class::{Case, Consistency, Intent, Mix, Tag, Tags};
use crate::cmd::{self, Request};
use crate::entropy::Entropy;

/// The tier-A floor: parse classes, and verify classes whose inputs are
/// drawn or edited.
pub const FLOOR_A: u64 = 10_000_000;

/// The tier-B floor: sign classes, and every class that solves for a key
/// or signature to reach a named branch.
pub const FLOOR_B: u64 = 1_000_000;

/// The per-PR case count of a class that names no other: every stratum of
/// a class with at most 48, and every (stratum, presentation) pair of the
/// EV classes.
pub const PR_CASES: u64 = 48;

/// Cases a class completes before its statistical mix is evaluated.
pub const MIX_MIN_N: u64 = 100_000;

/// The mix of a class whose every case dcrd accepts.
pub const ALL_ACCEPTED: &[Mix] = &[Mix::AcceptRate {
    lo: 1.0,
    hi: 1.0,
    min_n: MIX_MIN_N,
}];

/// The mix of a class whose every case dcrd rejects.
pub const NONE_ACCEPTED: &[Mix] = &[Mix::AcceptRate {
    lo: 0.0,
    hi: 0.0,
    min_n: MIX_MIN_N,
}];

/// Draws for a value that must decompress: the odds of 256 misses are
/// about 2^-256.
pub const DECOMPRESS_TRIES: u32 = 256;

/// Draws for a nonzero scalar, and for any other retry whose miss has odds
/// of 2^-127 or less.
pub const SCALAR_TRIES: u32 = 64;

/// A generator's entropy, with the bounded retries every construction
/// uses.
pub struct Draw<'a> {
    e: &'a mut dyn Entropy,
    fell_back: bool,
}

impl<'a> Draw<'a> {
    /// Draws from `e`.
    pub fn new(e: &'a mut dyn Entropy) -> Self {
        Draw {
            e,
            fell_back: false,
        }
    }

    /// The next 64 bits.
    pub fn next_u64(&mut self) -> u64 {
        self.e.next_u64()
    }

    /// A value in `0..n`; `n` must be nonzero.
    pub fn below(&mut self, n: u64) -> u64 {
        self.e.below(n)
    }

    /// A fair coin.
    pub fn coin(&mut self) -> bool {
        self.e.coin()
    }

    /// One byte: the low byte of the next word.
    pub fn byte(&mut self) -> u8 {
        self.e.next_u64().to_le_bytes()[0]
    }

    /// A nonzero byte, uniform over the other 255 values when xored onto a
    /// byte: `1 + below(255)`.
    pub fn nonzero_byte(&mut self) -> u8 {
        u8::try_from(self.e.below(255)).map_or(1, |b| b.saturating_add(1))
    }

    /// 32 bytes.
    pub fn bytes32(&mut self) -> [u8; 32] {
        self.e.bytes32()
    }

    /// `len` bytes.
    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        self.e.fill(&mut out);
        out
    }

    /// A length in `lo..=hi`.
    pub fn len_in(&mut self, lo: usize, hi: usize) -> usize {
        let span = u64::try_from(hi.saturating_sub(lo)).map_or(u64::MAX, |s| s.saturating_add(1));
        lo.saturating_add(usize::try_from(self.e.below(span)).unwrap_or(0))
    }

    /// The first value `attempt` returns within `tries` attempts, or
    /// `fallback()` with the draw marked as fallen back.
    pub fn retry<T>(
        &mut self,
        tries: u32,
        fallback: impl FnOnce() -> T,
        mut attempt: impl FnMut(&mut Self) -> Option<T>,
    ) -> T {
        for _ in 0..tries {
            if let Some(value) = attempt(self) {
                return value;
            }
        }
        self.fell_back = true;
        fallback()
    }

    /// Whether a retry ran out.
    pub fn fell_back(&self) -> bool {
        self.fell_back
    }

    /// A uniform value in `[0, bound)`, `bound` nonzero and big-endian:
    /// random bits masked to the bit length of `bound`, rejected until
    /// below it (each draw passes with odds above one half).  Falls back to
    /// zero.
    pub fn uniform_below(&mut self, bound: &[u8; 32]) -> [u8; 32] {
        let Some(top) = bound.iter().position(|&b| b != 0) else {
            panic!("uniform_below: a zero bound");
        };
        let mask = u8::MAX >> bound[top].leading_zeros();
        self.retry(
            DECOMPRESS_TRIES,
            || [0; 32],
            |d| {
                let mut v = d.bytes32();
                v[..top].fill(0);
                v[top] &= mask;
                (v < *bound).then_some(v)
            },
        )
    }

    /// A uniform value in `[lo, hi]`, big-endian, `lo <= hi`, not the
    /// whole 256-bit range.
    pub fn uniform_in(&mut self, lo: &[u8; 32], hi: &[u8; 32]) -> [u8; 32] {
        let (span, borrow) = arith::sub_be(hi, lo);
        assert!(!borrow, "uniform_in: lo above hi");
        let (count, carry) = arith::add_be(&span, &arith::be_from_u64(1));
        assert!(!carry, "uniform_in: the whole 256-bit range");
        arith::add_be(lo, &self.uniform_below(&count)).0
    }

    /// A private key: 32 random bytes until they are a nonzero scalar below
    /// N.  Falls back to one.
    pub fn key(&mut self) -> Scalar {
        self.retry(
            SCALAR_TRIES,
            || Scalar::ONE,
            |d| scalar(&d.bytes32()).filter(|k| !bool::from(k.is_zero())),
        )
    }

    /// An s uniform in `[1, ⌊N/2⌋]`, the low half every constructed class
    /// uses.
    pub fn low_s(&mut self) -> Scalar {
        let s = self.uniform_in(&arith::be_from_u64(1), &HALF_N);
        scalar(&s).unwrap_or(Scalar::ONE)
    }

    /// A random 32-byte hash whose value mod N is nonzero.  Falls back to
    /// the hash one.
    pub fn nonzero_hash(&mut self) -> ([u8; 32], Scalar) {
        self.retry(
            SCALAR_TRIES,
            || (arith::be_from_u64(1), Scalar::ONE),
            |d| {
                let h = d.bytes32();
                let e = reduce(&h);
                (!bool::from(e.is_zero())).then_some((h, e))
            },
        )
    }

    /// dcrd's `sign` with a random nonce instead of RFC6979
    /// (`ecdsa/signature.go`): k from [`Draw::key`], R = k·G, r = R.x mod N
    /// (retried when zero), s = k⁻¹(h mod N + r·d) (retried when zero), the
    /// recovery code (R.x ≥ N) << 1 | (R.y odd), and s negated, with the
    /// code's low bit flipped, when above ⌊N/2⌋.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
    )]
    pub fn honest_ecdsa(&mut self, d: &Scalar, h: &[u8; 32]) -> Signature {
        let e = reduce(h);
        let fallback = || Signature {
            r: scalar_bytes(&Scalar::ONE),
            s: scalar_bytes(&Scalar::ONE),
            code: 0,
        };
        self.retry(SCALAR_TRIES, fallback, |draw| {
            let k = draw.key();
            let big_r = (ProjectivePoint::GENERATOR * k).to_affine();
            let rx = x_of(&big_r);
            let r = reduce(&rx);
            if bool::from(r.is_zero()) {
                return None;
            }
            let k_inv = Option::<Scalar>::from(k.invert())?;
            let mut s = k_inv * (e + r * d);
            if bool::from(s.is_zero()) {
                return None;
            }
            // Negating s negates R, whose y then has the other parity.
            let high = bool::from(s.is_high());
            if high {
                s = -s;
            }
            let code = match (rx >= N, y_is_odd(&big_r) != high) {
                (false, false) => 0,
                (false, true) => 1,
                (true, false) => 2,
                (true, true) => 3,
            };
            Some(Signature {
                r: scalar_bytes(&r),
                s: scalar_bytes(&s),
                code,
            })
        })
    }

    /// `case`, or, when a retry ran out, its fallback form: variant
    /// `fallback`, every intent [`Intent::Any`], no consistency rule, and
    /// the [`Tag::Fallback`] tag.
    pub fn finish(self, mut case: Case) -> Case {
        if self.fell_back {
            case.variant = Cow::Borrowed("fallback");
            case.intents = vec![Intent::Any; case.requests.len()];
            case.consistency = Consistency::None;
            case.tags = case.tags.with(Tag::Fallback);
        }
        case
    }
}

/// An ECDSA signature as dcrd's signer makes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    /// r, big-endian, in `[1, N-1]`.
    pub r: [u8; 32],
    /// s, big-endian, in `[1, ⌊N/2⌋]`.
    pub s: [u8; 32],
    /// The public key recovery code, 0..=3.
    pub code: u8,
}

/// A case of one request.
pub fn single(variant: impl Into<Cow<'static, str>>, request: Request, intent: Intent) -> Case {
    Case {
        variant: variant.into(),
        requests: vec![request],
        intents: vec![intent],
        consistency: Consistency::None,
        tags: Tags::NONE,
    }
}

/// `bytes` as a scalar when below N.
pub fn scalar(bytes: &[u8; 32]) -> Option<Scalar> {
    Option::from(Scalar::from_repr((*bytes).into()))
}

/// `bytes` mod N, as dcrd's `ModNScalar.SetByteSlice` reduces a hash.
pub fn reduce(bytes: &[u8; 32]) -> Scalar {
    <Scalar as Reduce<FieldBytes>>::reduce(&(*bytes).into())
}

/// A scalar's 32 big-endian bytes.
pub fn scalar_bytes(s: &Scalar) -> [u8; 32] {
    s.to_repr().into()
}

/// k·G in affine form; `k` must be nonzero.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
)]
pub fn base_mul(k: &Scalar) -> AffinePoint {
    (ProjectivePoint::GENERATOR * k).to_affine()
}

/// `p` in affine form, or `None` for the point at infinity.
pub fn finite(p: &ProjectivePoint) -> Option<AffinePoint> {
    (!bool::from(p.is_identity())).then(|| p.to_affine())
}

/// The point with x coordinate `x` (below P) and y of the given parity, if
/// x³ + 7 is a square mod P.
pub fn decompress(x: &[u8; 32], odd: bool) -> Option<AffinePoint> {
    Option::from(AffinePoint::decompress(
        &(*x).into(),
        Choice::from(u8::from(odd)),
    ))
}

/// The point (x, y), if both are below P and it is on the curve.
pub fn from_xy(x: &[u8; 32], y: &[u8; 32]) -> Option<AffinePoint> {
    Option::from(AffinePoint::from_coordinates(&(*x).into(), &(*y).into()))
}

/// A finite point's x coordinate, big-endian.
pub fn x_of(p: &AffinePoint) -> [u8; 32] {
    p.x().into()
}

/// A finite point's y coordinate, big-endian.
pub fn y_of(p: &AffinePoint) -> [u8; 32] {
    p.y().into()
}

/// Whether a finite point's y coordinate is odd.
pub fn y_is_odd(p: &AffinePoint) -> bool {
    bool::from(p.y_is_odd())
}

/// The point, or its negation, whichever has a y of parity `odd`.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
)]
pub fn with_parity(p: &AffinePoint, odd: bool) -> AffinePoint {
    if y_is_odd(p) == odd { *p } else { -*p }
}

/// SEC1 compressed: 02 or 03 by y's parity, then x.
pub fn compressed(p: &AffinePoint) -> [u8; 33] {
    let mut out = [0u8; 33];
    out[0] = 0x02 | u8::from(y_is_odd(p));
    out[1..].copy_from_slice(&x_of(p));
    out
}

/// SEC1 uncompressed: 04, x, y.
pub fn uncompressed(p: &AffinePoint) -> [u8; 65] {
    with_format(0x04, &x_of(p), &y_of(p))
}

/// SEC1 hybrid: 06 or 07 by y's parity, x, y.
pub fn hybrid(p: &AffinePoint) -> [u8; 65] {
    with_format(0x06 | u8::from(y_is_odd(p)), &x_of(p), &y_of(p))
}

/// A 65-byte key of any format byte and coordinates.
pub fn with_format(format: u8, x: &[u8; 32], y: &[u8; 32]) -> [u8; 65] {
    let mut out = [0u8; 65];
    out[0] = format;
    out[1..33].copy_from_slice(x);
    out[33..].copy_from_slice(y);
    out
}

/// What `pubkey_parse` answers for a valid key: uncompressed ‖ compressed.
pub fn parsed(p: &AffinePoint) -> Vec<u8> {
    [uncompressed(p).as_slice(), &compressed(p)].concat()
}

/// How an ECDSA verify case carries its key: three raw layouts through
/// `ecdsa_verify_raw`, and the compressed key with a DER signature
/// through `ecdsa_verify`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presentation {
    /// `ecdsa_verify_raw` with 02/03 ‖ x.
    RawCompressed,
    /// `ecdsa_verify_raw` with 04 ‖ x ‖ y.
    RawUncompressed,
    /// `ecdsa_verify_raw` with 06/07 ‖ x ‖ y, the byte matching y's parity.
    RawHybrid,
    /// `ecdsa_verify` with 02/03 ‖ x and minimal DER.
    DerCompressed,
}

impl Presentation {
    /// The four, in index order.
    pub const ALL: [Presentation; 4] = [
        Presentation::RawCompressed,
        Presentation::RawUncompressed,
        Presentation::RawHybrid,
        Presentation::DerCompressed,
    ];

    /// The three raw layouts, in index order.
    pub const RAW: [Presentation; 3] = [
        Presentation::RawCompressed,
        Presentation::RawUncompressed,
        Presentation::RawHybrid,
    ];

    /// The presentation's label, as variants carry it.
    pub fn label(self) -> &'static str {
        match self {
            Presentation::RawCompressed => "raw-compressed",
            Presentation::RawUncompressed => "raw-uncompressed",
            Presentation::RawHybrid => "raw-hybrid",
            Presentation::DerCompressed => "der-compressed",
        }
    }
}

/// The verify request for key `q`, hash `h` and signature (r, s) in
/// presentation `p`.
pub fn present(
    q: &AffinePoint,
    p: Presentation,
    h: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
) -> Request {
    match p {
        Presentation::RawCompressed => cmd::ecdsa_verify_raw(&compressed(q), h, r, s),
        Presentation::RawUncompressed => cmd::ecdsa_verify_raw(&uncompressed(q), h, r, s),
        Presentation::RawHybrid => cmd::ecdsa_verify_raw(&hybrid(q), h, r, s),
        Presentation::DerCompressed => cmd::ecdsa_verify(&compressed(q), h, &der_minimal(r, s)),
    }
}

/// The minimal DER integer for a big-endian value: leading zero bytes
/// stripped (one kept for zero), and a zero byte put back in front when
/// the top bit is set, so the integer stays non-negative.
pub fn der_int(v: &[u8]) -> Vec<u8> {
    let first = v.iter().position(|&b| b != 0).unwrap_or(v.len());
    let stripped = v.get(first..).filter(|s| !s.is_empty()).unwrap_or(&[0]);
    let mut out = Vec::with_capacity(stripped.len().saturating_add(1));
    if stripped[0] & 0x80 != 0 {
        out.push(0x00);
    }
    out.extend_from_slice(stripped);
    out
}

/// `30 L 02 rl R 02 sl S` for the given integer bodies, L = 4 + rl + sl.
/// The bodies' lengths and their sum must fit a byte.
pub fn der_sequence(r: &[u8], s: &[u8]) -> Vec<u8> {
    let len = |n: usize| u8::try_from(n).expect("a DER length below 256");
    let body = r.len().saturating_add(s.len()).saturating_add(4);
    let mut out = Vec::with_capacity(body.saturating_add(2));
    out.extend_from_slice(&[0x30, len(body), 0x02, len(r.len())]);
    out.extend_from_slice(r);
    out.extend_from_slice(&[0x02, len(s.len())]);
    out.extend_from_slice(s);
    out
}

/// Minimal DER for (r, s) without low-S normalization, as
/// `crates/dcroxide-dcrec/tests/oracle_differential.rs` writes it, so a
/// high S reaches the verifier as it is.
pub fn der_minimal(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
    der_sequence(&der_int(r), &der_int(s))
}

/// The stratum of case `i` among `n`: `i % n`, `n` a nonzero class
/// constant.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "n is a nonzero class constant, and u64 % n cannot overflow"
)]
pub fn stratum(i: u64, n: u64) -> usize {
    usize::try_from(i % n).expect("a stratum count fits usize")
}

/// The digit of case `i` at place `s` in base `n`: `(i / s) % n`, both
/// nonzero class constants.  A class whose strata take `s` values from
/// `i % s` takes its next choice here, so the two never move together
/// and every pair recurs every `s·n` cases.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "s and n are nonzero class constants: neither division can overflow"
)]
pub fn digit(i: u64, s: u64, n: u64) -> usize {
    usize::try_from((i / s) % n).expect("a digit fits usize")
}

/// The presentation of case `i` of an EV class whose strata take `s`
/// values from the index: `(i / s) % 4`.
pub fn presentation(i: u64, s: u64) -> Presentation {
    Presentation::ALL[digit(i, s, 4)]
}

/// Flips bit `bit` (0..256, from the least significant) of a big-endian
/// value.
pub fn flip_bit(v: &mut [u8; 32], bit: u64) {
    let byte = digit(bit, 8, 32);
    let mask = 1u8 << stratum(bit, 8);
    v[31usize.saturating_sub(byte)] ^= mask;
}

/// Big-endian `v` as a `u64`-built value, for small constants.
pub fn be(v: u64) -> [u8; 32] {
    arith::be_from_u64(v)
}

/// N − k for a small k.
pub fn n_minus(k: u64) -> [u8; 32] {
    arith::sub_be(&N, &be(k)).0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::ByteEntropy;
    use dcroxide_testutil::SplitMix64;

    #[test]
    fn uniform_draws_stay_in_range() {
        let mut rng = SplitMix64(0x0dd5_eed5);
        let mut d = Draw::new(&mut rng);
        for bound in [
            be(1),
            be(2),
            be(3),
            be(255),
            be(256),
            arith::P_MINUS_N,
            HALF_N,
            N,
        ] {
            for _ in 0..200 {
                let v = d.uniform_below(&bound);
                assert!(v < bound);
            }
        }
        for _ in 0..200 {
            let v = d.uniform_in(&be(5), &be(7));
            assert!(v >= be(5) && v <= be(7));
        }
        let seen: std::collections::HashSet<[u8; 32]> =
            (0..200).map(|_| d.uniform_below(&be(3))).collect();
        assert_eq!(seen.len(), 3, "every value of a small range comes up");
        for _ in 0..200 {
            let s = scalar_bytes(&d.low_s());
            assert!(s >= be(1) && s <= HALF_N);
            assert!(d.len_in(3, 5) >= 3 && d.len_in(3, 5) <= 5);
            assert_ne!(d.nonzero_byte(), 0);
        }
        assert!(!d.fell_back());
    }

    /// Honest signatures verify by the textbook equation, carry a low S
    /// and the recovery code of their R.
    #[test]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
    )]
    fn honest_signatures_verify() {
        let mut rng = SplitMix64(0x51_9e5);
        let mut d = Draw::new(&mut rng);
        for _ in 0..32 {
            let key = d.key();
            let q = base_mul(&key);
            let h = d.bytes32();
            let sig = d.honest_ecdsa(&key, &h);
            let (r, s) = (scalar(&sig.r).expect("r"), scalar(&sig.s).expect("s"));
            assert!(!bool::from(s.is_high()));
            let w = Option::<Scalar>::from(s.invert()).expect("s nonzero");
            let x =
                ProjectivePoint::GENERATOR * (reduce(&h) * w) + ProjectivePoint::from(q) * (r * w);
            let x = finite(&x).expect("finite");
            assert_eq!(reduce(&x_of(&x)), r);
            // The code names the point the signature verifies through:
            // its x's overflow bit and its y's parity, after any negation
            // of s.
            assert_eq!(sig.code >> 1, u8::from(x_of(&x) >= N));
            assert_eq!(sig.code & 1, u8::from(y_is_odd(&x)));
        }
        assert!(!d.fell_back());
    }

    #[test]
    fn encodings_and_der() {
        let g = base_mul(&Scalar::ONE);
        assert_eq!(compressed(&g)[0], 0x02, "G has an even y");
        assert_eq!(hybrid(&g)[0], 0x06);
        assert_eq!(uncompressed(&g)[1..33], compressed(&g)[1..]);
        assert_eq!(with_parity(&g, true), -g);
        assert_eq!(with_parity(&g, false), g);
        assert_eq!(decompress(&x_of(&g), false), Some(g));
        assert_eq!(decompress(&x_of(&g), true), Some(-g));
        assert_eq!(from_xy(&x_of(&g), &y_of(&g)), Some(g));
        assert_eq!(from_xy(&x_of(&g), &x_of(&g)), None);
        assert_eq!(decompress(&be(0), false), None, "7 is no square mod P");
        assert_eq!(parsed(&g).len(), 98);

        assert_eq!(der_int(&be(0)), [0]);
        assert_eq!(der_int(&be(0x7f)), [0x7f]);
        assert_eq!(der_int(&be(0x80)), [0, 0x80]);
        assert_eq!(der_int(&be(0x0100)), [1, 0]);
        assert_eq!(der_int(&N).len(), 33);
        assert_eq!(
            der_minimal(&be(1), &be(0x80)),
            [0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x80]
        );
        let mut v = be(0);
        flip_bit(&mut v, 0);
        flip_bit(&mut v, 255);
        assert_eq!((v[31], v[0]), (1, 0x80));
        assert_eq!(n_minus(1), arith::sub_be(&N, &be(1)).0);
        assert_eq!(
            (stratum(13, 4), digit(13, 4, 4), digit(13, 2, 3)),
            (1, 3, 0)
        );
        assert_eq!(presentation(13, 4), Presentation::DerCompressed);
    }

    /// An all-zero stream runs every retry out, and the draw falls back
    /// rather than looping.
    #[test]
    fn a_zero_stream_falls_back() {
        let mut zeros = ByteEntropy::new(&[]);
        let mut d = Draw::new(&mut zeros);
        assert_eq!(d.key(), Scalar::ONE);
        assert!(d.fell_back());
        let case = d.finish(single("x", cmd::ecdsa_parse_der(&[]), Intent::Accept));
        assert_eq!(case.variant, "fallback");
        assert_eq!(case.intents, [Intent::Any]);
        assert!(case.tags.has(Tag::Fallback));
    }
}
