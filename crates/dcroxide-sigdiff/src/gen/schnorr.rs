// SPDX-License-Identifier: ISC
//! EC-Schnorr-DCRv0 classes: signing (SS-*), signature parsing (SP-*) and
//! verification (SV-*).
//!
//! dcrd's verify (`schnorr/signature.go`, `schnorrVerify`) computes
//! e = BLAKE-256(r ‖ m), failing when e ≥ N (ErrSchnorrHashValue), then
//! R = s·G + e·Q, and fails when R is the point at infinity
//! (ErrSigRNotOnCurve), when R.y is odd (ErrSigRYIsOdd) and when R.x ≠ r
//! (ErrUnequalRValues).  Parsing checks the length, then r < P, then
//! s < N.  dcrd's verify returns only a boolean, so a class built for one
//! reason is held to it through dcroxide's own reason and the model's
//! ([`crate::model::schnorr`]).
//!
//! Honest signatures take a random nonce from the entropy, never RFC6979
//! and never dcroxide's signer.  The constructed classes (tier B) solve
//! for a key with group arithmetic: Q = e⁻¹·(R − s·G) makes s·G + e·Q = R
//! for any chosen R, s and nonzero e, so R, and with it the reason dcrd's
//! verify ends with, is the construction's choice.

use std::borrow::Cow;

use dcroxide_crypto::blake256;
use k256::{AffinePoint, ProjectivePoint, Scalar};

use crate::arith::{self, N, P, P_MINUS_N, TWO_256_MINUS_P};
use crate::class::{Case, ClassSpec, Family, Intent, Mix, Size, Tag, Tier};
use crate::cmd::{self, Cmd};
use crate::entropy::Entropy;
use crate::r#gen::{
    ALL_ACCEPTED, AT_OR_ABOVE_N, BOUNDARY_KEYS, DECOMPRESS_TRIES, Draw, FLOOR_A, FLOOR_B,
    MIX_MIN_N, NONE_ACCEPTED, PR_CASES, SCALAR_TRIES, at_or_above_n, base_mul, be, boundary_key,
    compressed, decompress, digit, finite, flip_bit, scalar, scalar_bytes, single, stratum, x_of,
    y_is_odd,
};

/// The signing command.
const SIGN: &[Cmd] = &[Cmd::SchnorrSign];

/// The parsing command.
const PARSE: &[Cmd] = &[Cmd::SchnorrParse];

/// The verify command.
const VERIFY: &[Cmd] = &[Cmd::SchnorrVerify];

/// dcrd's challenge BLAKE-256(r ‖ h), as a scalar: `None` at or above N,
/// where dcrd's signer draws a new nonce and its verify fails.
pub fn challenge(r: &[u8; 32], h: &[u8; 32]) -> Option<Scalar> {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(r);
    input[32..].copy_from_slice(h);
    scalar(&blake256::sum256(&input))
}

/// r ‖ s.
pub fn signature(r: &[u8; 32], s: &[u8; 32]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(r);
    out[32..].copy_from_slice(s);
    out
}

/// A verify case's inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Verify {
    /// The public key.
    q: AffinePoint,
    /// The hash.
    h: [u8; 32],
    /// r, big-endian.
    r: [u8; 32],
    /// s, big-endian.
    s: [u8; 32],
}

impl Verify {
    /// The `schnorr_verify` request: the compressed key, the hash and
    /// r ‖ s.
    fn request(&self) -> cmd::Request {
        cmd::schnorr_verify(&compressed(&self.q), &self.h, &signature(&self.r, &self.s))
    }

    /// The inputs a construction falls back to when a retry runs out: the
    /// key G, hash zero, r = s = 1.
    fn fallback() -> Verify {
        Verify {
            q: base_mul(&Scalar::ONE),
            h: [0; 32],
            r: be(1),
            s: be(1),
        }
    }
}

/// A verify case of one request.
fn verify_case(variant: impl Into<Cow<'static, str>>, v: &Verify, intent: Intent) -> Case {
    single(variant, v.request(), intent)
}

/// dcrd's signer with a random nonce instead of RFC6979
/// (`schnorr/signature.go`): k from [`Draw::key`], R = k·G, k negated when
/// R.y is odd, r = R.x, e = BLAKE-256(r ‖ h) (a new k when e ≥ N), and
/// s = k − e·d.  Falls back to r = s = 1.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
)]
fn honest_schnorr(d: &mut Draw, key: &Scalar, h: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    d.retry(
        SCALAR_TRIES,
        || (be(1), be(1)),
        |d| {
            let k = d.key();
            let big_r = base_mul(&k);
            let k = if y_is_odd(&big_r) { -k } else { k };
            let r = x_of(&big_r);
            let e = challenge(&r, h)?;
            Some((r, scalar_bytes(&(k - e * key))))
        },
    )
}

/// A random key, a random hash and an honest signature of it.
fn honest(d: &mut Draw) -> (Scalar, Verify) {
    let key = d.key();
    let h = d.bytes32();
    let (r, s) = honest_schnorr(d, &key, &h);
    (
        key,
        Verify {
            q: base_mul(&key),
            h,
            r,
            s,
        },
    )
}

/// A random hash whose challenge for `r` is nonzero and below N, and that
/// challenge.  Falls back to the hash one.
fn challenged_hash(d: &mut Draw, r: &[u8; 32]) -> ([u8; 32], Scalar) {
    d.retry(
        SCALAR_TRIES,
        || (be(1), Scalar::ONE),
        |d| {
            let h = d.bytes32();
            let e = challenge(r, &h).filter(|e| !bool::from(e.is_zero()))?;
            Some((h, e))
        },
    )
}

/// The key Q for which s·G + e·Q is the point `big_r`: Q = e⁻¹·(R − s·G).
/// `None` when e is zero or Q would be the point at infinity.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
)]
fn solve_key(s: &Scalar, e: &Scalar, big_r: &AffinePoint) -> Option<AffinePoint> {
    let e_inv = Option::<Scalar>::from(e.invert())?;
    finite(&((ProjectivePoint::from(*big_r) - ProjectivePoint::GENERATOR * s) * e_inv))
}

/// A point R of y parity `odd` whose x coordinate is `shift` + t, for t
/// uniform below P − N with that sum an x coordinate: `shift` N gives an
/// x at or above N, zero one below P − N.  Returns t and R.  Falls back to
/// t = 1 and G.
fn shifted_point(d: &mut Draw, shift: &[u8; 32], odd: bool) -> ([u8; 32], AffinePoint) {
    d.retry(
        DECOMPRESS_TRIES,
        || (be(1), base_mul(&Scalar::ONE)),
        |d| {
            let t = d.uniform_below(&P_MINUS_N);
            decompress(&arith::add_be(shift, &t).0, odd).map(|point| (t, point))
        },
    )
}

/// A key solved so that s·G + e·Q = R for a random s, the R given and the
/// challenge of `r` for a random hash: the verify inputs, or `None` when
/// Q would be the point at infinity.
fn solved(d: &mut Draw, big_r: &AffinePoint, r: [u8; 32]) -> Option<Verify> {
    let s = d.key();
    let (h, e) = challenged_hash(d, &r);
    let q = solve_key(&s, &e, big_r)?;
    Some(Verify {
        q,
        h,
        r,
        s: scalar_bytes(&s),
    })
}

fn ss_random(e: &mut dyn Entropy, _: u64) -> Case {
    let mut d = Draw::new(e);
    let key = scalar_bytes(&d.key());
    let h = d.bytes32();
    d.finish(single(
        "random",
        cmd::schnorr_sign(&key, &h),
        Intent::Accept,
    ))
}

fn ss_hash_gen(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let k = stratum(i, 4);
    let key = scalar_bytes(&d.key());
    let h = at_or_above_n(&mut d, k);
    d.finish(single(
        format!("h={}", AT_OR_ABOVE_N[k]),
        cmd::schnorr_sign(&key, &h),
        Intent::Accept,
    ))
}

/// SS-boundary's hashes.
const SIGN_HASHES: [&str; 3] = ["0", "max", "random"];

fn ss_boundary(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let k = stratum(i, 6);
    let which = digit(i, 6, 3);
    let h = match which {
        0 => [0; 32],
        1 => [0xff; 32],
        _ => d.bytes32(),
    };
    d.finish(single(
        format!("d={}/h={}", BOUNDARY_KEYS[k], SIGN_HASHES[which]),
        cmd::schnorr_sign(&boundary_key(k), &h),
        Intent::Accept,
    ))
}

fn sp_random(e: &mut dyn Entropy, _: u64) -> Case {
    let mut d = Draw::new(e);
    // The parse generator of crates/dcroxide-dcrec/tests/
    // schnorr_differential.rs: random blobs, a tenth of them short and a
    // tenth long, and of the 64-byte ones a quarter with r at or just
    // below P and a quarter with s at or just below N.
    let len = match d.below(10) {
        0 => d.len_in(0, 63),
        1 => d.len_in(65, 80),
        _ => 64,
    };
    let mut blob = d.bytes(len);
    let label = if len < 64 {
        "short"
    } else if len > 64 {
        "long"
    } else {
        let (at, value, label): (usize, _, _) = match d.below(4) {
            0 => (0, P, "r-near-P"),
            1 => (32, N, "s-near-N"),
            _ => (0, [0; 32], "random"),
        };
        if label != "random" {
            blob[at..at.saturating_add(32)].copy_from_slice(&value);
            if d.coin() {
                let last = at.saturating_add(31);
                let less = u8::try_from(d.below(3)).unwrap_or(0);
                blob[last] = blob[last].wrapping_sub(less);
            }
        }
        label
    };
    d.finish(single(label, cmd::schnorr_parse(&blob), Intent::Any))
}

/// SP-rRange's strata.
const R_RANGE: [&str; 6] = ["r>=N", "r>=P", "s>=N", "both", "short", "long"];

/// The labels of the values at or above P SP-rRange takes.
const AT_OR_ABOVE_P: [&str; 4] = ["P", "P+1", "max", "random"];

/// Value `k` of [`AT_OR_ABOVE_P`]: P, P + 1, 2^256 − 1, or uniform in
/// [P, 2^256).
fn at_or_above_p(d: &mut Draw, k: usize) -> [u8; 32] {
    match k {
        0 => P,
        1 => arith::add_be(&P, &be(1)).0,
        2 => [0xff; 32],
        _ => arith::add_be(&P, &d.uniform_below(&TWO_256_MINUS_P)).0,
    }
}

fn sp_r_range(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let which = stratum(i, 6);
    let k = digit(i, 6, 4);
    let below_p = || arith::sub_be(&P, &be(1)).0;
    let (label, sig, intent): (Cow<'static, str>, _, _) = match which {
        0 => {
            // r in [N, P), which a field element holds: it parses.
            let r = d.uniform_in(&N, &below_p());
            let s = d.uniform_below(&N);
            let sig = signature(&r, &s).to_vec();
            (R_RANGE[0].into(), sig.clone(), Intent::AcceptValue(sig))
        }
        1..=3 => {
            let r = if which == 2 {
                d.uniform_below(&P)
            } else {
                at_or_above_p(&mut d, k)
            };
            let s = if which == 1 {
                d.uniform_below(&N)
            } else {
                at_or_above_n(&mut d, k)
            };
            let (values, kind) = if which == 2 {
                (AT_OR_ABOVE_N, "ErrSigSTooBig")
            } else {
                (AT_OR_ABOVE_P, "ErrSigRTooBig")
            };
            (
                format!("{}/{}", R_RANGE[which], values[k]).into(),
                signature(&r, &s).to_vec(),
                Intent::RejectKind(kind),
            )
        }
        4 => (
            R_RANGE[4].into(),
            {
                let len = d.len_in(0, 63);
                d.bytes(len)
            },
            Intent::RejectKind("ErrSigTooShort"),
        ),
        _ => (
            R_RANGE[5].into(),
            {
                let len = d.len_in(65, 128);
                d.bytes(len)
            },
            Intent::RejectKind("ErrSigTooLong"),
        ),
    };
    d.finish(single(label, cmd::schnorr_parse(&sig), intent))
}

fn sv_honest(e: &mut dyn Entropy, _: u64) -> Case {
    let mut d = Draw::new(e);
    let (_, v) = honest(&mut d);
    d.finish(verify_case("honest", &v, Intent::Schnorr(Ok(()))))
}

/// SV-tamper's edits.
const TAMPER: [&str; 3] = ["hash", "r", "s"];

fn sv_tamper(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let edit = stratum(i, 3);
    let (_, mut v) = honest(&mut d);
    // A flip that makes r or s unparseable is kept: both sides then
    // report the parse kind.
    let bit = d.below(256);
    match edit {
        0 => flip_bit(&mut v.h, bit),
        1 => flip_bit(&mut v.r, bit),
        _ => flip_bit(&mut v.s, bit),
    }
    d.finish(verify_case(TAMPER[edit], &v, Intent::Reject))
}

fn sv_random(e: &mut dyn Entropy, _: u64) -> Case {
    let mut d = Draw::new(e);
    let q = base_mul(&d.key());
    let h = d.bytes32();
    let (r, s) = d.retry(
        SCALAR_TRIES,
        || (be(1), be(1)),
        |d| {
            let (r, s) = (d.bytes32(), d.bytes32());
            (r < P && s < N).then_some((r, s))
        },
    );
    d.finish(verify_case(
        "random",
        &Verify { q, h, r, s },
        Intent::Reject,
    ))
}

fn sv_hash_gen(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let k = stratum(i, 4);
    let key = d.key();
    let h = at_or_above_n(&mut d, k);
    // The challenge hashes h's bytes as they are, never h mod N.
    let (r, s) = honest_schnorr(&mut d, &key, &h);
    d.finish(verify_case(
        format!("h={}", AT_OR_ABOVE_N[k]),
        &Verify {
            q: base_mul(&key),
            h,
            r,
            s,
        },
        Intent::Schnorr(Ok(())),
    ))
}

fn sv_zero_s(e: &mut dyn Entropy, _: u64) -> Case {
    let mut d = Draw::new(e);
    let (_, mut v) = honest(&mut d);
    // R = e·Q, whose reason splits between an odd y and an unequal x.
    v.s = [0; 32];
    d.finish(verify_case("s=0", &v, Intent::Reject))
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
)]
fn sv_infinity(e: &mut dyn Entropy, _: u64) -> Case {
    let mut d = Draw::new(e);
    let v = d.retry(SCALAR_TRIES, Verify::fallback, |d| {
        // s = −e·d, so R = s·G + e·Q = −e·d·G + e·d·G is the point at
        // infinity.
        let (key, mut v) = honest(d);
        let e = challenge(&v.r, &v.h)?;
        v.s = scalar_bytes(&-(e * key));
        Some(v)
    });
    d.finish(verify_case(
        "s=-ed",
        &v,
        Intent::Schnorr(Err("ErrSigRNotOnCurve")),
    ))
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
)]
fn sv_odd_r(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let which = stratum(i, 2);
    let key = d.key();
    let h = d.bytes32();
    let v = d.retry(SCALAR_TRIES, Verify::fallback, |d| {
        // A nonce whose k·G has an odd y (negated otherwise), signed
        // without the signer's negation: R = s·G + e·Q = k·G, odd.  In the
        // second stratum r is another value below P, so R.x ≠ r as well,
        // and dcrd's step 9 decides before its step 10 compares them.
        let k = d.key();
        let k = if y_is_odd(&base_mul(&k)) { k } else { -k };
        let x = x_of(&base_mul(&k));
        let r = if which == 0 { x } else { d.uniform_below(&P) };
        if which == 1 && r == x {
            return None;
        }
        let e = challenge(&r, &h)?;
        Some(Verify {
            q: base_mul(&key),
            h,
            r,
            s: scalar_bytes(&(k - e * key)),
        })
    });
    d.finish(verify_case(
        ODD_R[which],
        &v,
        Intent::Schnorr(Err("ErrSigRYIsOdd")),
    ))
}

/// SV-oddR's strata: r = R.x, and r another value below P.
const ODD_R: [&str; 2] = ["R.x=r", "R.x!=r"];

/// SV-rGEN-true's and SV-rGEN-odd's construction: R with R.x = N + t of
/// parity `odd`, r = N + t, a random s and the key solved for.
fn r_gen(d: &mut Draw, odd: bool) -> Verify {
    d.retry(SCALAR_TRIES, Verify::fallback, |d| {
        let (t, big_r) = shifted_point(d, &N, odd);
        solved(d, &big_r, arith::add_be(&N, &t).0)
    })
}

fn sv_r_gen_true(e: &mut dyn Entropy, _: u64) -> Case {
    let mut d = Draw::new(e);
    let v = r_gen(&mut d, false);
    d.finish(verify_case("r>=N", &v, Intent::Schnorr(Ok(()))))
}

fn sv_r_gen_odd(e: &mut dyn Entropy, _: u64) -> Case {
    let mut d = Draw::new(e);
    let v = r_gen(&mut d, true);
    d.finish(verify_case(
        "r>=N",
        &v,
        Intent::Schnorr(Err("ErrSigRYIsOdd")),
    ))
}

/// SV-unequalR's strata.
const UNEQUAL: [&str; 3] = ["random", "xminusN", "xplusN"];

#[allow(
    clippy::arithmetic_side_effects,
    reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
)]
fn sv_unequal_r(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let which = stratum(i, 3);
    let v = d.retry(SCALAR_TRIES, Verify::fallback, |d| match which {
        0 => {
            // An even R = k·G (k negated otherwise), r any other value
            // below P, and s = k − e·d for the challenge of r: R is what
            // verify computes, and R.x ≠ r.
            let key = d.key();
            let k = d.key();
            let k = if y_is_odd(&base_mul(&k)) { -k } else { k };
            let big_r = base_mul(&k);
            let r = d.uniform_below(&P);
            if r == x_of(&big_r) {
                return None;
            }
            let (h, e) = challenged_hash(d, &r);
            Some(Verify {
                q: base_mul(&key),
                h,
                r,
                s: scalar_bytes(&(k - e * key)),
            })
        }
        1 => {
            // R.x = N + t and r = t: R.x = r + N.
            let (t, big_r) = shifted_point(d, &N, false);
            solved(d, &big_r, t)
        }
        _ => {
            // R.x = t below P − N and r = t + N: R.x = r − N.
            let (t, big_r) = shifted_point(d, &[0; 32], false);
            solved(d, &big_r, arith::add_be(&t, &N).0)
        }
    });
    d.finish(verify_case(
        UNEQUAL[which],
        &v,
        Intent::Schnorr(Err("ErrUnequalRValues")),
    ))
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
)]
fn sv_double(e: &mut dyn Entropy, _: u64) -> Case {
    let mut d = Draw::new(e);
    let v = d.retry(SCALAR_TRIES, Verify::fallback, |d| {
        // R = 2s·G (s negated when R.y is odd), Q = (s/e)·G: then
        // e·Q = s·G, the sum doubles, and R is its even result.
        let s = d.key();
        let big_r = base_mul(&(s + s));
        let (s, big_r) = if y_is_odd(&big_r) {
            (-s, -big_r)
        } else {
            (s, big_r)
        };
        let r = x_of(&big_r);
        let (h, e) = challenged_hash(d, &r);
        let q = base_mul(&(s * Option::<Scalar>::from(e.invert())?));
        Some(Verify {
            q,
            h,
            r,
            s: scalar_bytes(&s),
        })
    });
    let mut case = verify_case("doubled", &v, Intent::Schnorr(Ok(())));
    case.tags = case.tags.with(Tag::Doubled);
    d.finish(case)
}

/// SS-random.
pub const SS_RANDOM: ClassSpec = ClassSpec {
    name: "SS-random",
    family: Family::Schnorr,
    commands: SIGN,
    size: Size::Sampled { floor: FLOOR_B },
    tier: Tier::B,
    generator: ss_random,
    mix: ALL_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "RFC6979 EC-Schnorr-DCRv0 signing of a random hash by a random key, compared byte for \
          byte",
};

/// SS-hashGEN.
pub const SS_HASH_GEN: ClassSpec = ClassSpec {
    name: "SS-hashGEN",
    family: Family::Schnorr,
    commands: SIGN,
    size: Size::Stratified {
        strata: 4,
        floor: FLOOR_B,
    },
    tier: Tier::B,
    generator: ss_hash_gen,
    mix: ALL_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "signing hashes at or above N (N, N+1, 2^256-1 or random, i % 4)",
};

/// SS-boundary.
pub const SS_BOUNDARY: ClassSpec = ClassSpec {
    name: "SS-boundary",
    family: Family::Schnorr,
    commands: SIGN,
    size: Size::Stratified {
        strata: 18,
        floor: FLOOR_B,
    },
    tier: Tier::B,
    generator: ss_boundary,
    mix: ALL_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "the keys 1, 2, N-1, N-2, N/2 and N/2+1 (i % 6) over the hashes 0, 2^256-1 and random \
          ((i / 6) % 3)",
};

/// SP-random.
pub const SP_RANDOM: ClassSpec = ClassSpec {
    name: "SP-random",
    family: Family::Schnorr,
    commands: PARSE,
    size: Size::Sampled { floor: FLOOR_A },
    tier: Tier::A,
    generator: sp_random,
    mix: &[],
    pr_cases: PR_CASES,
    doc: "random signature blobs of wrong and right lengths, some with P or N planted in r or \
          s",
};

/// SP-rRange.
pub const SP_R_RANGE: ClassSpec = ClassSpec {
    name: "SP-rRange",
    family: Family::Schnorr,
    commands: PARSE,
    size: Size::Stratified {
        strata: 6,
        floor: FLOOR_A,
    },
    tier: Tier::A,
    generator: sp_r_range,
    // One stratum of six parses: the share is 1/6 to within one case.
    mix: &[Mix::AcceptRate {
        lo: 0.1666,
        hi: 0.1667,
        min_n: MIX_MIN_N,
    }],
    pr_cases: PR_CASES,
    doc: "r in [N, P), which parses; r at or above P, s at or above N, or both (values \
          (i / 6) % 4); short and long blobs (i % 6): each case its parse result",
};

/// SV-honest.
pub const SV_HONEST: ClassSpec = ClassSpec {
    name: "SV-honest",
    family: Family::Schnorr,
    commands: VERIFY,
    size: Size::Sampled { floor: FLOOR_A },
    tier: Tier::A,
    generator: sv_honest,
    mix: ALL_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "a random key, hash and honest signature (random nonce): valid",
};

/// SV-tamper.
pub const SV_TAMPER: ClassSpec = ClassSpec {
    name: "SV-tamper",
    family: Family::Schnorr,
    commands: VERIFY,
    size: Size::Stratified {
        strata: 3,
        floor: FLOOR_A,
    },
    tier: Tier::A,
    generator: sv_tamper,
    mix: NONE_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "an honest signature with one bit of the hash, r or s flipped (i % 3)",
};

/// SV-random.
pub const SV_RANDOM: ClassSpec = ClassSpec {
    name: "SV-random",
    family: Family::Schnorr,
    commands: VERIFY,
    size: Size::Sampled { floor: FLOOR_A },
    tier: Tier::A,
    generator: sv_random,
    mix: NONE_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "a valid random key with random r below P, s below N and hash",
};

/// SV-hashGEN.
pub const SV_HASH_GEN: ClassSpec = ClassSpec {
    name: "SV-hashGEN",
    family: Family::Schnorr,
    commands: VERIFY,
    size: Size::Stratified {
        strata: 4,
        floor: FLOOR_A,
    },
    tier: Tier::A,
    generator: sv_hash_gen,
    mix: ALL_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "an honest signature over a hash at or above N (N, N+1, 2^256-1 or random, i % 4), \
          verified with the hash as it is: valid, the challenge being BLAKE-256 of r and the \
          hash's bytes, never of the hash mod N",
};

/// SV-zeroS.
pub const SV_ZERO_S: ClassSpec = ClassSpec {
    name: "SV-zeroS",
    family: Family::Schnorr,
    commands: VERIFY,
    size: Size::Sampled { floor: FLOOR_A },
    tier: Tier::A,
    generator: sv_zero_s,
    mix: NONE_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "an honest r with s = 0, so R = e·Q",
};

/// SV-infinity.
pub const SV_INFINITY: ClassSpec = ClassSpec {
    name: "SV-infinity",
    family: Family::Schnorr,
    commands: VERIFY,
    size: Size::Sampled { floor: FLOOR_B },
    tier: Tier::B,
    generator: sv_infinity,
    mix: NONE_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "an honest r with s = -e·d, so R = s·G + e·Q is the point at infinity: \
          ErrSigRNotOnCurve",
};

/// SV-oddR.
pub const SV_ODD_R: ClassSpec = ClassSpec {
    name: "SV-oddR",
    family: Family::Schnorr,
    commands: VERIFY,
    size: Size::Stratified {
        strata: 2,
        floor: FLOOR_B,
    },
    tier: Tier::B,
    generator: sv_odd_r,
    mix: NONE_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "a signature by a nonce whose point R has an odd y, not negated, with r = R.x or \
          another r below P (i % 2): ErrSigRYIsOdd, which dcrd checks before it compares R.x \
          with r",
};

/// SV-rGEN-true.
pub const SV_R_GEN_TRUE: ClassSpec = ClassSpec {
    name: "SV-rGEN-true",
    family: Family::Schnorr,
    commands: VERIFY,
    size: Size::Sampled { floor: FLOOR_B },
    tier: Tier::B,
    generator: sv_r_gen_true,
    mix: ALL_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "an even R with R.x = r at or above N and the key solved for: valid",
};

/// SV-rGEN-odd.
pub const SV_R_GEN_ODD: ClassSpec = ClassSpec {
    name: "SV-rGEN-odd",
    family: Family::Schnorr,
    commands: VERIFY,
    size: Size::Sampled { floor: FLOOR_B },
    tier: Tier::B,
    generator: sv_r_gen_odd,
    mix: NONE_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "SV-rGEN-true's construction with an odd R: ErrSigRYIsOdd",
};

/// SV-unequalR.
pub const SV_UNEQUAL_R: ClassSpec = ClassSpec {
    name: "SV-unequalR",
    family: Family::Schnorr,
    commands: VERIFY,
    size: Size::Stratified {
        strata: 3,
        floor: FLOOR_B,
    },
    tier: Tier::B,
    generator: sv_unequal_r,
    mix: NONE_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "an even R that verify computes with R.x != r (i % 3): r random, r = R.x - N, or \
          r = R.x + N, the last two accepted by a verifier comparing x mod N: \
          ErrUnequalRValues",
};

/// SV-double.
pub const SV_DOUBLE: ClassSpec = ClassSpec {
    name: "SV-double",
    family: Family::Schnorr,
    commands: VERIFY,
    size: Size::Sampled { floor: FLOOR_B },
    tier: Tier::B,
    generator: sv_double,
    mix: ALL_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "Q = (s/e)·G, so s·G = e·Q and the sum doubles to R = 2s·G: valid",
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::class::generate;
    use crate::model::ModelOutcome;
    use crate::model::ecdsa::decode_key;
    use crate::model::schnorr::request_outcome;
    use k256::elliptic_curve::group::Group;
    use std::collections::BTreeSet;

    /// Every SS, SP and SV class.
    const CLASSES: [&ClassSpec; 16] = [
        &SS_RANDOM,
        &SS_HASH_GEN,
        &SS_BOUNDARY,
        &SP_RANDOM,
        &SP_R_RANGE,
        &SV_HONEST,
        &SV_TAMPER,
        &SV_RANDOM,
        &SV_HASH_GEN,
        &SV_ZERO_S,
        &SV_INFINITY,
        &SV_ODD_R,
        &SV_R_GEN_TRUE,
        &SV_R_GEN_ODD,
        &SV_UNEQUAL_R,
        &SV_DOUBLE,
    ];

    fn cases(class: &ClassSpec, n: u64) -> impl Iterator<Item = (u64, Case)> + '_ {
        (0..n).map(move |i| (i, generate(class, 0x7e57_5eed, i)))
    }

    /// A verify request decoded: Q, h, r, s.
    fn decode(case: &Case) -> (AffinePoint, [u8; 32], [u8; 32], [u8; 32]) {
        let data = &case.requests[0].data;
        assert_eq!(case.requests[0].cmd, Cmd::SchnorrVerify);
        assert_eq!(data.len(), 129);
        let q = decode_key(&data[..33]).expect("a valid key");
        let h: [u8; 32] = data[33..65].try_into().expect("hash");
        let r: [u8; 32] = data[65..97].try_into().expect("r");
        let s: [u8; 32] = data[97..].try_into().expect("s");
        (q, h, r, s)
    }

    /// R = s·G + e·Q with e = BLAKE-256(r ‖ h), computed here apart from
    /// the model; also s·G and e·Q.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
    )]
    fn sum(
        q: &AffinePoint,
        h: &[u8; 32],
        r: &[u8; 32],
        s: &[u8; 32],
    ) -> (ProjectivePoint, ProjectivePoint, ProjectivePoint) {
        let e = challenge(r, h).expect("a challenge below N");
        let sg = ProjectivePoint::GENERATOR * scalar(s).expect("s below N");
        let eq = ProjectivePoint::from(*q) * e;
        (sg + eq, sg, eq)
    }

    /// The witness predicates and each construction's reason, on the
    /// numbers: per constructed class, a few cases decoded from their
    /// request bytes and R computed apart from the model.
    #[test]
    fn constructed_classes_reach_their_reasons() {
        let even_with_x = |p: &ProjectivePoint| {
            let p = finite(p).expect("finite");
            assert!(!y_is_odd(&p), "an even R");
            x_of(&p)
        };
        for (i, case) in cases(&SV_R_GEN_TRUE, 16) {
            let (q, h, r, s) = decode(&case);
            assert!(r >= N && r < P, "case {i}: N <= r < P");
            assert_eq!(even_with_x(&sum(&q, &h, &r, &s).0), r, "case {i}: R.x = r");
        }
        for (i, case) in cases(&SV_R_GEN_ODD, 16) {
            let (q, h, r, s) = decode(&case);
            assert!(r >= N, "case {i}");
            let big_r = finite(&sum(&q, &h, &r, &s).0).expect("finite");
            assert!(y_is_odd(&big_r) && x_of(&big_r) == r, "case {i}: an odd R");
        }
        for (i, case) in cases(&SV_UNEQUAL_R, 24) {
            let (q, h, r, s) = decode(&case);
            let x = even_with_x(&sum(&q, &h, &r, &s).0);
            assert_ne!(x, r, "case {i}: R.x != r");
            match stratum(i, 3) {
                1 => assert_eq!(x, arith::add_be(&r, &N).0, "case {i}: R.x = r + N"),
                2 => assert_eq!(x, arith::sub_be(&r, &N).0, "case {i}: R.x = r - N"),
                _ => {}
            }
        }
        for (i, case) in cases(&SV_DOUBLE, 16) {
            assert!(case.tags.has(Tag::Doubled));
            let (q, h, r, s) = decode(&case);
            let (big_r, sg, eq) = sum(&q, &h, &r, &s);
            assert_eq!(sg, eq, "case {i}: s·G = e·Q");
            assert_eq!(big_r, sg.double(), "case {i}");
            assert_eq!(even_with_x(&big_r), r, "case {i}");
        }
        for (i, case) in cases(&SV_INFINITY, 16) {
            let (q, h, r, s) = decode(&case);
            assert!(bool::from(sum(&q, &h, &r, &s).0.is_identity()), "case {i}");
        }
        for (i, case) in cases(&SV_ODD_R, 16) {
            let (q, h, r, s) = decode(&case);
            let big_r = finite(&sum(&q, &h, &r, &s).0).expect("finite");
            assert!(y_is_odd(&big_r), "case {i}: an odd R");
            assert_eq!(x_of(&big_r) == r, stratum(i, 2) == 0, "case {i}: R.x = r");
        }
        for (i, case) in cases(&SV_HONEST, 16) {
            let (q, h, r, s) = decode(&case);
            assert_eq!(even_with_x(&sum(&q, &h, &r, &s).0), r, "case {i}");
        }
    }

    /// The range classes reach their ranges: SS-hashGEN signs, and
    /// SV-hashGEN verifies, N, N + 1, 2^256 − 1 or another hash at or
    /// above N, and each SP-rRange stratum puts r and s where its name
    /// says, r in [N, P) in the first, which parses.  SV-hashGEN's
    /// signatures verify over the hash as it is and not over its value mod
    /// N, the hash a verifier that reduced it before the challenge would
    /// take.
    #[test]
    fn range_classes_reach_their_ranges() {
        let hash_at = |i: u64, h: &[u8; 32]| {
            assert!(*h >= N, "case {i}: a hash at or above N");
            match stratum(i, 4) {
                0 => assert_eq!(*h, N, "case {i}"),
                1 => assert_eq!(*h, arith::add_be(&N, &be(1)).0, "case {i}"),
                2 => assert_eq!(*h, [0xff; 32], "case {i}"),
                _ => {}
            }
        };
        for (i, case) in cases(&SS_HASH_GEN, 16) {
            hash_at(i, &case.requests[0].data[32..].try_into().expect("hash"));
        }
        for (i, case) in cases(&SV_HASH_GEN, 16) {
            let (q, h, r, s) = decode(&case);
            hash_at(i, &h);
            let big_r = finite(&sum(&q, &h, &r, &s).0).expect("finite");
            assert!(!y_is_odd(&big_r) && x_of(&big_r) == r, "case {i}: valid");
            let reduced = arith::sub_be(&h, &N).0;
            let other = finite(&sum(&q, &reduced, &r, &s).0);
            assert!(
                other.is_none_or(|p| y_is_odd(&p) || x_of(&p) != r),
                "case {i}: not valid over h mod N"
            );
        }
        for (i, case) in cases(&SP_R_RANGE, 48) {
            let sig = &case.requests[0].data;
            let ctx = format!("case {i} ({})", case.variant);
            match stratum(i, 6) {
                0 => {
                    assert!(sig[..32] >= N[..] && sig[..32] < P[..], "{ctx}: N <= r < P");
                    assert!(sig[32..] < N[..], "{ctx}: s below N");
                }
                1 => assert!(sig[..32] >= P[..] && sig[32..] < N[..], "{ctx}"),
                2 => assert!(sig[..32] < P[..] && sig[32..] >= N[..], "{ctx}"),
                3 => assert!(sig[..32] >= P[..] && sig[32..] >= N[..], "{ctx}"),
                4 => assert!(sig.len() < 64, "{ctx}"),
                _ => assert!(sig.len() > 64, "{ctx}"),
            }
        }
    }

    /// Every SV request's reason is the model's, every accept intent is
    /// accepted by the model and every reject rejected or unparseable, for
    /// 16 cases per class and at least the per-PR count; every SP case's
    /// intent is what dcrd's parse checks, written out here, give.
    #[test]
    fn every_intent_holds_in_the_model() {
        for class in CLASSES {
            for (i, case) in cases(class, class.pr_cases.max(16)) {
                let ctx = format!("{} case {i} ({})", class.name, case.variant);
                assert!(!case.tags.has(Tag::Fallback), "{ctx}: fallback");
                let request = &case.requests[0];
                let intent = &case.intents[0];
                match request.cmd {
                    Cmd::SchnorrVerify => {
                        let got = request_outcome(request);
                        let reason = match got {
                            Some(ModelOutcome::Schnorr { reason, doubled }) => {
                                assert_eq!(doubled, case.tags.has(Tag::Doubled), "{ctx}");
                                Some(reason)
                            }
                            None => None,
                            other => panic!("{ctx}: {other:?}"),
                        };
                        match intent {
                            Intent::Schnorr(want) => assert_eq!(reason, Some(*want), "{ctx}"),
                            Intent::Reject => {
                                assert!(reason.is_none_or(|r| r.is_err()), "{ctx}: {got:?}");
                            }
                            other => panic!("{ctx}: {other:?}"),
                        }
                    }
                    Cmd::SchnorrParse => {
                        let sig = &request.data;
                        let want = if sig.len() < 64 {
                            Err("ErrSigTooShort")
                        } else if sig.len() > 64 {
                            Err("ErrSigTooLong")
                        } else if sig[..32] >= P[..] {
                            Err("ErrSigRTooBig")
                        } else if sig[32..] >= N[..] {
                            Err("ErrSigSTooBig")
                        } else {
                            Ok(sig.clone())
                        };
                        match intent {
                            Intent::Any => {}
                            Intent::AcceptValue(bytes) => {
                                assert_eq!(want, Ok(bytes.clone()), "{ctx}");
                            }
                            Intent::RejectKind(kind) => assert_eq!(want, Err(*kind), "{ctx}"),
                            other => panic!("{ctx}: {other:?}"),
                        }
                    }
                    Cmd::SchnorrSign => {
                        assert_eq!(*intent, Intent::Accept, "{ctx}");
                        let key: [u8; 32] = request.data[..32].try_into().expect("key");
                        assert!(
                            scalar(&key).is_some_and(|k| !bool::from(k.is_zero())),
                            "{ctx}: a key in [1, N-1]"
                        );
                        assert_eq!(request.data.len(), 64, "{ctx}");
                    }
                    other => panic!("{ctx}: {other:?}"),
                }
            }
        }
    }

    /// Each class's per-PR cases cover every variant it can produce, and
    /// send its command.
    #[test]
    fn per_pr_counts_cover_every_variant() {
        let all_labels: [(&ClassSpec, usize); 16] = [
            (&SS_RANDOM, 1),
            (&SS_HASH_GEN, 4),
            (&SS_BOUNDARY, 18),
            (&SP_RANDOM, 5),
            (&SP_R_RANGE, 15),
            (&SV_HONEST, 1),
            (&SV_TAMPER, 3),
            (&SV_RANDOM, 1),
            (&SV_HASH_GEN, 4),
            (&SV_ZERO_S, 1),
            (&SV_INFINITY, 1),
            (&SV_ODD_R, 2),
            (&SV_R_GEN_TRUE, 1),
            (&SV_R_GEN_ODD, 1),
            (&SV_UNEQUAL_R, 3),
            (&SV_DOUBLE, 1),
        ];
        for (class, labels) in all_labels {
            let mut variants = BTreeSet::new();
            for (_, case) in cases(class, class.pr_cases) {
                assert_eq!(case.requests.len(), 1);
                assert!(class.commands.contains(&case.requests[0].cmd));
                variants.insert(case.variant.into_owned());
            }
            assert_eq!(variants.len(), labels, "{}: {variants:?}", class.name);
        }
    }

    /// The honest signer is dcrd's signer with another nonce: dcrd's own
    /// vector for key 1 and BLAKE-256(01020304) verifies by the same
    /// equation, and the challenge is dcrd's.
    #[test]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
    )]
    fn the_challenge_is_dcrds() {
        let b32 =
            |hex: &str| -> [u8; 32] { dcroxide_testutil::unhex(hex).try_into().expect("32 bytes") };
        let h = b32("c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7");
        let r = b32("4c68976afe187ff0167919ad181cb30f187e2af1c8233b2cbebbbe0fc97fff61");
        let s = b32("e9ae2d0e306497236d4e328dc1a34244045745e87da69d806859348bc2a74525");
        let g = base_mul(&Scalar::ONE);
        let big_r = finite(&sum(&g, &h, &r, &s).0).expect("finite");
        assert_eq!((x_of(&big_r), y_is_odd(&big_r)), (r, false));
        // dcrd's vector signed with its nonce: s = k − e·d with d = 1.
        let k = b32("d4e18f08eb87073cb2a6707def02007315f7349c3c132590a0088fefece557ef");
        let k = scalar(&k).expect("k");
        let k = if y_is_odd(&base_mul(&k)) { -k } else { k };
        let e = challenge(&r, &h).expect("below N");
        assert_eq!(scalar_bytes(&(k - e)), s);
    }
}
