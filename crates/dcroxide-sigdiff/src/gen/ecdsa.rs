// SPDX-License-Identifier: ISC
//! ECDSA verification (EV-*) and signing (ES-*) classes.
//!
//! A verify case is a key Q, a hash h and a signature (r, s), sent in one
//! of four presentations ([`Presentation`]): the three raw key layouts of
//! `ecdsa_verify_raw` and the compressed key with minimal DER of
//! `ecdsa_verify`.  Every EV class that sends one request reaches its cases
//! through all four, chosen by the case index: `i % 4` where the strata are
//! the presentations, `(i / S) % 4` where the class already takes S strata
//! from the index, so that every (stratum, presentation) pair recurs every
//! 4·S cases.  Two classes fix the layer in the stratum instead: EV-zero
//! (raw or DER) and EV-range (raw only, where range errors exist) take the
//! raw presentation from `(i / S) % 3`.  EV-keyenc sends all four in one
//! case.
//!
//! The constructed classes (tier B) solve for a key or signature with
//! group arithmetic so that dcrd's verify ends in a named step, which the
//! model ([`crate::model::ecdsa`]) re-derives for every case.  They use
//! s ≤ ⌊N/2⌋, as an attacker on the consensus path must; EV-sEdge's two
//! high-S strata are the exception, kept for API parity.

use std::borrow::Cow;

use k256::elliptic_curve::scalar::IsHigh;
use k256::{AffinePoint, ProjectivePoint, Scalar};

use crate::arith::{self, HALF_N, N, P_MINUS_N, TWO_256_MINUS_N};
use crate::class::{Case, ClassSpec, Consistency, Family, Intent, Mix, Size, Tag, Tags, Tier};
use crate::cmd::{self, Cmd, Request};
use crate::entropy::Entropy;
use crate::r#gen::{
    ALL_ACCEPTED, DECOMPRESS_TRIES, Draw, FLOOR_A, FLOOR_B, MIX_MIN_N, NONE_ACCEPTED, PR_CASES,
    Presentation, SCALAR_TRIES, base_mul, be, decompress, digit, finite, flip_bit, n_minus,
    present, presentation, reduce, scalar, scalar_bytes, single, stratum, x_of,
};
use crate::model::EcdsaBranch;

/// Both verify commands: the raw layouts and DER.
const VERIFY: &[Cmd] = &[Cmd::EcdsaVerifyRaw, Cmd::EcdsaVerify];

/// The raw verify command alone.
const VERIFY_RAW: &[Cmd] = &[Cmd::EcdsaVerifyRaw];

/// The signing command.
const SIGN: &[Cmd] = &[Cmd::EcdsaSign];

/// A verify case's inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Verify {
    /// The public key.
    q: AffinePoint,
    /// The hash, as the request carries it.
    h: [u8; 32],
    /// r, big-endian.
    r: [u8; 32],
    /// s, big-endian.
    s: [u8; 32],
}

impl Verify {
    /// The request in presentation `p`.
    fn present(&self, p: Presentation) -> Request {
        present(&self.q, p, &self.h, &self.r, &self.s)
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

/// A verify case of one request in presentation `p`.
fn verify_case(
    variant: impl Into<Cow<'static, str>>,
    v: &Verify,
    p: Presentation,
    intent: Intent,
) -> Case {
    single(variant, v.present(p), intent)
}

/// `<label>/<presentation>`.
fn label(label: &str, p: Presentation) -> String {
    format!("{label}/{}", p.label())
}

/// A key and a hash, honestly signed.
fn honest(d: &mut Draw) -> Verify {
    let key = d.key();
    let h = d.bytes32();
    signed(d, &key, h, h)
}

/// Q = d·G, signed over `sign_h` and verified with `verify_h`.
fn signed(d: &mut Draw, key: &Scalar, sign_h: [u8; 32], verify_h: [u8; 32]) -> Verify {
    let sig = d.honest_ecdsa(key, &sign_h);
    Verify {
        q: base_mul(key),
        h: verify_h,
        r: sig.r,
        s: sig.s,
    }
}

/// The key Q for which u1·G + u2·Q is the point `x`, with u1 = e/s and
/// u2 = r/s: Q = r⁻¹·(s·X − e·G).  `None` when Q would be the point at
/// infinity.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
)]
fn solve_key(r: &Scalar, s: &Scalar, e: &Scalar, x: &AffinePoint) -> Option<AffinePoint> {
    let r_inv = Option::<Scalar>::from(r.invert())?;
    finite(&((ProjectivePoint::from(*x) * s - ProjectivePoint::GENERATOR * e) * r_inv))
}

/// The labels of the values at or above N that EV-hashGEN, EV-range and
/// ES-hashGEN take.
const AT_OR_ABOVE_N: [&str; 4] = ["N", "N+1", "max", "random"];

/// Value `k` of [`AT_OR_ABOVE_N`]: N, N + 1, 2^256 − 1, or uniform in
/// [N, 2^256).
fn at_or_above_n(d: &mut Draw, k: usize) -> [u8; 32] {
    match k {
        0 => N,
        1 => arith::add_be(&N, &be(1)).0,
        2 => [0xff; 32],
        _ => arith::add_be(&N, &d.uniform_below(&TWO_256_MINUS_N)).0,
    }
}

/// The EV-tamper edits.
const TAMPER: [&str; 4] = ["hash", "key", "r", "s"];

/// Applies tamper edit `edit`: one random bit of h flipped, Q replaced by
/// another key's, or one random bit of r or s flipped (a flip that lands
/// at or above N is kept: both sides then report the range kind).
fn tamper(d: &mut Draw, v: &mut Verify, edit: usize) {
    match edit {
        0 => flip_bit(&mut v.h, d.below(256)),
        1 => v.q = base_mul(&d.key()),
        2 => flip_bit(&mut v.r, d.below(256)),
        _ => flip_bit(&mut v.s, d.below(256)),
    }
}

fn ev_honest(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let p = Presentation::ALL[stratum(i, 4)];
    let v = honest(&mut d);
    d.finish(verify_case(p.label(), &v, p, Intent::Accept))
}

fn ev_high_s(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let p = Presentation::ALL[stratum(i, 4)];
    let mut v = honest(&mut d);
    v.s = arith::neg_mod_n(&v.s);
    d.finish(verify_case(p.label(), &v, p, Intent::Accept))
}

fn ev_tamper(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let edit = stratum(i, 4);
    let p = presentation(i, 4);
    let mut v = honest(&mut d);
    tamper(&mut d, &mut v, edit);
    d.finish(verify_case(label(TAMPER[edit], p), &v, p, Intent::Reject))
}

fn ev_random(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let p = Presentation::ALL[stratum(i, 4)];
    let q = base_mul(&d.key());
    let v = Verify {
        q,
        h: d.bytes32(),
        r: d.bytes32(),
        s: d.bytes32(),
    };
    d.finish(verify_case(p.label(), &v, p, Intent::Reject))
}

fn ev_keyenc(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let valid = stratum(i, 2) == 0;
    let mut v = honest(&mut d);
    let intent = if valid {
        Intent::Accept
    } else {
        let edit = usize::try_from(d.below(4)).unwrap_or(0);
        tamper(&mut d, &mut v, edit);
        Intent::Reject
    };
    let case = Case {
        variant: Cow::Borrowed(if valid { "valid" } else { "invalid" }),
        requests: Presentation::ALL.iter().map(|&p| v.present(p)).collect(),
        intents: vec![intent; 4],
        consistency: Consistency::SameVerdict,
        tags: Tags::NONE,
    };
    d.finish(case)
}

/// EV-keys' private keys.
const KEYS: [&str; 8] = ["1", "2", "3", "N-1", "N-2", "N-3", "N/2", "N/2+1"];

fn edge_key(k: usize) -> [u8; 32] {
    match k {
        0..=2 => be(u64::try_from(k).unwrap_or(0).saturating_add(1)),
        3..=5 => n_minus(u64::try_from(k).unwrap_or(3).saturating_sub(2)),
        6 => HALF_N,
        _ => arith::add_be(&HALF_N, &be(1)).0,
    }
}

fn ev_keys(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let k = stratum(i, 8);
    let p = presentation(i, 8);
    let key = scalar(&edge_key(k)).unwrap_or(Scalar::ONE);
    let h = d.bytes32();
    let v = signed(&mut d, &key, h, h);
    d.finish(verify_case(label(KEYS[k], p), &v, p, Intent::Accept))
}

/// EV-hashGEN's strata, `high` split by the value of h.
const HASH_GEN: [&str; 3] = ["high", "alias-up", "alias-down"];

fn ev_hash_gen(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let s = stratum(i, 3);
    let p = presentation(i, 12);
    let key = d.key();
    let (name, v) = match s {
        0 => {
            let k = digit(i, 3, 4);
            let h = at_or_above_n(&mut d, k);
            (
                format!("high-{}", AT_OR_ABOVE_N[k]),
                signed(&mut d, &key, h, h),
            )
        }
        1 => {
            let h0 = d.uniform_below(&TWO_256_MINUS_N);
            let up = arith::add_be(&h0, &N).0;
            (HASH_GEN[1].to_owned(), signed(&mut d, &key, h0, up))
        }
        _ => {
            let h = arith::add_be(&N, &d.uniform_below(&TWO_256_MINUS_N)).0;
            let down = arith::sub_be(&h, &N).0;
            (HASH_GEN[2].to_owned(), signed(&mut d, &key, h, down))
        }
    };
    d.finish(verify_case(label(&name, p), &v, p, Intent::Accept))
}

fn ev_hash0(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let s = stratum(i, 2);
    let p = presentation(i, 2);
    let h = if s == 0 { [0; 32] } else { N };
    let key = d.key();
    let v = signed(&mut d, &key, h, h);
    d.finish(verify_case(
        label(["h=0", "h=N"][s], p),
        &v,
        p,
        Intent::Accept,
    ))
}

/// EV-zero's components.
const ZEROED: [&str; 3] = ["r", "s", "both"];

fn ev_zero(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let which = stratum(i, 3);
    let der = digit(i, 3, 2) == 1;
    let mut v = honest(&mut d);
    if which != 1 {
        v.r = [0; 32];
    }
    if which != 0 {
        v.s = [0; 32];
    }
    let (p, intent) = if der {
        let kind = if which == 1 {
            "ErrSigSIsZero"
        } else {
            "ErrSigRIsZero"
        };
        (Presentation::DerCompressed, Intent::RejectKind(kind))
    } else {
        (
            Presentation::RAW[digit(i, 6, 3)],
            Intent::Branch(EcdsaBranch::Step1Zero),
        )
    };
    d.finish(verify_case(label(ZEROED[which], p), &v, p, intent))
}

/// EV-range's strata.
const RANGE: [&str; 4] = ["r", "s", "both", "badkey"];

fn ev_range(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let which = stratum(i, 4);
    let p = Presentation::RAW[digit(i, 4, 3)];
    let k = digit(i, 12, 4);
    let mut v = honest(&mut d);
    let case = match which {
        0..=2 => {
            if which != 1 {
                v.r = at_or_above_n(&mut d, k);
            }
            if which != 0 {
                v.s = at_or_above_n(&mut d, k);
            }
            let kind = if which == 1 {
                "ErrSigSTooBig"
            } else {
                "ErrSigRTooBig"
            };
            verify_case(
                format!("{}/{}/{}", RANGE[which], AT_OR_ABOVE_N[k], p.label()),
                &v,
                p,
                Intent::RejectKind(kind),
            )
        }
        _ => {
            // A 33-byte key with format 0x05, ahead of r = N: the key is
            // parsed first, so its kind wins.
            let mut key = crate::r#gen::compressed(&v.q);
            key[0] = 0x05;
            single(
                RANGE[3],
                cmd::ecdsa_verify_raw(&key, &v.h, &N, &v.s),
                Intent::RejectKind("ErrPubKeyInvalidFormat"),
            )
        }
    };
    d.finish(case)
}

/// t uniform in [1, P−N−1] such that N + t is the x coordinate of a point
/// R, with R's parity drawn: an r whose point has x = r + N.
fn above_n_point(d: &mut Draw) -> ([u8; 32], AffinePoint) {
    let hi = arith::sub_be(&P_MINUS_N, &be(1)).0;
    d.retry(
        DECOMPRESS_TRIES,
        || (be(1), base_mul(&Scalar::ONE)),
        |d| {
            let t = d.uniform_in(&be(1), &hi);
            let x = arith::add_be(&N, &t).0;
            let odd = d.coin();
            decompress(&x, odd).map(|point| (t, point))
        },
    )
}

/// EV-xGEN-true's construction: R with R.x = N + t, r = t, s low, h
/// random, Q = r⁻¹·(s·R − e·G), so X = R and X.x = r + N.
fn xgen_true(d: &mut Draw) -> Verify {
    d.retry(SCALAR_TRIES, Verify::fallback, |d| {
        let (t, big_r) = above_n_point(d);
        let s = d.low_s();
        let h = d.bytes32();
        let q = solve_key(&scalar(&t)?, &s, &reduce(&h), &big_r)?;
        Some(Verify {
            q,
            h,
            r: t,
            s: scalar_bytes(&s),
        })
    })
}

fn ev_xgen_true(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let p = Presentation::ALL[stratum(i, 4)];
    let v = xgen_true(&mut d);
    d.finish(verify_case(
        p.label(),
        &v,
        p,
        Intent::Branch(EcdsaBranch::Step10Accept),
    ))
}

/// EV-xGEN-false's constructions.
const XGEN_FALSE: [&str; 3] = ["s+1", "hash", "unrelated"];

#[allow(
    clippy::arithmetic_side_effects,
    reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
)]
fn ev_xgen_false(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let which = stratum(i, 3);
    let p = presentation(i, 3);
    let v = match which {
        0 => {
            let mut v = xgen_true(&mut d);
            let s = scalar(&v.s).unwrap_or(Scalar::ONE) + Scalar::ONE;
            v.s = scalar_bytes(&s);
            v
        }
        1 => {
            let mut v = xgen_true(&mut d);
            flip_bit(&mut v.h, d.below(256));
            v
        }
        _ => {
            let r = d.uniform_in(&be(1), &arith::sub_be(&P_MINUS_N, &be(1)).0);
            let q = base_mul(&d.key());
            let s = scalar_bytes(&d.low_s());
            Verify {
                q,
                h: d.bytes32(),
                r,
                s,
            }
        }
    };
    d.finish(verify_case(
        label(XGEN_FALSE[which], p),
        &v,
        p,
        Intent::Branch(EcdsaBranch::Step10Reject),
    ))
}

fn ev_xgen_wrap(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let p = Presentation::ALL[stratum(i, 4)];
    let v = d.retry(SCALAR_TRIES, Verify::fallback, |d| {
        // X = k·G with X.x < 2N − P, so that r = X.x + P − N is below N.
        let (x, r) = d.retry(
            SCALAR_TRIES,
            || (base_mul(&Scalar::ONE), be(1)),
            |d| {
                let x = base_mul(&d.key());
                let (r, carry) = arith::add_be(&x_of(&x), &P_MINUS_N);
                (!carry && r < N).then_some((x, r))
            },
        );
        let s = d.low_s();
        let h = d.bytes32();
        let q = solve_key(&scalar(&r)?, &s, &reduce(&h), &x)?;
        Some(Verify {
            q,
            h,
            r,
            s: scalar_bytes(&s),
        })
    });
    d.finish(verify_case(
        p.label(),
        &v,
        p,
        Intent::Branch(EcdsaBranch::Step9Reject),
    ))
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
)]
fn ev_infinity(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let p = Presentation::ALL[stratum(i, 4)];
    let v = d.retry(SCALAR_TRIES, Verify::fallback, |d| {
        // Q = −(e·r⁻¹)·G, so u2·Q = −(e/s)·G = −u1·G.
        let r = d.key();
        let s = d.low_s();
        let (h, e) = d.nonzero_hash();
        let r_inv = Option::<Scalar>::from(r.invert())?;
        let q = finite(&(ProjectivePoint::GENERATOR * (-(e * r_inv))))?;
        Some(Verify {
            q,
            h,
            r: scalar_bytes(&r),
            s: scalar_bytes(&s),
        })
    });
    d.finish(verify_case(
        p.label(),
        &v,
        p,
        Intent::Branch(EcdsaBranch::Step6Infinity),
    ))
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
)]
fn ev_double(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let p = Presentation::ALL[stratum(i, 4)];
    let v = d.retry(SCALAR_TRIES, Verify::fallback, |d| {
        // X = 2·(e/s)·G, r = X.x, Q = (e/r)·G: then u2·Q = (e/s)·G = u1·G.
        // An X.x at or above N (odds about 2^-127) is drawn again, so the
        // case is decided at step 8.
        let s = d.low_s();
        let (h, e) = d.nonzero_hash();
        let u = e * Option::<Scalar>::from(s.invert())?;
        let x = finite(&(ProjectivePoint::GENERATOR * (u + u)))?;
        let r = scalar(&x_of(&x)).filter(|r| !bool::from(r.is_zero()))?;
        let q = finite(&(ProjectivePoint::GENERATOR * (e * Option::<Scalar>::from(r.invert())?)))?;
        Some(Verify {
            q,
            h,
            r: scalar_bytes(&r),
            s: scalar_bytes(&s),
        })
    });
    let mut case = verify_case(p.label(), &v, p, Intent::Branch(EcdsaBranch::Step8Accept));
    case.tags = case.tags.with(Tag::Doubled);
    d.finish(case)
}

/// EV-sEdge's values of s.
const S_EDGES: [&str; 4] = ["s=1", "s=N-1", "s=N/2", "s=N/2+1"];

#[allow(
    clippy::arithmetic_side_effects,
    reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
)]
fn ev_s_edge(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let which = stratum(i, 4);
    let p = presentation(i, 4);
    let s_bytes = match which {
        0 => be(1),
        1 => n_minus(1),
        2 => HALF_N,
        _ => arith::add_be(&HALF_N, &be(1)).0,
    };
    let s = scalar(&s_bytes).unwrap_or(Scalar::ONE);
    let v = d.retry(SCALAR_TRIES, Verify::fallback, |d| {
        // R = k·G, r = R.x (drawn again when at or above N, so step 8
        // decides), and the key d = (s·k − e)·r⁻¹ for which (r, s) signs h.
        let k = d.key();
        let rx = x_of(&base_mul(&k));
        let r = scalar(&rx)?;
        let h = d.bytes32();
        let key = (s * k - reduce(&h)) * Option::<Scalar>::from(r.invert())?;
        if bool::from(key.is_zero()) {
            return None;
        }
        Some(Verify {
            q: base_mul(&key),
            h,
            r: rx,
            s: s_bytes,
        })
    });
    d.finish(verify_case(
        label(S_EDGES[which], p),
        &v,
        p,
        Intent::Branch(EcdsaBranch::Step8Accept),
    ))
}

/// EV-rEdge's values of r.
const R_EDGES: [&str; 5] = ["r=1", "r=2", "r=N-3", "r=N-2", "r=N-1"];

fn ev_r_edge(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let which = stratum(i, 5);
    let p = presentation(i, 5);
    let r = match which {
        0 => be(1),
        1 => be(2),
        2 => n_minus(3),
        3 => n_minus(2),
        _ => n_minus(1),
    };
    let (v, branch) = if which < 4 {
        // r is an x coordinate: R = (r, y), Q = r⁻¹·(s·R − e·G), X = R.
        let v = d.retry(SCALAR_TRIES, Verify::fallback, |d| {
            let odd = d.coin();
            let big_r = decompress(&r, odd)?;
            let s = d.low_s();
            let h = d.bytes32();
            let q = solve_key(&scalar(&r)?, &s, &reduce(&h), &big_r)?;
            Some(Verify {
                q,
                h,
                r,
                s: scalar_bytes(&s),
            })
        });
        (v, EcdsaBranch::Step8Accept)
    } else {
        // N − 1 is no x coordinate and 2N − 1 is above P, so no signature
        // with this r verifies; r ≥ P − N, so step 9 rejects it.
        let q = base_mul(&d.key());
        let s = scalar_bytes(&d.low_s());
        let v = Verify {
            q,
            h: d.bytes32(),
            r,
            s,
        };
        (v, EcdsaBranch::Step9Reject)
    };
    d.finish(verify_case(
        label(R_EDGES[which], p),
        &v,
        p,
        Intent::Branch(branch),
    ))
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
)]
fn ev_small_x_key(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let p = Presentation::ALL[stratum(i, 4)];
    let v = d.retry(SCALAR_TRIES, Verify::fallback, |d| {
        // Q = (x, y) for x uniform among the values in 1..=1024 that
        // decompress; R = u1·G + u2·Q for random u1, u2; then r = R.x,
        // s = r/u2 and h = u1·s make u1 and u2 the verifier's own.
        let q = d.retry(
            DECOMPRESS_TRIES,
            || base_mul(&Scalar::ONE),
            |d| {
                let x = be(d.below(1024).saturating_add(1));
                let odd = d.coin();
                decompress(&x, odd)
            },
        );
        let (u1, u2) = (d.key(), d.key());
        let big_r = finite(&(ProjectivePoint::GENERATOR * u1 + ProjectivePoint::from(q) * u2))?;
        let rx = x_of(&big_r);
        let r = scalar(&rx).filter(|r| !bool::from(r.is_zero()))?;
        let mut s = r * Option::<Scalar>::from(u2.invert())?;
        let h = scalar_bytes(&(u1 * s));
        // A high s is negated: u1 and u2 then negate too, X becomes −R,
        // whose x is the same.
        if bool::from(s.is_high()) {
            s = -s;
        }
        Some(Verify {
            q,
            h,
            r: rx,
            s: scalar_bytes(&s),
        })
    });
    d.finish(verify_case(
        p.label(),
        &v,
        p,
        Intent::Branch(EcdsaBranch::Step8Accept),
    ))
}

fn es_random(e: &mut dyn Entropy, _: u64) -> Case {
    let mut d = Draw::new(e);
    let key = scalar_bytes(&d.key());
    let h = d.bytes32();
    d.finish(single("random", cmd::ecdsa_sign(&key, &h), Intent::Accept))
}

fn es_hash_gen(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let k = stratum(i, 4);
    let key = scalar_bytes(&d.key());
    let h = at_or_above_n(&mut d, k);
    d.finish(single(
        format!("h={}", AT_OR_ABOVE_N[k]),
        cmd::ecdsa_sign(&key, &h),
        Intent::Accept,
    ))
}

/// ES-boundary's private keys.
const SIGN_KEYS: [&str; 6] = ["1", "2", "N-1", "N-2", "N/2", "N/2+1"];

/// ES-boundary's hashes.
const SIGN_HASHES: [&str; 4] = ["0", "1", "leading-zeros", "random"];

fn es_boundary(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let k = stratum(i, 6);
    let which = digit(i, 6, 4);
    let key = match k {
        0 => be(1),
        1 => be(2),
        2 => n_minus(1),
        3 => n_minus(2),
        4 => HALF_N,
        _ => arith::add_be(&HALF_N, &be(1)).0,
    };
    let h = match which {
        0 => [0; 32],
        1 => be(1),
        2 => {
            let mut h = d.bytes32();
            let zeros = d.len_in(1, 31);
            h[..zeros].fill(0);
            h
        }
        _ => d.bytes32(),
    };
    d.finish(single(
        format!("d={}/h={}", SIGN_KEYS[k], SIGN_HASHES[which]),
        cmd::ecdsa_sign(&key, &h),
        Intent::Accept,
    ))
}

/// EV-honest.
pub const EV_HONEST: ClassSpec = ClassSpec {
    name: "EV-honest",
    family: Family::Ecdsa,
    commands: VERIFY,
    size: Size::Stratified {
        strata: 4,
        floor: FLOOR_A,
    },
    tier: Tier::A,
    generator: ev_honest,
    mix: ALL_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "a random key, hash and honest signature (random nonce, low S), in each of the four \
          presentations (i % 4)",
};

/// EV-highS.
pub const EV_HIGH_S: ClassSpec = ClassSpec {
    name: "EV-highS",
    family: Family::Ecdsa,
    commands: VERIFY,
    size: Size::Stratified {
        strata: 4,
        floor: FLOOR_A,
    },
    tier: Tier::A,
    generator: ev_high_s,
    mix: ALL_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "an honest signature with s replaced by N - s, which dcrd's verify accepts; four \
          presentations (i % 4)",
};

/// EV-tamper.
pub const EV_TAMPER: ClassSpec = ClassSpec {
    name: "EV-tamper",
    family: Family::Ecdsa,
    commands: VERIFY,
    size: Size::Stratified {
        strata: 4,
        floor: FLOOR_A,
    },
    tier: Tier::A,
    generator: ev_tamper,
    mix: NONE_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "an honest signature with one edit (i % 4): a bit of the hash, another key, a bit of \
          r or of s; presentation (i / 4) % 4",
};

/// EV-random.
pub const EV_RANDOM: ClassSpec = ClassSpec {
    name: "EV-random",
    family: Family::Ecdsa,
    commands: VERIFY,
    size: Size::Sampled { floor: FLOOR_A },
    tier: Tier::A,
    generator: ev_random,
    mix: NONE_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "a valid random key with random r, s and hash; presentation i % 4",
};

/// EV-keyenc.
pub const EV_KEYENC: ClassSpec = ClassSpec {
    name: "EV-keyenc",
    family: Family::Ecdsa,
    commands: VERIFY,
    size: Size::Stratified {
        strata: 2,
        floor: FLOOR_A,
    },
    tier: Tier::A,
    generator: ev_keyenc,
    mix: &[],
    pr_cases: PR_CASES,
    doc: "one key, hash and signature as four requests, one per presentation, valid or with an \
          EV-tamper edit (i % 2); every request must get the same verdict",
};

/// EV-keys.
pub const EV_KEYS: ClassSpec = ClassSpec {
    name: "EV-keys",
    family: Family::Ecdsa,
    commands: VERIFY,
    size: Size::Stratified {
        strata: 8,
        floor: FLOOR_A,
    },
    tier: Tier::A,
    generator: ev_keys,
    mix: ALL_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "honest signatures by the private keys 1, 2, 3, N-1, N-2, N-3, N/2 and N/2+1 (i % 8); \
          presentation (i / 8) % 4",
};

/// EV-hashGEN.
pub const EV_HASH_GEN: ClassSpec = ClassSpec {
    name: "EV-hashGEN",
    family: Family::Ecdsa,
    commands: VERIFY,
    size: Size::Stratified {
        strata: 3,
        floor: FLOOR_A,
    },
    tier: Tier::A,
    generator: ev_hash_gen,
    mix: ALL_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "hashes at or above N (i % 3): high (N, N+1, 2^256-1 or random, (i / 3) % 4) signed \
          over h mod N and verified with h; alias-up, verified with h + N; alias-down, \
          verified with h - N; presentation (i / 12) % 4",
};

/// EV-hash0.
pub const EV_HASH0: ClassSpec = ClassSpec {
    name: "EV-hash0",
    family: Family::Ecdsa,
    commands: VERIFY,
    size: Size::Stratified {
        strata: 2,
        floor: FLOOR_A,
    },
    tier: Tier::A,
    generator: ev_hash0,
    mix: ALL_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "honest signatures over the hashes 0 and N (i % 2), where u1 = 0; presentation \
          (i / 2) % 4",
};

/// EV-zero.
pub const EV_ZERO: ClassSpec = ClassSpec {
    name: "EV-zero",
    family: Family::Ecdsa,
    commands: VERIFY,
    size: Size::Stratified {
        strata: 6,
        floor: FLOOR_A,
    },
    tier: Tier::A,
    generator: ev_zero,
    mix: NONE_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "an honest key and hash with r, s or both zero (i % 3), raw or DER ((i / 3) % 2): raw \
          ends at verify step 1, DER at ErrSigRIsZero or ErrSigSIsZero; raw presentation \
          (i / 6) % 3",
};

/// EV-range.
pub const EV_RANGE: ClassSpec = ClassSpec {
    name: "EV-range",
    family: Family::Ecdsa,
    commands: VERIFY_RAW,
    size: Size::Stratified {
        strata: 4,
        floor: FLOOR_A,
    },
    tier: Tier::A,
    generator: ev_range,
    mix: NONE_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "r, s or both at or above N (N, N+1, 2^256-1 or random, (i / 12) % 4) at the raw \
          layer, or a format-0x05 key ahead of r = N (i % 4); raw presentation (i / 4) % 3",
};

/// EV-xGEN-true.
pub const EV_XGEN_TRUE: ClassSpec = ClassSpec {
    name: "EV-xGEN-true",
    family: Family::Ecdsa,
    commands: VERIFY,
    size: Size::Stratified {
        strata: 4,
        floor: FLOOR_B,
    },
    tier: Tier::B,
    generator: ev_xgen_true,
    mix: ALL_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "constructed so that X.x = r + N with r < P - N: dcrd accepts at verify step 10; four \
          presentations (i % 4)",
};

/// EV-xGEN-false.
pub const EV_XGEN_FALSE: ClassSpec = ClassSpec {
    name: "EV-xGEN-false",
    family: Family::Ecdsa,
    commands: VERIFY,
    size: Size::Stratified {
        strata: 3,
        floor: FLOOR_B,
    },
    tier: Tier::B,
    generator: ev_xgen_false,
    mix: NONE_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "r < P - N with X.x neither r nor r + N (i % 3: an EV-xGEN-true case with s + 1 or a \
          hash bit flipped, or an unrelated key): dcrd rejects at verify step 10; \
          presentation (i / 3) % 4",
};

/// EV-xGEN-wrap.
pub const EV_XGEN_WRAP: ClassSpec = ClassSpec {
    name: "EV-xGEN-wrap",
    family: Family::Ecdsa,
    commands: VERIFY,
    size: Size::Stratified {
        strata: 4,
        floor: FLOOR_B,
    },
    tier: Tier::B,
    generator: ev_xgen_wrap,
    mix: NONE_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "r = X.x + P - N in [P - N, N), so (r + N) mod P = X.x: dcrd rejects at verify step 9, \
          where a verifier without it accepts; four presentations (i % 4)",
};

/// EV-infinity.
pub const EV_INFINITY: ClassSpec = ClassSpec {
    name: "EV-infinity",
    family: Family::Ecdsa,
    commands: VERIFY,
    size: Size::Stratified {
        strata: 4,
        floor: FLOOR_B,
    },
    tier: Tier::B,
    generator: ev_infinity,
    mix: NONE_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "Q = -(e/r)·G, so u1·G + u2·Q is the point at infinity: dcrd rejects at verify step 6; \
          four presentations (i % 4)",
};

/// EV-double.
pub const EV_DOUBLE: ClassSpec = ClassSpec {
    name: "EV-double",
    family: Family::Ecdsa,
    commands: VERIFY,
    size: Size::Stratified {
        strata: 4,
        floor: FLOOR_B,
    },
    tier: Tier::B,
    generator: ev_double,
    mix: ALL_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "Q = (e/r)·G with r the x of 2(e/s)·G, so u1·G = u2·Q and the sum doubles: dcrd \
          accepts at verify step 8; four presentations (i % 4)",
};

/// EV-sEdge.
pub const EV_S_EDGE: ClassSpec = ClassSpec {
    name: "EV-sEdge",
    family: Family::Ecdsa,
    commands: VERIFY,
    size: Size::Stratified {
        strata: 4,
        floor: FLOOR_B,
    },
    tier: Tier::B,
    generator: ev_s_edge,
    mix: ALL_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "valid signatures with s at 1, N-1, N/2 and N/2+1 (i % 4), the key solved for: dcrd \
          accepts at verify step 8; presentation (i / 4) % 4",
};

/// EV-rEdge.
pub const EV_R_EDGE: ClassSpec = ClassSpec {
    name: "EV-rEdge",
    family: Family::Ecdsa,
    commands: VERIFY,
    size: Size::Stratified {
        strata: 5,
        floor: FLOOR_B,
    },
    tier: Tier::B,
    generator: ev_r_edge,
    // Four strata of five accept: the share is 4/5 to within one case.
    mix: &[Mix::AcceptRate {
        lo: 0.7999,
        hi: 0.8001,
        min_n: MIX_MIN_N,
    }],
    pr_cases: PR_CASES,
    doc: "r at 1, 2, N-3 and N-2, valid signatures with the key solved for (verify step 8), \
          and r = N-1, which no signature has (step 9) (i % 5); presentation (i / 5) % 4",
};

/// EV-smallXKey.
pub const EV_SMALL_X_KEY: ClassSpec = ClassSpec {
    name: "EV-smallXKey",
    family: Family::Ecdsa,
    commands: VERIFY,
    size: Size::Stratified {
        strata: 4,
        floor: FLOOR_B,
    },
    tier: Tier::B,
    generator: ev_small_x_key,
    mix: ALL_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "keys with x in 1..=1024 and a signature solved for them: dcrd accepts at verify step \
          8; four presentations (i % 4)",
};

/// ES-random.
pub const ES_RANDOM: ClassSpec = ClassSpec {
    name: "ES-random",
    family: Family::Ecdsa,
    commands: SIGN,
    size: Size::Sampled { floor: FLOOR_B },
    tier: Tier::B,
    generator: es_random,
    mix: ALL_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "RFC6979 signing of a random hash by a random key, compared byte for byte",
};

/// ES-hashGEN.
pub const ES_HASH_GEN: ClassSpec = ClassSpec {
    name: "ES-hashGEN",
    family: Family::Ecdsa,
    commands: SIGN,
    size: Size::Stratified {
        strata: 4,
        floor: FLOOR_B,
    },
    tier: Tier::B,
    generator: es_hash_gen,
    mix: ALL_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "signing hashes at or above N (N, N+1, 2^256-1 or random, i % 4), where the nonce \
          derivation sees the unreduced hash",
};

/// ES-boundary.
pub const ES_BOUNDARY: ClassSpec = ClassSpec {
    name: "ES-boundary",
    family: Family::Ecdsa,
    commands: SIGN,
    size: Size::Stratified {
        strata: 24,
        floor: FLOOR_B,
    },
    tier: Tier::B,
    generator: es_boundary,
    mix: ALL_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "the keys 1, 2, N-1, N-2, N/2 and N/2+1 (i % 6) over the hashes 0, 1, leading zero \
          bytes then random, and random ((i / 6) % 4)",
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::class::generate;
    use crate::r#gen::decompress;
    use crate::model::ModelOutcome;
    use crate::model::ecdsa::{decode_der, decode_key, request_outcome, verify};
    use std::collections::BTreeSet;

    /// Every EV and ES class.
    const CLASSES: [&ClassSpec; 21] = [
        &EV_HONEST,
        &EV_HIGH_S,
        &EV_TAMPER,
        &EV_RANDOM,
        &EV_KEYENC,
        &EV_KEYS,
        &EV_HASH_GEN,
        &EV_HASH0,
        &EV_ZERO,
        &EV_RANGE,
        &EV_XGEN_TRUE,
        &EV_XGEN_FALSE,
        &EV_XGEN_WRAP,
        &EV_INFINITY,
        &EV_DOUBLE,
        &EV_S_EDGE,
        &EV_R_EDGE,
        &EV_SMALL_X_KEY,
        &ES_RANDOM,
        &ES_HASH_GEN,
        &ES_BOUNDARY,
    ];

    /// One verify request decoded: Q, h, r, s.
    fn decode(request: &Request) -> (AffinePoint, [u8; 32], [u8; 32], [u8; 32]) {
        match request.cmd {
            Cmd::EcdsaVerifyRaw => {
                let data = &request.data;
                let len = usize::from(data[0]);
                let (key, rest) = data[1..].split_at(len);
                let q = decode_key(key).expect("a valid key");
                let h: [u8; 32] = rest[..32].try_into().expect("hash");
                let r: [u8; 32] = rest[32..64].try_into().expect("r");
                let s: [u8; 32] = rest[64..].try_into().expect("s");
                (q, h, r, s)
            }
            Cmd::EcdsaVerify => {
                let q = decode_key(&request.data[..33]).expect("a valid key");
                let h: [u8; 32] = request.data[33..65].try_into().expect("hash");
                let (r, s) = decode_der(&request.data[65..]).expect("minimal DER");
                (q, h, r, s)
            }
            other => panic!("{other:?} is not a verify command"),
        }
    }

    /// X = u1·G + u2·Q, computed here apart from the model, with u1 = e/s
    /// and u2 = r/s; `None` at infinity.  Also u1·G and u2·Q.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
    )]
    fn sum(
        q: &AffinePoint,
        h: &[u8; 32],
        r: &[u8; 32],
        s: &[u8; 32],
    ) -> (Option<[u8; 32]>, ProjectivePoint, ProjectivePoint) {
        let r = scalar(r).expect("r below N");
        let w = Option::<Scalar>::from(scalar(s).expect("s below N").invert()).expect("s nonzero");
        let u1g = ProjectivePoint::GENERATOR * (reduce(h) * w);
        let u2q = ProjectivePoint::from(*q) * (r * w);
        (finite(&(u1g + u2q)).map(|x| x_of(&x)), u1g, u2q)
    }

    fn cases(class: &ClassSpec, n: u64) -> impl Iterator<Item = (u64, Case)> + '_ {
        (0..n).map(move |i| (i, generate(class, 0x7e57_5eed, i)))
    }

    /// The witness predicates: per constructed class, a few cases decoded
    /// from their request bytes, X computed apart from the model, and the
    /// branch each must reach shown on the numbers.
    #[test]
    fn constructed_classes_reach_their_branches() {
        let r_plus_n = |r: &[u8; 32]| arith::add_be(r, &N).0;
        for (i, case) in cases(&EV_XGEN_TRUE, 16) {
            let (q, h, r, s) = decode(&case.requests[0]);
            assert!(r < P_MINUS_N, "case {i}: r < P - N");
            assert_eq!(
                sum(&q, &h, &r, &s).0,
                Some(r_plus_n(&r)),
                "case {i}: X.x = r + N"
            );
        }
        for (i, case) in cases(&EV_XGEN_FALSE, 24) {
            let (q, h, r, s) = decode(&case.requests[0]);
            assert!(r < P_MINUS_N, "case {i}: r < P - N");
            let x = sum(&q, &h, &r, &s).0.expect("finite");
            assert!(
                x != r && x != r_plus_n(&r),
                "case {i}: X.x not in {{r, r + N}}"
            );
            if case.variant.starts_with("s+1/") {
                let s_less = scalar_bytes(&(scalar(&s).expect("s") - Scalar::ONE));
                assert_eq!(
                    sum(&q, &h, &r, &s_less).0,
                    Some(r_plus_n(&r)),
                    "case {i}: (Q, h, r, s - 1) is an EV-xGEN-true case"
                );
            }
        }
        for (i, case) in cases(&EV_XGEN_WRAP, 16) {
            let (q, h, r, s) = decode(&case.requests[0]);
            assert!(P_MINUS_N <= r && r < N, "case {i}: P - N <= r < N");
            let x = sum(&q, &h, &r, &s).0.expect("finite");
            let (wrapped, borrow) = arith::sub_be(&r, &P_MINUS_N);
            assert!(!borrow);
            assert_eq!(x, wrapped, "case {i}: X.x = r + N - P");
            assert_ne!(x, r, "case {i}: step 8 fails");
        }
        for (i, case) in cases(&EV_INFINITY, 16) {
            let (q, h, r, s) = decode(&case.requests[0]);
            assert_eq!(sum(&q, &h, &r, &s).0, None, "case {i}: X = O");
        }
        for (i, case) in cases(&EV_DOUBLE, 16) {
            assert!(case.tags.has(Tag::Doubled));
            let (q, h, r, s) = decode(&case.requests[0]);
            let (x, u1g, u2q) = sum(&q, &h, &r, &s);
            assert_eq!(u1g, u2q, "case {i}: u1·G = u2·Q");
            assert_eq!(x, Some(r), "case {i}: X.x = r");
        }
        for (i, case) in cases(&EV_S_EDGE, 16) {
            let (q, h, r, s) = decode(&case.requests[0]);
            let want = match stratum(i, 4) {
                0 => be(1),
                1 => n_minus(1),
                2 => HALF_N,
                _ => arith::add_be(&HALF_N, &be(1)).0,
            };
            assert_eq!(s, want, "case {i}: s at its edge");
            assert_eq!(sum(&q, &h, &r, &s).0, Some(r), "case {i}: X.x = r");
        }
        for (i, case) in cases(&EV_R_EDGE, 20) {
            let (q, h, r, s) = decode(&case.requests[0]);
            let x = sum(&q, &h, &r, &s).0.expect("finite");
            if stratum(i, 5) == 4 {
                assert_eq!(r, n_minus(1));
                assert!(r >= P_MINUS_N && x != r, "case {i}: step 9 decides");
                assert_eq!(decompress(&r, false), None, "N - 1 is no x coordinate");
            } else {
                assert_eq!(x, r, "case {i}: X.x = r");
            }
        }
        for (i, case) in cases(&EV_SMALL_X_KEY, 16) {
            let (q, h, r, s) = decode(&case.requests[0]);
            assert!(
                x_of(&q) <= be(1024) && x_of(&q) >= be(1),
                "case {i}: a small x"
            );
            assert!(s <= HALF_N, "case {i}: low S");
            assert_eq!(sum(&q, &h, &r, &s).0, Some(r), "case {i}: X.x = r");
        }
        for (i, case) in cases(&EV_ZERO, 24) {
            let (_, _, r, s) = decode(&case.requests[0]);
            assert!(r == [0; 32] || s == [0; 32], "case {i}: a zero component");
        }
    }

    /// Every EV request with a branch intent ends where the model says,
    /// every accept intent is accepted by the model and every reject
    /// rejected or out of range, for 16 cases per class and at least one
    /// per (stratum, presentation) pair.
    #[test]
    fn every_intent_holds_in_the_model() {
        for class in CLASSES {
            let n = class.pr_cases.max(16);
            for (i, case) in cases(class, n) {
                assert!(
                    !case.tags.has(Tag::Fallback),
                    "{} {i}: fallback",
                    class.name
                );
                for (request, intent) in case.requests.iter().zip(&case.intents) {
                    let got = request_outcome(request);
                    let branch = match got {
                        Some(ModelOutcome::Ecdsa { branch, .. }) => Some(branch),
                        _ => None,
                    };
                    let ctx = format!("{} case {i} ({})", class.name, case.variant);
                    match intent {
                        Intent::Branch(want) => assert_eq!(branch, Some(*want), "{ctx}"),
                        Intent::Accept if request.cmd.is_verify() => {
                            assert!(branch.is_some_and(EcdsaBranch::accepts), "{ctx}: {got:?}");
                        }
                        Intent::Reject => {
                            assert!(!branch.is_some_and(EcdsaBranch::accepts), "{ctx}: {got:?}");
                        }
                        Intent::RejectKind(kind) => {
                            // A range or key kind never reaches verify, so
                            // the model has no branch; a zero component in
                            // DER is rejected by dcrd's parser, and the
                            // model, reading the DER leniently, ends at
                            // step 1.
                            assert!(
                                branch.is_none() || branch == Some(EcdsaBranch::Step1Zero),
                                "{ctx}: {kind}, model {got:?}"
                            );
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    /// The model's branch for a constructed class matches the predicate
    /// computed above, and a doubling it reports is the generator's tag.
    #[test]
    fn the_model_confirms_the_doubling() {
        for (i, case) in cases(&EV_DOUBLE, 16) {
            assert_eq!(
                request_outcome(&case.requests[0]),
                Some(ModelOutcome::Ecdsa {
                    branch: EcdsaBranch::Step8Accept,
                    doubled: true
                }),
                "case {i}"
            );
        }
        for (i, case) in cases(&EV_HONEST, 16) {
            let (q, h, r, s) = decode(&case.requests[0]);
            assert_eq!(
                verify(&q, &h, &r, &s),
                Some((EcdsaBranch::Step8Accept, false)),
                "case {i}"
            );
        }
    }

    /// Each class's per-PR cases cover every variant it can produce (every
    /// stratum, and for an EV class every (stratum, presentation) pair:
    /// its labels are a function of the index, so the count of distinct
    /// labels says that all of them came up), and every command it lists.
    #[test]
    fn per_pr_counts_cover_every_variant() {
        let all_labels: [(&ClassSpec, usize); 21] = [
            (&EV_HONEST, 4),
            (&EV_HIGH_S, 4),
            (&EV_TAMPER, 16),
            (&EV_RANDOM, 4),
            (&EV_KEYENC, 2),
            (&EV_KEYS, 32),
            (&EV_HASH_GEN, 24),
            (&EV_HASH0, 8),
            (&EV_ZERO, 12),
            (&EV_RANGE, 37),
            (&EV_XGEN_TRUE, 4),
            (&EV_XGEN_FALSE, 12),
            (&EV_XGEN_WRAP, 4),
            (&EV_INFINITY, 4),
            (&EV_DOUBLE, 4),
            (&EV_S_EDGE, 16),
            (&EV_R_EDGE, 20),
            (&EV_SMALL_X_KEY, 4),
            (&ES_RANDOM, 1),
            (&ES_HASH_GEN, 4),
            (&ES_BOUNDARY, 24),
        ];
        for (class, labels) in all_labels {
            let mut variants = BTreeSet::new();
            let mut commands = BTreeSet::new();
            for (_, case) in cases(class, class.pr_cases) {
                commands.extend(case.requests.iter().map(|r| r.cmd));
                variants.insert(case.variant.into_owned());
            }
            assert_eq!(variants.len(), labels, "{}: {variants:?}", class.name);
            assert_eq!(
                commands,
                class.commands.iter().copied().collect(),
                "{}",
                class.name
            );
        }
    }

    /// The signing classes keep keys in [1, N-1] and send 64 bytes.
    #[test]
    fn signing_keys_stay_in_range() {
        for class in [&ES_RANDOM, &ES_HASH_GEN, &ES_BOUNDARY] {
            for (i, case) in cases(class, 48) {
                let data = &case.requests[0].data;
                assert_eq!(data.len(), 64);
                let key: [u8; 32] = data[..32].try_into().expect("key");
                assert!(
                    scalar(&key).is_some_and(|k| !bool::from(k.is_zero())),
                    "{} {i}",
                    class.name
                );
            }
        }
        for (i, case) in cases(&ES_HASH_GEN, 8) {
            let h: [u8; 32] = case.requests[0].data[32..].try_into().expect("hash");
            assert!(h >= N, "case {i}: a hash at or above N");
        }
    }
}
