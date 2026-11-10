// SPDX-License-Identifier: ISC
//! Compact recovery's and EC-Schnorr-DCRv0 verification's branches, built
//! on k256 and judged by dcrd (ADR-0016): every case is a signature
//! constructed so that recovery computes chosen scalars u1 and u2, or
//! verification reaches a chosen point R, and dcrd's answer through
//! `tools/oracle`'s `ecdsa_recover_compact` and `schnorr_verify` is the
//! reference, never k256's or this crate's.  A recovered key is also
//! compared as bytes with a recovery on k256, and each case checks the
//! step this crate reports against dcrd's algorithm run on k256.
//!
//! Recovery:
//!
//! - The collision grid: R in {+-G, +-2G, +-3G, +-lambda G, +-lambda^2 G,
//!   +-2^128 G, +-lambda 2^128 G}, u2 = a + b*lambda (nonzero), u1 = c +
//!   d*2^128, a to d in [-3, 3]; r = R.x with the code of R.y's parity,
//!   s = u2*r and e = -u1*r as the hash, so recovery recomputes exactly
//!   (u1, u2) and Q = u1*G + u2*R, where the Straus loop's four digit
//!   strings collide, Q at infinity included.
//! - Recovery's shapes: every recovery code with both compressed flags
//!   (the overflow codes from R.x in [N, N + 2^32)); hashes 0 and N (e = 0,
//!   so u1 = 0 and the G half is empty); u2 = 1 (s = r); a recovered Q
//!   with a tiny x, a tiny y, x near p or x in [N, P), R solved for random
//!   (u1, u2); Q at infinity; and an R.x no point has.
//!
//! Schnorr verification:
//!
//! - Valid signatures with s = 0: kG of even y, r = kG's x, e = BLAKE-256(r
//!   || hash), the key Q = (k/e)G; the odd twin (-k, the same r), which
//!   step 9 rejects; and the same key with the next hash, which another e
//!   sends to a random R.
//! - R with tiny coordinates and near p: R with a tiny x, a tiny y, x near
//!   p or x in [N, P), for a random s and for s = 0, the key solved as
//!   Q = (R - s*G)/e, which anyone can publish; and r = R.x + 1 with the
//!   key solved again, which reaches R and rejects at step 10 (or 9).
//! - R at infinity: the key Q = -(s/e)G for a random s and a random r
//!   below P, so that R = s*G + e*Q is the point at infinity, which step 8
//!   rejects.
//!
//! Below the 10^6 volume (`DCROXIDE_VARTIME_CASES`, as CI's soak-asserts
//! run sets it) or in builds with debug assertions, the grid runs [-1, 1]
//! and the other classes a fixed subset.  The committed file
//! `tests/data/vartime_recovery_schnorr_branches.txt` holds the first case
//! of each (grid key or class, step) of the small selection, and the grid
//! cases whose Straus loop doubles through an addition at each of its four
//! call sites, with dcrd's answer: one test checks it everywhere, without
//! Go, and one rebuilds it with dcrd and compares it byte for byte.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "k256 scalar and field operators, which are modular, and byte \
              offsets within 32-byte arrays"
)]

mod common;

use std::collections::BTreeSet;
use std::fmt::Write as _;

use common::{
    add, data_lines, full, grid_bases, point_at, rand_scalar, require_regenerated, sc_i64, scalar,
    small, sub, tiny_y_xs,
};
use dcroxide_dcrec::secp256k1::ecdsa::recover_compact;
use dcroxide_dcrec::secp256k1::schnorr::{self, Error as SchnorrError};
use dcroxide_dcrec::secp256k1::{FIELD_PRIME_BYTES, GROUP_ORDER_BYTES, PublicKey};
use dcroxide_testutil::{Oracle, SplitMix64, hex, oracle_or_skip, unhex};
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::group::{CurveAffine, Group};
use k256::elliptic_curve::ops::{MulByGeneratorVartime, Reduce};
use k256::elliptic_curve::point::{AffineCoordinates, BatchNormalize};
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};

/// The committed vectors.
const COMMITTED: &str = include_str!("data/vartime_recovery_schnorr_branches.txt");

/// The recovery command.
const RECOVER: &str = "ecdsa_recover_compact";
/// The Schnorr verification command.
const SCHNORR: &str = "schnorr_verify";

/// One constructed case.
struct Case {
    /// The class: `grid`, a recovery shape or a Schnorr class.
    class: &'static str,
    /// What within the class, and the step dcrd's algorithm decides at, as
    /// `<what>/<step>`.
    variant: String,
    /// [`RECOVER`] or [`SCHNORR`].
    command: &'static str,
    /// The request: hash || 65-byte compact signature, or 33-byte
    /// compressed key || hash || r || s.
    request: Vec<u8>,
}

impl Case {
    /// The step the variant names.
    fn step(&self) -> &str {
        self.variant.rsplit('/').next().unwrap_or("")
    }
}

// ---------------------------------------------------------------------------
// Compact recovery.

/// A key's serialization as dcrd's `RecoverCompact` returns it with the
/// signature's flag, and the flag: the oracle's `ok:<hex>:<flag>`.
fn ok_answer(key: &[u8; 65], compressed: bool) -> String {
    let bytes = if compressed {
        let mut c = [0u8; 33];
        c[0] = 2 | (key[64] & 1);
        c[1..].copy_from_slice(&key[1..33]);
        hex(&c)
    } else {
        hex(key)
    };
    format!("ok:{bytes}:{compressed}")
}

/// Recovery on k256, independent of this crate's seam: decompression, the
/// reduction, `invert_vartime`, the combined multiply and one
/// `batch_normalize_vartime`.  `Err(step)` for the step that fails (no
/// point for R.x, Q at infinity), else the key, uncompressed.  The
/// request has passed recovery's steps 1 to 3.
fn k256_recover(request: &[u8]) -> Result<[u8; 65], &'static str> {
    let (hash, sig) = request.split_at(32);
    let code = sig[0] - 27;
    let r: [u8; 32] = sig[1..33].try_into().expect("32 bytes");
    let s: [u8; 32] = sig[33..].try_into().expect("32 bytes");
    let x = if code & 2 != 0 {
        add(&r, &GROUP_ORDER_BYTES)
    } else {
        r
    };
    let big_r = point_at(&x, code & 1 != 0).ok_or("step4-5")?;
    let (r, s) = (scalar(&r), scalar(&s));
    let h: [u8; 32] = hash.try_into().expect("32 bytes");
    let e = <Scalar as Reduce<FieldBytes>>::reduce(&h.into());
    let w = r.invert_vartime().expect("r nonzero");
    let q = ProjectivePoint::mul_by_generator_and_mul_add_vartime(
        &-(e * w),
        &(s * w),
        &ProjectivePoint::from(big_r),
    );
    if bool::from(q.is_identity()) {
        return Err("step10");
    }
    let [a] =
        <ProjectivePoint as BatchNormalize<[ProjectivePoint; 1]>>::batch_normalize_vartime(&[q]);
    Ok(a.to_sec1_point(false)
        .as_bytes()
        .try_into()
        .expect("65 bytes"))
}

/// This crate's answer to a recovery request, as the oracle serializes
/// dcrd's.
fn our_recovery(request: &[u8]) -> String {
    let (hash, sig) = request.split_at(32);
    match recover_compact(sig, hash.try_into().expect("32 bytes")) {
        Ok((key, compressed)) => ok_answer(&key.serialize_uncompressed(), compressed),
        Err(e) => format!("err:{}", e.kind_name()),
    }
}

/// dcrd's answer to a recovery request, in the same form.
fn dcrd_recovery(oracle: &mut Oracle, request: &[u8]) -> String {
    let resp = oracle.call(RECOVER, request);
    match resp.get("error").and_then(|e| e.as_str()) {
        None => format!(
            "ok:{}:{}",
            resp["result"].as_str().expect("result"),
            resp["was_compressed"].as_str().expect("was_compressed")
        ),
        Some(_) => format!("err:{}", resp["kind"].as_str().expect("kind")),
    }
}

/// The recovery case for R, u1 and u2: r = R.x (less N, with the overflow
/// bit, when R.x is at or above N), the code's low bit R.y's parity,
/// s = u2*r and e = -u1*r as the hash (below N, so dcrd's reduction keeps
/// it), so that recovery recomputes (u1, u2) and Q = u1*G + u2*R.  `None`
/// when r would be zero.  The step is dcrd's algorithm's on Q.
fn recovery_case(
    class: &'static str,
    what: &str,
    big_r: &AffinePoint,
    u1: &Scalar,
    u2: &Scalar,
    compressed: bool,
) -> Option<Case> {
    let x: [u8; 32] = big_r.x().into();
    let (rb, overflow) = if x >= GROUP_ORDER_BYTES {
        (sub(&x, &GROUP_ORDER_BYTES), 2)
    } else {
        (x, 0)
    };
    let r = Option::<Scalar>::from(Scalar::from_repr(rb.into()))?;
    if bool::from(r.is_zero()) {
        return None;
    }
    let e = -(*u1 * r);
    let s = *u2 * r;
    let q = ProjectivePoint::GENERATOR * u1 + ProjectivePoint::from(*big_r) * u2;
    let step = if bool::from(q.is_identity()) {
        "step10"
    } else {
        "key"
    };
    Some(recovery_request(
        class,
        what,
        &e.to_repr().into(),
        &rb,
        &s.to_repr().into(),
        overflow | big_r.y_is_odd().unwrap_u8(),
        compressed,
        step,
    ))
}

/// A recovery request from its parts.
#[allow(clippy::too_many_arguments, reason = "a request's named parts")]
fn recovery_request(
    class: &'static str,
    what: &str,
    hash: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
    code: u8,
    compressed: bool,
    step: &str,
) -> Case {
    let mut request = hash.to_vec();
    request.push(27 + code + if compressed { 4 } else { 0 });
    request.extend_from_slice(r);
    request.extend_from_slice(s);
    Case {
        class,
        variant: format!("{what}/{step}"),
        command: RECOVER,
        request,
    }
}

/// The recovery grid at range `range`.
fn recovery_grid(range: i64) -> Vec<Case> {
    let lam = scalar(&common::LAMBDA);
    let t = common::pow2_128();
    let mut out = Vec::new();
    for (name, b) in grid_bases() {
        for (sign, big_r) in [("+", b), ("-", -b)] {
            let ra = big_r.to_affine();
            for a in -range..=range {
                for bb in -range..=range {
                    let u2 = sc_i64(a) + sc_i64(bb) * lam;
                    if bool::from(u2.is_zero()) {
                        continue;
                    }
                    for c in -range..=range {
                        for d in -range..=range {
                            let u1 = sc_i64(c) + sc_i64(d) * t;
                            let compressed = out.len() % 2 == 0;
                            let what = format!("{sign}{name}");
                            out.extend(recovery_case("grid", &what, &ra, &u1, &u2, compressed));
                        }
                    }
                }
            }
        }
    }
    out
}

/// Target points with a tiny x, a tiny y, x near p or x in [N, N + 2^32),
/// as (class, point), with both parities where the class has them;
/// `subset` keeps the first eight of each class.
fn boundary_points(subset: bool) -> Vec<(&'static str, AffinePoint)> {
    let mut rng = SplitMix64(0x7273_626f_756e_6431);
    let mut out: Vec<(&'static str, AffinePoint)> = Vec::new();
    let mut push = |class: &'static str, x: &[u8; 32], odd: bool| {
        if let Some(p) = point_at(x, odd) {
            out.push((class, p));
        }
    };
    for x in 1..=64 {
        push("tiny-x", &small(x), false);
        push("tiny-x", &small(x), true);
    }
    for x in tiny_y_xs() {
        push("tiny-y", &x, false);
        push("tiny-y", &x, true);
    }
    for k in 1..=64u64 {
        let x = sub(&FIELD_PRIME_BYTES, &small(k));
        push("x-near-p", &x, false);
        push("x-near-p", &x, true);
    }
    let mut ks: Vec<u64> = (1..=64).collect();
    ks.extend((0..64).map(|_| rng.below(1 << 32)));
    for k in ks {
        let x = add(&GROUP_ORDER_BYTES, &small(k));
        push("x-above-n", &x, rng.below(2) == 1);
    }
    if subset {
        let mut kept: Vec<(&'static str, AffinePoint)> = Vec::new();
        for (c, p) in out {
            if kept.iter().filter(|(k, _)| *k == c).count() < 8 {
                kept.push((c, p));
            }
        }
        kept
    } else {
        out
    }
}

/// Recovery's shapes; `subset` keeps a fixed few of each.
fn recovery_shapes(subset: bool) -> Vec<Case> {
    let mut rng = SplitMix64(0x7265_636f_7665_7279);
    let g = ProjectivePoint::GENERATOR;
    let n = if subset { 4 } else { 64 };
    let mut out = Vec::new();

    // Every code with both flags: R random (codes 0 and 1) and R.x in
    // [N, N + 2^32) (codes 2 and 3), negated where needed for the parity.
    let above_n: Vec<AffinePoint> = boundary_points(false)
        .into_iter()
        .filter(|(c, _)| *c == "x-above-n")
        .map(|(_, p)| p)
        .collect();
    for i in 0..4 * n {
        let (code, compressed) = (i % 4, (i / 4) % 2 == 0);
        let big_r = if code & 2 == 0 {
            (g * rand_scalar(&mut rng)).to_affine()
        } else {
            above_n[i % above_n.len()]
        };
        let big_r = if bool::from(big_r.y_is_odd()) == (code & 1 == 1) {
            big_r
        } else {
            -big_r
        };
        let (u1, u2) = (rand_scalar(&mut rng), rand_scalar(&mut rng));
        let what = format!("code{code}-{}", if compressed { "comp" } else { "uncomp" });
        let c = recovery_case("code", &what, &big_r, &u1, &u2, compressed);
        if let Some(c) = &c {
            let header = usize::from(c.request[32] - 27);
            assert_eq!(header, code + if compressed { 4 } else { 0 }, "{what}");
        }
        out.extend(c);
    }

    // e = 0, from a hash of 0 and a hash of N: u1 = 0.
    for i in 0..2 * n {
        let big_r = (g * rand_scalar(&mut rng)).to_affine();
        let u2 = rand_scalar(&mut rng);
        let Some(mut c) = recovery_case("e-zero", "", &big_r, &Scalar::ZERO, &u2, i % 2 == 0)
        else {
            continue;
        };
        let (hash, what) = if i % 4 < 2 {
            ([0u8; 32], "hash-0")
        } else {
            (GROUP_ORDER_BYTES, "hash-n")
        };
        c.request[..32].copy_from_slice(&hash);
        c.variant = format!("{what}/{}", c.step());
        out.push(c);
    }

    // u2 = 1: s = r.
    for i in 0..n {
        let big_r = (g * rand_scalar(&mut rng)).to_affine();
        let u1 = rand_scalar(&mut rng);
        out.extend(recovery_case(
            "u2-one",
            "s=r",
            &big_r,
            &u1,
            &Scalar::ONE,
            i % 2 == 0,
        ));
    }

    // Q at the boundaries: R = (Q - u1*G)/u2 for random (u1, u2).
    for (i, (class, q)) in boundary_points(subset).into_iter().enumerate() {
        let (u1, u2) = (rand_scalar(&mut rng), rand_scalar(&mut rng));
        let big_r = (ProjectivePoint::from(q) - g * u1) * u2.invert_vartime().expect("nonzero");
        let big_r = big_r.to_affine();
        if bool::from(big_r.is_identity()) {
            continue;
        }
        let class = match class {
            "tiny-x" => "q-tiny-x",
            "tiny-y" => "q-tiny-y",
            "x-near-p" => "q-x-near-p",
            _ => "q-x-above-n",
        };
        out.extend(recovery_case(
            class,
            "solved-r",
            &big_r,
            &u1,
            &u2,
            i % 2 == 0,
        ));
    }

    // Q at infinity: R = cG and u1 = -u2*c.
    for i in 0..n {
        let (c, u2) = (rand_scalar(&mut rng), rand_scalar(&mut rng));
        let big_r = (g * c).to_affine();
        out.extend(recovery_case(
            "q-infinity",
            "r=cG",
            &big_r,
            &-(u2 * c),
            &u2,
            i % 2 == 0,
        ));
    }

    // An R.x no point has, either oddness, and r + N with the overflow
    // bit.
    let mut found = 0;
    let mut v = 1u64;
    while found < n {
        let r = small(v);
        v += 1;
        if point_at(&r, false).is_some() {
            continue;
        }
        let s = rand_scalar(&mut rng).to_repr().into();
        let mut hash = [0u8; 32];
        rng.fill(&mut hash);
        out.push(recovery_request(
            "no-point",
            "r",
            &hash,
            &r,
            &s,
            u8::from(found % 2 == 1),
            false,
            "step4-5",
        ));
        found += 1;
    }
    let mut found = 0;
    let mut v = 1u64;
    while found < n {
        let r = small(v);
        v += 1;
        if point_at(&add(&r, &GROUP_ORDER_BYTES), false).is_some() {
            continue;
        }
        let s = rand_scalar(&mut rng).to_repr().into();
        let mut hash = [0u8; 32];
        rng.fill(&mut hash);
        out.push(recovery_request(
            "no-point",
            "r+n",
            &hash,
            &r,
            &s,
            2 | u8::from(found % 2 == 1),
            true,
            "step4-5",
        ));
        found += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// Schnorr verification.

/// BLAKE-256(r || hash) as a scalar, `None` at or above N (dcrd's step 6
/// rejects) or at zero.
fn challenge(r: &[u8; 32], hash: &[u8; 32]) -> Option<Scalar> {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(r);
    input[32..].copy_from_slice(hash);
    let e = Option::<Scalar>::from(Scalar::from_repr(
        dcroxide_crypto::blake256::sum256(&input).into(),
    ))?;
    (!bool::from(e.is_zero())).then_some(e)
}

/// A random hash whose challenge for r is valid, with the challenge.
fn hash_for(rng: &mut SplitMix64, r: &[u8; 32]) -> ([u8; 32], Scalar) {
    loop {
        let mut hash = [0u8; 32];
        rng.fill(&mut hash);
        if let Some(e) = challenge(r, &hash) {
            return (hash, e);
        }
    }
}

/// dcrd's verification decided on k256's R = s*G + e*Q (two constant-time
/// multiplications and an addition): step 8 at infinity, step 9 for an
/// odd y, step 10 on whether R.x is r.
fn schnorr_step(q: &AffinePoint, r: &[u8; 32], s: &Scalar, e: &Scalar) -> &'static str {
    let big_r = (ProjectivePoint::GENERATOR * s + ProjectivePoint::from(*q) * e).to_affine();
    if bool::from(big_r.is_identity()) {
        "step8"
    } else if bool::from(big_r.y_is_odd()) {
        "step9"
    } else if <[u8; 32]>::from(big_r.x()) == *r {
        "step10-accept"
    } else {
        "step10-reject"
    }
}

/// The Schnorr case for key Q, hash, r and s; `None` when Q is infinity.
fn schnorr_case(
    class: &'static str,
    what: &str,
    q: &ProjectivePoint,
    hash: &[u8; 32],
    r: &[u8; 32],
    s: &Scalar,
) -> Option<Case> {
    let qa = q.to_affine();
    if bool::from(qa.is_identity()) {
        return None;
    }
    let e = challenge(r, hash).expect("a valid challenge");
    let step = schnorr_step(&qa, r, s, &e);
    let mut request = qa.to_sec1_point(true).as_bytes().to_vec();
    request.extend_from_slice(hash);
    request.extend_from_slice(r);
    request.extend_from_slice(&s.to_repr());
    Some(Case {
        class,
        variant: format!("{what}/{step}"),
        command: SCHNORR,
        request,
    })
}

/// Valid signatures with s = 0 for keys built for them, their odd twins
/// and the next hash; `n` of each.
fn zero_s(n: usize) -> Vec<Case> {
    let mut rng = SplitMix64(0x7a65_726f_5f73_3031);
    let g = ProjectivePoint::GENERATOR;
    let mut out = Vec::new();
    for _ in 0..n {
        let mut k = rand_scalar(&mut rng);
        if bool::from((g * k).to_affine().y_is_odd()) {
            k = -k;
        }
        let r: [u8; 32] = (g * k).to_affine().x().into();
        let (hash, e) = hash_for(&mut rng, &r);
        let ei = e.invert_vartime().expect("nonzero");
        let q = g * (k * ei);
        out.extend(schnorr_case(
            "zero-s",
            "q=(k/e)G",
            &q,
            &hash,
            &r,
            &Scalar::ZERO,
        ));
        out.extend(schnorr_case(
            "zero-s",
            "odd-twin",
            &(-q),
            &hash,
            &r,
            &Scalar::ZERO,
        ));
        let mut next = hash;
        loop {
            next[31] = next[31].wrapping_add(1);
            if challenge(&r, &next).is_some() {
                break;
            }
        }
        out.extend(schnorr_case(
            "zero-s",
            "next-hash",
            &q,
            &next,
            &r,
            &Scalar::ZERO,
        ));
    }
    out
}

/// R with tiny coordinates and near p, for a random s and s = 0, the key
/// solved as Q = (R - s*G)/e; and r = R.x + 1 with the key solved again.
fn tiny_r(subset: bool) -> Vec<Case> {
    let mut rng = SplitMix64(0x7469_6e79_5f72_3031);
    let g = ProjectivePoint::GENERATOR;
    let mut out = Vec::new();
    for (class, big_r) in boundary_points(subset) {
        let class = match class {
            "tiny-x" => "r-tiny-x",
            "tiny-y" => "r-tiny-y",
            "x-near-p" => "r-x-near-p",
            _ => "r-x-above-n",
        };
        let rp = ProjectivePoint::from(big_r);
        let x: [u8; 32] = big_r.x().into();
        for (what, s) in [
            ("s-random", rand_scalar(&mut rng)),
            ("s-zero", Scalar::ZERO),
        ] {
            let (hash, e) = hash_for(&mut rng, &x);
            let q = (rp - g * s) * e.invert_vartime().expect("nonzero");
            out.extend(schnorr_case(class, what, &q, &hash, &x, &s));
            let x1 = add(&x, &small(1));
            if x1 < FIELD_PRIME_BYTES {
                let (hash, e) = hash_for(&mut rng, &x1);
                let q = (rp - g * s) * e.invert_vartime().expect("nonzero");
                out.extend(schnorr_case(
                    class,
                    &format!("{what}-r+1"),
                    &q,
                    &hash,
                    &x1,
                    &s,
                ));
            }
        }
    }
    out
}

/// R at infinity: the key Q = -(s/e)G for a random s (never zero), a
/// random r below P and a hash whose challenge e is valid, so that R =
/// s*G + e*Q is the point at infinity; `n` of them.
fn r_infinity(n: usize) -> Vec<Case> {
    let mut rng = SplitMix64(0x725f_696e_665f_3031);
    let g = ProjectivePoint::GENERATOR;
    let mut out = Vec::new();
    while out.len() < n {
        let mut r = [0u8; 32];
        rng.fill(&mut r);
        if r >= FIELD_PRIME_BYTES {
            continue;
        }
        let s = rand_scalar(&mut rng);
        let (hash, e) = hash_for(&mut rng, &r);
        let q = -(g * (s * e.invert_vartime().expect("nonzero")));
        out.extend(schnorr_case("r-infinity", "q=-(s/e)G", &q, &hash, &r, &s));
    }
    out
}

/// This crate's step for a Schnorr request, by `verify_detailed`.
fn our_schnorr(request: &[u8]) -> &'static str {
    assert_eq!(request.len(), 33 + 32 + 64);
    let key = PublicKey::parse(&request[..33]).expect("a valid key");
    let sig = schnorr::parse_signature(&request[65..]).expect("a valid signature");
    match sig.verify_detailed(&request[33..65], &key) {
        Ok(()) => "step10-accept",
        Err(SchnorrError::SigRNotOnCurve) => "step8",
        Err(SchnorrError::SigRYIsOdd) => "step9",
        Err(SchnorrError::UnequalRValues) => "step10-reject",
        Err(e) => panic!("verification failed before step 7: {e}"),
    }
}

/// dcrd's verdict for a Schnorr request.
fn dcrd_schnorr(oracle: &mut Oracle, request: &[u8]) -> String {
    let answer = oracle.call_ok(SCHNORR, request);
    assert!(
        answer == "true" || answer == "false",
        "{SCHNORR} answered {answer}"
    );
    answer
}

// ---------------------------------------------------------------------------
// Checks.

/// A case's answer by this crate, checked against its step: the error kind
/// or key a recovery step implies (and, for a key, the bytes of k256's
/// recovery), or the verdict a Schnorr step implies.
fn ours_checked(c: &Case, what: &str) -> String {
    match c.command {
        RECOVER => {
            let ours = our_recovery(&c.request);
            let k = k256_recover(&c.request);
            match c.step() {
                "key" => {
                    let key = k.unwrap_or_else(|s| panic!("{what}: k256 stops at {s}"));
                    let compressed = c.request[32] - 27 >= 4;
                    assert_eq!(ours, ok_answer(&key, compressed), "{what}: the key");
                }
                step => {
                    assert_eq!(k, Err(step), "{what}: k256's step");
                    assert_eq!(ours, "err:ErrPointNotOnCurve", "{what}: the error");
                }
            }
            ours
        }
        _ => {
            let ours = our_schnorr(&c.request);
            assert_eq!(ours, c.step(), "{what}: the step");
            (ours == "step10-accept").to_string()
        }
    }
}

/// dcrd's answer to a case.
fn dcrd_answer(oracle: &mut Oracle, c: &Case) -> String {
    match c.command {
        RECOVER => dcrd_recovery(oracle, &c.request),
        _ => dcrd_schnorr(oracle, &c.request),
    }
}

/// Every case: this crate's answer matches its step and equals dcrd's.
/// Returns the steps seen.
fn check_all(oracle: &mut Oracle, cases: &[Case]) -> BTreeSet<String> {
    let mut steps = BTreeSet::new();
    for (i, c) in cases.iter().enumerate() {
        let what = format!("{} {} case {i}", c.class, c.variant);
        let ours = ours_checked(c, &what);
        assert_eq!(
            dcrd_answer(oracle, c),
            ours,
            "{what}: dcrd's answer, request {}",
            hex(&c.request)
        );
        steps.insert(c.step().to_owned());
    }
    steps
}

/// The recovery grid's signatures against dcrd.
#[test]
fn recovery_grid_matches_dcrd() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let cases = recovery_grid(if full() { 3 } else { 1 });
    let steps = check_all(&mut oracle, &cases);
    println!("{} grid signatures; steps {steps:?}", cases.len());
    assert!(steps.contains("key") && steps.contains("step10"));
}

/// Recovery's shapes against dcrd.
#[test]
fn recovery_shapes_match_dcrd() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let cases = recovery_shapes(!full());
    let steps = check_all(&mut oracle, &cases);
    println!("{} recovery shapes; steps {steps:?}", cases.len());
    for s in ["key", "step4-5", "step10"] {
        assert!(steps.contains(s), "no recovery shape reached {s}");
    }
    let codes: BTreeSet<&str> = cases
        .iter()
        .filter(|c| c.class == "code")
        .map(|c| c.variant.as_str())
        .collect();
    assert_eq!(codes.len(), 8, "codes and flags reached {codes:?}");
}

/// Valid s = 0 signatures and their variants against dcrd.
#[test]
fn zero_s_schnorr_matches_dcrd() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let cases = zero_s(if full() { 1024 } else { 32 });
    let steps = check_all(&mut oracle, &cases);
    println!("{} zero-s signatures; steps {steps:?}", cases.len());
    for c in &cases {
        let want = match c.variant.split('/').next() {
            Some("q=(k/e)G") => Some("step10-accept"),
            Some("odd-twin") => Some("step9"),
            _ => None,
        };
        if let Some(want) = want {
            assert_eq!(c.step(), want, "{} {}", c.class, c.variant);
        }
    }
}

/// Schnorr R with tiny coordinates and near p against dcrd.
#[test]
fn tiny_r_schnorr_matches_dcrd() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let cases = tiny_r(!full());
    let steps = check_all(&mut oracle, &cases);
    println!("{} tiny-R signatures; steps {steps:?}", cases.len());
    for s in ["step9", "step10-accept", "step10-reject"] {
        assert!(steps.contains(s), "no tiny-R case reached {s}");
    }
}

/// Schnorr R at infinity against dcrd: every case rejects at step 8.
#[test]
fn r_at_infinity_schnorr_matches_dcrd() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let cases = r_infinity(if full() { 1024 } else { 32 });
    let steps = check_all(&mut oracle, &cases);
    println!("{} R-at-infinity signatures; steps {steps:?}", cases.len());
    assert_eq!(steps, BTreeSet::from(["step8".to_owned()]));
}

/// The committed selection, in this order: the first case of each (grid
/// key, step) of the grid at [-1, 1], with the grid's doubling cases
/// ([`common::DOUBLING_CELLS`], labelled `<key>/<cell>/<step>`) in their
/// place; of each (what, step) of the code,
/// e = 0, no-point and s = 0 classes; of each step of the other recovery
/// shapes; and, for the Schnorr R classes, of each step, with the
/// accepting step kept apart for a random s and for s = 0.
fn selection() -> Vec<(usize, Case)> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for set in [
        recovery_grid(1),
        recovery_shapes(true),
        zero_s(8),
        tiny_r(true),
        r_infinity(8),
    ] {
        for (i, mut c) in set.into_iter().enumerate() {
            let what = c.variant.split('/').next().unwrap_or("").to_owned();
            let key = match c.class {
                "grid" | "code" | "e-zero" | "no-point" | "zero-s" => {
                    format!("{} {what} {}", c.class, c.step())
                }
                class if class.starts_with("r-") && c.step() == "step10-accept" => {
                    format!("{class} {what} {}", c.step())
                }
                class => format!("{class} {}", c.step()),
            };
            let cell = (c.class == "grid")
                .then(|| common::doubling_cell(i))
                .flatten();
            if let Some(cell) = cell {
                c.variant = format!("{what}/{cell}/{}", c.step());
            }
            if seen.insert(key) || cell.is_some() {
                out.push((i, c));
            }
        }
    }
    out
}

/// The file's text for the selection with dcrd's answers.
fn file_text(oracle: &mut Oracle) -> String {
    let mut s = String::new();
    for line in [
        "# Compact recovery's and EC-Schnorr-DCRv0 verification's branches on",
        "# dcroxide-secp256k1-vartime, judged by dcrd: per grid key or class, the",
        "# first case of each step dcrd's algorithm decides at, as",
        "# tests/vartime_recovery_schnorr_branches.rs constructs them on k256 from",
        "# its fixed seeds (the recovery grid at [-1, 1], recovery's shapes, valid",
        "# s = 0 signatures, Schnorr R with tiny coordinates and near p, Schnorr R",
        "# at infinity, each in its small selection, plus the grid cases whose",
        "# Straus loop doubles through an addition at each call site, labelled",
        "# dbl-<site>), each answer given by dcrd's",
        "# dcrec/secp256k1/v4 at the parity pin 3360ae4d through tools/oracle.",
        "# committed_recovery_schnorr_vectors_regenerate rebuilds the file and",
        "# fails on any difference; committed_recovery_schnorr_vectors_hold checks",
        "# it without Go.",
        "#",
        "# <class>|<what>/<step>|<case index>|<command>|<request data hex>|<answer>",
    ] {
        let _ = writeln!(s, "{line}");
    }
    for (i, c) in selection() {
        let answer = dcrd_answer(oracle, &c);
        let _ = writeln!(
            s,
            "{}|{}|{i}|{}|{}|{answer}",
            c.class,
            c.variant,
            c.command,
            hex(&c.request)
        );
    }
    s
}

/// Each committed line: this crate's answer is the recorded dcrd answer,
/// and it matches the step the line names.  Needs no Go.
#[test]
fn committed_recovery_schnorr_vectors_hold() {
    let mut n = 0;
    let mut steps = BTreeSet::new();
    for (line, f) in data_lines(COMMITTED) {
        let [_, variant, _, command, request, answer] = f[..] else {
            panic!("{line}: not six fields");
        };
        let command = match command {
            RECOVER => RECOVER,
            SCHNORR => SCHNORR,
            other => panic!("{line}: command {other}"),
        };
        let c = Case {
            class: "committed",
            variant: variant.to_owned(),
            command,
            request: unhex(request),
        };
        assert_eq!(ours_checked(&c, line), answer, "{line}: dcrd's answer");
        steps.insert(format!("{command} {}", c.step()));
        n += 1;
    }
    assert!(n >= 30, "{n} lines");
    for s in [
        "ecdsa_recover_compact key",
        "ecdsa_recover_compact step4-5",
        "ecdsa_recover_compact step10",
        "schnorr_verify step8",
        "schnorr_verify step9",
        "schnorr_verify step10-accept",
        "schnorr_verify step10-reject",
    ] {
        assert!(steps.contains(s), "no committed line reaches {s}");
    }
    common::assert_doubling_cells_named(
        data_lines(COMMITTED)
            .filter(|(_, f)| f[0] == "grid")
            .map(|(_, f)| f[1]),
    );
}

/// The committed file is the selection with dcrd's answers, byte for byte.
/// With `DCROXIDE_REGEN_RECOVERY_SCHNORR_BRANCHES=<path>` set, a differing
/// text is written there, never into the source tree, and the test still
/// fails.
#[test]
fn committed_recovery_schnorr_vectors_regenerate() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    require_regenerated(
        &file_text(&mut oracle),
        COMMITTED,
        "DCROXIDE_REGEN_RECOVERY_SCHNORR_BRANCHES",
        "tests/data/vartime_recovery_schnorr_branches.txt",
    );
}
