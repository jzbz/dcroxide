// SPDX-License-Identifier: ISC
//! Compact signature recovery classes (ER-*).
//!
//! A case is one `ecdsa_recover_compact` request: a 32-byte hash and a
//! compact signature, header ‖ r ‖ s, whose header is 27 + code +
//! 4·compressed for the recovery code (R.x ≥ N) << 1 | (R.y odd).  dcrd's
//! `RecoverCompact` checks the length, the header, r and s, the overflow
//! bit against P − N, that the x the code names decompresses, and that the
//! recovered key is not the point at infinity, in that order
//! ([`crate::model::ecdsa::recover`] is the model).  Each class is built to
//! end at one of those checks, or to recover a key its construction knows,
//! and that kind or key is each case's intent.
//!
//! The constructed classes solve for a key or a signature with group
//! arithmetic: the valid overflow branch dcrd's own tests call impossible
//! to build from a private key (ER-overflowValid), a recovered key at
//! infinity (ER-infinity) and a recovery sum that doubles (ER-double).
//!
//! dcroxide reports no recovery error kind yet, so its rejections are held
//! to dcrd's by verdict alone and counted as kinds not compared; dcrd's
//! kind is still each rejecting case's intent.

use std::borrow::Cow;

use k256::{AffinePoint, ProjectivePoint, Scalar};

use crate::arith::{self, N, P_MINUS_N};
use crate::class::{Case, ClassSpec, Family, Intent, Size, Tag, Tier};
use crate::cmd::{self, Cmd};
use crate::entropy::Entropy;
use crate::r#gen::{
    ALL_ACCEPTED, DECOMPRESS_TRIES, Draw, FLAGS, FLOOR_B, NONE_ACCEPTED, PR_CASES, SCALAR_TRIES,
    Signature, at_or_above_n, base_mul, be, compressed, decompress, digit, finite, reduce, scalar,
    scalar_bytes, single, solve_key, stratum, uncompressed, x_of, y_is_odd,
};
use crate::model::ecdsa::{CODE_ODD, CODE_OVERFLOW, COMPACT_COMPRESSED, COMPACT_MAGIC};

/// The recovery command.
const RECOVER: &[Cmd] = &[Cmd::EcdsaRecoverCompact];

/// The largest code a header carries, 3 + 4: the valid headers are
/// 27..=34.
const MAX_CODE: u8 = COMPACT_COMPRESSED | CODE_OVERFLOW | CODE_ODD;

/// The header for recovery code `code` (its two low bits) and the
/// compressed flag: 27 + code + 4·compressed.
fn header(code: u8, compressed: bool) -> u8 {
    COMPACT_MAGIC
        .saturating_add(code & (CODE_OVERFLOW | CODE_ODD))
        .saturating_add(if compressed { COMPACT_COMPRESSED } else { 0 })
}

/// The recovery code for a point whose x is at or above N (`overflow`) and
/// whose y is odd (`odd`).
fn recovery_code(overflow: bool, odd: bool) -> u8 {
    (if overflow { CODE_OVERFLOW } else { 0 }) | (if odd { CODE_ODD } else { 0 })
}

/// A compact signature: header ‖ r ‖ s.
fn compact(header: u8, r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(65);
    out.push(header);
    out.extend_from_slice(r);
    out.extend_from_slice(s);
    out
}

/// What `ecdsa_recover_compact` answers for key `q` recovered under the
/// compressed flag `flag`: the key serialized as the flag says, as dcrd's
/// verifymessage serializes it.
fn recovered(q: &AffinePoint, flag: bool) -> Vec<u8> {
    if flag {
        compressed(q).to_vec()
    } else {
        uncompressed(q).to_vec()
    }
}

/// The point recovery code `code` names for r: x = r, or r + N with the
/// overflow bit, of the code's parity.  `None` when that x is no x
/// coordinate (or r + N does not fit below 2^256).
fn code_point(r: &[u8; 32], code: u8) -> Option<AffinePoint> {
    let x = if code & CODE_OVERFLOW != 0 {
        let (x, carry) = arith::add_be(r, &N);
        if carry {
            return None;
        }
        x
    } else {
        *r
    };
    decompress(&x, code & CODE_ODD != 0)
}

/// A recovery case of one request.
fn recover_case(
    variant: impl Into<Cow<'static, str>>,
    h: &[u8; 32],
    sig: &[u8],
    intent: Intent,
) -> Case {
    single(variant, cmd::ecdsa_recover_compact(h, sig), intent)
}

/// The signature a construction falls back to when a retry runs out: r =
/// s = 1, code 0.
fn fallback_signature() -> Signature {
    Signature {
        r: be(1),
        s: be(1),
        code: 0,
    }
}

/// A random key, a random hash and an honest signature of it.
fn honest(d: &mut Draw) -> (Scalar, [u8; 32], Signature) {
    let key = d.key();
    let h = d.bytes32();
    let sig = d.honest_ecdsa(&key, &h);
    (key, h, sig)
}

/// The four headers with the overflow bit: 29, 30 (uncompressed, even and
/// odd), 33, 34 (compressed).
const OVERFLOW_HEADERS: [u8; 4] = [29, 30, 33, 34];

/// The four headers without it: 27, 28, 31, 32.
const PLAIN_HEADERS: [u8; 4] = [27, 28, 31, 32];

/// The labels of [`OVERFLOW_HEADERS`].
const OVERFLOW_LABELS: [&str; 4] = ["29", "30", "33", "34"];

/// A header drawn from `headers`.
fn drawn_header(d: &mut Draw, headers: &[u8; 4]) -> u8 {
    headers[usize::try_from(d.below(4)).unwrap_or(0)]
}

/// t uniform in [1, P − N − 1] such that N + t is the x coordinate of a
/// point whose y has parity `odd`, and that point.  Falls back to t = 1
/// and G.
fn above_n_point(d: &mut Draw, odd: bool) -> ([u8; 32], AffinePoint) {
    let hi = arith::sub_be(&P_MINUS_N, &be(1)).0;
    d.retry(
        DECOMPRESS_TRIES,
        || (be(1), base_mul(&Scalar::ONE)),
        |d| {
            let t = d.uniform_in(&be(1), &hi);
            decompress(&arith::add_be(&N, &t).0, odd).map(|point| (t, point))
        },
    )
}

fn er_honest(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let flag = stratum(i, 2);
    let (key, h, sig) = honest(&mut d);
    d.finish(recover_case(
        FLAGS[flag],
        &h,
        &compact(header(sig.code, flag == 1), &sig.r, &sig.s),
        Intent::AcceptValue(recovered(&base_mul(&key), flag == 1)),
    ))
}

fn er_flip_parity(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let flag = stratum(i, 2);
    let (h, sig, q) = d.retry(
        SCALAR_TRIES,
        || ([0; 32], fallback_signature(), base_mul(&Scalar::ONE)),
        |d| {
            // The other parity names −R, so the key recovered is
            // Q' = r⁻¹·(s·(−R) − e·G), redrawn in the unreachable case
            // that it is the point at infinity.
            let (_, h, sig) = honest(d);
            let flipped = code_point(&sig.r, sig.code ^ CODE_ODD)?;
            let q = solve_key(&scalar(&sig.r)?, &scalar(&sig.s)?, &reduce(&h), &flipped)?;
            Some((h, sig, q))
        },
    );
    d.finish(recover_case(
        FLAGS[flag],
        &h,
        &compact(header(sig.code ^ CODE_ODD, flag == 1), &sig.r, &sig.s),
        Intent::AcceptValue(recovered(&q, flag == 1)),
    ))
}

fn er_high_s(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let flag = stratum(i, 2);
    let (key, h, sig) = honest(&mut d);
    // Negating s negates the point it recovers through, so the other
    // parity recovers the signer's key.
    let high_s = arith::neg_mod_n(&sig.s);
    d.finish(recover_case(
        FLAGS[flag],
        &h,
        &compact(header(sig.code ^ CODE_ODD, flag == 1), &sig.r, &high_s),
        Intent::AcceptValue(recovered(&base_mul(&key), flag == 1)),
    ))
}

fn er_overflow_valid(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let k = stratum(i, 4);
    let header = OVERFLOW_HEADERS[k];
    let (odd, flag) = (k == 1 || k == 3, k >= 2);
    let (h, r, s, q) = d.retry(
        SCALAR_TRIES,
        || ([0; 32], be(1), be(1), base_mul(&Scalar::ONE)),
        |d| {
            // X with X.x = N + t, r = t: the header's overflow bit names X,
            // and Q = r⁻¹·(s·X − e·G) is the key recovery returns.
            let (t, big_x) = above_n_point(d, odd);
            let s = d.key();
            let h = d.bytes32();
            let q = solve_key(&scalar(&t)?, &s, &reduce(&h), &big_x)?;
            Some((h, t, scalar_bytes(&s), q))
        },
    );
    d.finish(recover_case(
        OVERFLOW_LABELS[k],
        &h,
        &compact(header, &r, &s),
        Intent::AcceptValue(recovered(&q, flag)),
    ))
}

/// ER-overflowPrime's values of r.
const OVERFLOW_PRIME: [&str; 3] = ["r=P-N", "r=P-N+1", "r=random"];

fn er_overflow_prime(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let which = stratum(i, 3);
    let r = match which {
        0 => P_MINUS_N,
        1 => arith::add_be(&P_MINUS_N, &be(1)).0,
        _ => d.uniform_in(&P_MINUS_N, &arith::sub_be(&N, &be(1)).0),
    };
    let header = drawn_header(&mut d, &OVERFLOW_HEADERS);
    let s = scalar_bytes(&d.key());
    let h = d.bytes32();
    d.finish(recover_case(
        OVERFLOW_PRIME[which],
        &h,
        &compact(header, &r, &s),
        Intent::RejectKind("ErrSigOverflowsPrime"),
    ))
}

/// ER-notOnCurve's strata.
const NOT_ON_CURVE: [&str; 3] = ["plain", "overflow", "row"];

fn er_not_on_curve(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let which = stratum(i, 3);
    let below_p_minus_n = arith::sub_be(&P_MINUS_N, &be(1)).0;
    let (r, header) = match which {
        // r below N with r³ + 7 a non-residue, so no point has x = r.
        0 => {
            let r = d.retry(
                DECOMPRESS_TRIES,
                || be(1),
                |d| {
                    let r = scalar_bytes(&d.key());
                    decompress(&r, false).is_none().then_some(r)
                },
            );
            (r, drawn_header(&mut d, &PLAIN_HEADERS))
        }
        // r below P − N with (r + N)³ + 7 a non-residue.
        1 => {
            let r = d.retry(
                DECOMPRESS_TRIES,
                || be(1),
                |d| {
                    let r = d.uniform_in(&be(1), &below_p_minus_n);
                    decompress(&arith::add_be(&r, &N).0, false)
                        .is_none()
                        .then_some(r)
                },
            );
            (r, drawn_header(&mut d, &OVERFLOW_HEADERS))
        }
        // dcrd's own row: r = P − N − 1 with the overflow bit, so x = P − 1
        // and x³ + 7 = 6, a non-residue.
        _ => (below_p_minus_n, drawn_header(&mut d, &OVERFLOW_HEADERS)),
    };
    let s = scalar_bytes(&d.key());
    let h = d.bytes32();
    d.finish(recover_case(
        NOT_ON_CURVE[which],
        &h,
        &compact(header, &r, &s),
        Intent::RejectKind("ErrPointNotOnCurve"),
    ))
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
)]
fn er_infinity(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let flag = stratum(i, 2);
    let (h, r, s, code) = d.retry(
        SCALAR_TRIES,
        || ([0; 32], be(1), be(1), 0),
        |d| {
            // X = (e/s)·G and r = X.x mod N: then u2·X = (s/r)·(e/s)·G =
            // (e/r)·G = −u1·G, so the recovered key is the point at
            // infinity.
            let s = d.key();
            let (h, e) = d.nonzero_hash();
            let big_x = base_mul(&(e * Option::<Scalar>::from(s.invert())?));
            let x = x_of(&big_x);
            let r = reduce(&x);
            if bool::from(r.is_zero()) {
                return None;
            }
            let code = recovery_code(x >= N, y_is_odd(&big_x));
            Some((h, scalar_bytes(&r), scalar_bytes(&s), code))
        },
    );
    d.finish(recover_case(
        FLAGS[flag],
        &h,
        &compact(header(code, flag == 1), &r, &s),
        Intent::RejectKind("ErrPointNotOnCurve"),
    ))
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
)]
fn er_double(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let flag = stratum(i, 2);
    let (h, r, s, code, q) = d.retry(
        SCALAR_TRIES,
        || ([0; 32], be(1), be(1), 0, base_mul(&Scalar::ONE)),
        |d| {
            // A = a·G with A.x below N (redrawn otherwise, odds about
            // 2^-127), r = A.x, e = −s·a: then u1 = −e/r = s·a/r and
            // u2·A = (s/r)·a·G = u1·G, so the sum doubles and Q = 2·u1·G.
            let a = d.key();
            let big_a = base_mul(&a);
            let r = scalar(&x_of(&big_a))?;
            let s = d.key();
            let e = -(s * a);
            let u1 = -(e * Option::<Scalar>::from(r.invert())?);
            let q = finite(&(ProjectivePoint::GENERATOR * (u1 + u1)))?;
            let code = recovery_code(false, y_is_odd(&big_a));
            Some((scalar_bytes(&e), x_of(&big_a), scalar_bytes(&s), code, q))
        },
    );
    let mut case = recover_case(
        FLAGS[flag],
        &h,
        &compact(header(code, flag == 1), &r, &s),
        Intent::AcceptValue(recovered(&q, flag == 1)),
    );
    case.tags = case.tags.with(Tag::Doubled);
    d.finish(case)
}

fn er_header(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let byte = u8::try_from(stratum(i, 256)).expect("a header byte");
    // An honest signature whose R.x is below N and whose r is at or above
    // P − N (each misses with odds about 2^-127), so that every overflow
    // header ends at ErrSigOverflowsPrime.
    let (key, h, sig) = d.retry(
        SCALAR_TRIES,
        || (Scalar::ONE, [0; 32], fallback_signature()),
        |d| {
            let (key, h, sig) = honest(d);
            (sig.code & CODE_OVERFLOW == 0 && sig.r >= P_MINUS_N).then_some((key, h, sig))
        },
    );
    let intent = match byte
        .checked_sub(COMPACT_MAGIC)
        .filter(|&code| code <= MAX_CODE)
    {
        None => Intent::RejectKind("ErrSigInvalidRecoveryCode"),
        Some(code) if code & CODE_OVERFLOW != 0 => Intent::RejectKind("ErrSigOverflowsPrime"),
        Some(code) => {
            let flag = code & COMPACT_COMPRESSED != 0;
            if code & CODE_ODD == sig.code & CODE_ODD {
                Intent::AcceptValue(recovered(&base_mul(&key), flag))
            } else {
                // The other parity names −R: Q' = r⁻¹·(s·(−R) − e·G).
                let other = code_point(&sig.r, sig.code ^ CODE_ODD)
                    .and_then(|x| solve_key(&scalar(&sig.r)?, &scalar(&sig.s)?, &reduce(&h), &x));
                match other {
                    Some(q) => Intent::AcceptValue(recovered(&q, flag)),
                    None => Intent::RejectKind("ErrPointNotOnCurve"),
                }
            }
        }
    };
    d.finish(recover_case(
        byte.to_string(),
        &h,
        &compact(byte, &sig.r, &sig.s),
        intent,
    ))
}

fn er_length(e: &mut dyn Entropy, _: u64) -> Case {
    let mut d = Draw::new(e);
    // A length in 0..=130 other than 65.
    let len = d.len_in(0, 129);
    let long = len >= 65;
    let len = if long { len.saturating_add(1) } else { len };
    let sig = d.bytes(len);
    let h = d.bytes32();
    d.finish(recover_case(
        if long { "long" } else { "short" },
        &h,
        &sig,
        Intent::RejectKind("ErrSigInvalidLen"),
    ))
}

/// ER-range's strata: r or s out of range, or both, under a valid header;
/// both under an invalid header.
const RANGE: [&str; 4] = ["r", "s", "both", "header"];

/// ER-range's values: zero, then the four of [`at_or_above_n`].
const RANGE_VALUES: [&str; 5] = ["0", "N", "N+1", "max", "random"];

/// Value `k` of [`RANGE_VALUES`].
fn range_value(d: &mut Draw, k: usize) -> [u8; 32] {
    match k {
        0 => [0; 32],
        _ => at_or_above_n(d, k.saturating_sub(1)),
    }
}

/// A header byte outside 27..=34, uniform over the 248: a draw below 27 is
/// the byte, one from 27 on is moved past the eight valid headers.
fn invalid_header(d: &mut Draw) -> u8 {
    let byte = u8::try_from(d.below(248)).unwrap_or(0);
    if byte < COMPACT_MAGIC {
        byte
    } else {
        byte.saturating_add(MAX_CODE).saturating_add(1)
    }
}

fn er_range(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let which = stratum(i, 4);
    // r's value (s's in the `s` stratum), and s's where both are set: the
    // two digits take every one of the 25 pairs every 100 cases.
    let (k, k_s) = (digit(i, 4, 5), digit(i, 20, 5));
    let (_, h, mut sig) = honest(&mut d);
    let header = if which == 3 {
        invalid_header(&mut d)
    } else {
        // Any valid header: r and s are checked before the overflow bit.
        COMPACT_MAGIC.saturating_add(u8::try_from(d.below(8)).unwrap_or(0))
    };
    match which {
        0 => sig.r = range_value(&mut d, k),
        1 => sig.s = range_value(&mut d, k),
        _ => {
            sig.r = range_value(&mut d, k);
            sig.s = range_value(&mut d, k_s);
        }
    }
    // dcrd checks the header, then r's range, r's zero, s's range and s's
    // zero, so where both are out of range r's check decides, and an
    // invalid header decides before either.
    let kind = match (which, k) {
        (3, _) => "ErrSigInvalidRecoveryCode",
        (1, 0) => "ErrSigSIsZero",
        (1, _) => "ErrSigSTooBig",
        (_, 0) => "ErrSigRIsZero",
        _ => "ErrSigRTooBig",
    };
    let label = if which < 2 {
        format!("{}/{}", RANGE[which], RANGE_VALUES[k])
    } else {
        format!("{}/{}/{}", RANGE[which], RANGE_VALUES[k], RANGE_VALUES[k_s])
    };
    d.finish(recover_case(
        label,
        &h,
        &compact(header, &sig.r, &sig.s),
        Intent::RejectKind(kind),
    ))
}

/// ER-hash's hashes.
const HASHES: [&str; 4] = ["h=0", "h=N", "h=random", "h=max"];

fn er_hash(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let which = stratum(i, 4);
    let h = match which {
        0 => [0; 32],
        1 => N,
        2 => at_or_above_n(&mut d, 3),
        _ => [0xff; 32],
    };
    let flag = d.coin();
    let key = d.key();
    // Signed over h mod N, as the signer reduces it; recovered with h.
    let sig = d.honest_ecdsa(&key, &h);
    d.finish(recover_case(
        HASHES[which],
        &h,
        &compact(header(sig.code, flag), &sig.r, &sig.s),
        Intent::AcceptValue(recovered(&base_mul(&key), flag)),
    ))
}

/// ER-honest.
pub const ER_HONEST: ClassSpec = ClassSpec {
    name: "ER-honest",
    family: Family::Recover,
    commands: RECOVER,
    size: Size::Stratified {
        strata: 2,
        floor: FLOOR_B,
    },
    tier: Tier::B,
    generator: er_honest,
    mix: ALL_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "an honest signature (random nonce) under its own recovery code, uncompressed or \
          compressed (i % 2): recovers the signer's key",
};

/// ER-flipParity.
pub const ER_FLIP_PARITY: ClassSpec = ClassSpec {
    name: "ER-flipParity",
    family: Family::Recover,
    commands: RECOVER,
    size: Size::Stratified {
        strata: 2,
        floor: FLOOR_B,
    },
    tier: Tier::B,
    generator: er_flip_parity,
    mix: ALL_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "an honest signature under the recovery code of the other parity, which names -R: \
          recovers r^-1·(-s·R - e·G); flag i % 2",
};

/// ER-highS.
pub const ER_HIGH_S: ClassSpec = ClassSpec {
    name: "ER-highS",
    family: Family::Recover,
    commands: RECOVER,
    size: Size::Stratified {
        strata: 2,
        floor: FLOOR_B,
    },
    tier: Tier::B,
    generator: er_high_s,
    mix: ALL_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "an honest signature with s replaced by N - s and the parity flipped: recovers the \
          signer's key; flag i % 2",
};

/// ER-overflowValid.
pub const ER_OVERFLOW_VALID: ClassSpec = ClassSpec {
    name: "ER-overflowValid",
    family: Family::Recover,
    commands: RECOVER,
    size: Size::Stratified {
        strata: 4,
        floor: FLOOR_B,
    },
    tier: Tier::B,
    generator: er_overflow_valid,
    mix: ALL_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "the overflow headers 29, 30, 33 and 34 (i % 4) with r = X.x - N for a point X of the \
          header's parity and the key solved for: the valid overflow branch, which recovers that \
          key",
};

/// ER-overflowPrime.
pub const ER_OVERFLOW_PRIME: ClassSpec = ClassSpec {
    name: "ER-overflowPrime",
    family: Family::Recover,
    commands: RECOVER,
    size: Size::Stratified {
        strata: 3,
        floor: FLOOR_B,
    },
    tier: Tier::B,
    generator: er_overflow_prime,
    mix: NONE_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "an overflow header with r = P - N, P - N + 1 or random in [P - N, N) (i % 3): \
          ErrSigOverflowsPrime",
};

/// ER-notOnCurve.
pub const ER_NOT_ON_CURVE: ClassSpec = ClassSpec {
    name: "ER-notOnCurve",
    family: Family::Recover,
    commands: RECOVER,
    size: Size::Stratified {
        strata: 3,
        floor: FLOOR_B,
    },
    tier: Tier::B,
    generator: er_not_on_curve,
    mix: NONE_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "an x the header names that no point has (i % 3): r itself, r + N under an overflow \
          header, or dcrd's row r = P - N - 1 with the overflow bit: ErrPointNotOnCurve",
};

/// ER-infinity.
pub const ER_INFINITY: ClassSpec = ClassSpec {
    name: "ER-infinity",
    family: Family::Recover,
    commands: RECOVER,
    size: Size::Stratified {
        strata: 2,
        floor: FLOOR_B,
    },
    tier: Tier::B,
    generator: er_infinity,
    mix: NONE_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "X = (e/s)·G with r its x mod N, so u1·G + u2·X is the point at infinity: \
          ErrPointNotOnCurve; flag i % 2",
};

/// ER-double.
pub const ER_DOUBLE: ClassSpec = ClassSpec {
    name: "ER-double",
    family: Family::Recover,
    commands: RECOVER,
    size: Size::Stratified {
        strata: 2,
        floor: FLOOR_B,
    },
    tier: Tier::B,
    generator: er_double,
    mix: ALL_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "X = a·G with r its x and the hash -s·a, so u1·G = u2·X and the sum doubles: recovers \
          2·u1·G; flag i % 2",
};

/// ER-header.
pub const ER_HEADER: ClassSpec = ClassSpec {
    name: "ER-header",
    family: Family::Recover,
    commands: RECOVER,
    size: Size::Stratified {
        strata: 256,
        floor: FLOOR_B,
    },
    tier: Tier::B,
    generator: er_header,
    mix: &[],
    pr_cases: 256,
    doc: "an honest signature under every header byte (i % 256): outside 27..=34 \
          ErrSigInvalidRecoveryCode, the overflow codes ErrSigOverflowsPrime, the signer's parity \
          its key and the other parity the other key, each per case",
};

/// ER-length.
pub const ER_LENGTH: ClassSpec = ClassSpec {
    name: "ER-length",
    family: Family::Recover,
    commands: RECOVER,
    size: Size::Sampled { floor: FLOOR_B },
    tier: Tier::B,
    generator: er_length,
    mix: NONE_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "random signatures of every length in 0..=130 but 65: ErrSigInvalidLen",
};

/// ER-range.
pub const ER_RANGE: ClassSpec = ClassSpec {
    name: "ER-range",
    family: Family::Recover,
    commands: RECOVER,
    size: Size::Stratified {
        strata: 4,
        floor: FLOOR_B,
    },
    tier: Tier::B,
    generator: er_range,
    mix: NONE_ACCEPTED,
    // Every (r, s) pair of the both and header strata.
    pr_cases: 100,
    doc: "r, s or both set to 0, N, N+1, 2^256-1 or random above N under a valid header, or \
          both under a header outside 27..=34 (i % 4); the value (i / 4) % 5, and s's where \
          both are set (i / 20) % 5: the kind of the first check dcrd's order reaches, the \
          header before r's range, r's zero, s's range and s's zero",
};

/// ER-hash.
pub const ER_HASH: ClassSpec = ClassSpec {
    name: "ER-hash",
    family: Family::Recover,
    commands: RECOVER,
    size: Size::Stratified {
        strata: 4,
        floor: FLOOR_B,
    },
    tier: Tier::B,
    generator: er_hash,
    mix: ALL_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "honest signatures over the hashes 0, N, random above N and 2^256-1 (i % 4), \
          recovered with the hash as it is; flag drawn",
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::class::generate;
    use crate::model::ecdsa::{Recovery, recover, recover_request};
    use k256::elliptic_curve::group::Group;
    use std::collections::BTreeSet;

    /// Every ER class.
    const CLASSES: [&ClassSpec; 12] = [
        &ER_HONEST,
        &ER_FLIP_PARITY,
        &ER_HIGH_S,
        &ER_OVERFLOW_VALID,
        &ER_OVERFLOW_PRIME,
        &ER_NOT_ON_CURVE,
        &ER_INFINITY,
        &ER_DOUBLE,
        &ER_HEADER,
        &ER_LENGTH,
        &ER_RANGE,
        &ER_HASH,
    ];

    fn cases(class: &ClassSpec, n: u64) -> impl Iterator<Item = (u64, Case)> + '_ {
        (0..n).map(move |i| (i, generate(class, 0x7e57_5eed, i)))
    }

    /// A recovery request decoded: h, header, r, s.
    fn decode(case: &Case) -> ([u8; 32], u8, [u8; 32], [u8; 32]) {
        let data = &case.requests[0].data;
        assert_eq!(data.len(), 97, "a hash and a 65-byte signature");
        let h: [u8; 32] = data[..32].try_into().expect("hash");
        let r: [u8; 32] = data[33..65].try_into().expect("r");
        let s: [u8; 32] = data[65..].try_into().expect("s");
        (h, data[32], r, s)
    }

    /// Q = u1·G + u2·X with u1 = −e/r and u2 = s/r, computed here apart
    /// from the model; also u1·G and u2·X.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
    )]
    fn recovery_sum(
        h: &[u8; 32],
        r: &[u8; 32],
        s: &[u8; 32],
        x: &AffinePoint,
    ) -> (ProjectivePoint, ProjectivePoint, ProjectivePoint) {
        let w = Option::<Scalar>::from(scalar(r).expect("r below N").invert()).expect("r nonzero");
        let u1g = ProjectivePoint::GENERATOR * (-(reduce(h) * w));
        let u2x = ProjectivePoint::from(*x) * (scalar(s).expect("s below N") * w);
        (u1g + u2x, u1g, u2x)
    }

    /// The x of u1·G + u2·Q for ECDSA verification of (r, s) over h by Q,
    /// computed here: every key recovery returns verifies the signature.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
    )]
    fn verify_point(h: &[u8; 32], r: &[u8; 32], s: &[u8; 32], q: &AffinePoint) -> AffinePoint {
        let w = Option::<Scalar>::from(scalar(s).expect("s below N").invert()).expect("s nonzero");
        let x = ProjectivePoint::GENERATOR * (reduce(h) * w)
            + ProjectivePoint::from(*q) * (scalar(r).expect("r below N") * w);
        finite(&x).expect("finite")
    }

    /// The recovery code and flag of a valid header, `header - 27`.
    fn code_of(header: u8) -> u8 {
        header.checked_sub(COMPACT_MAGIC).expect("a valid header")
    }

    /// The key an intent says recovery returns, decoded.
    fn intent_key(intent: &Intent) -> Option<(AffinePoint, bool)> {
        let Intent::AcceptValue(bytes) = intent else {
            return None;
        };
        let q = crate::model::ecdsa::decode_key(bytes).expect("a valid key");
        Some((q, bytes.len() == 33))
    }

    /// The witness predicates and each construction's branch, on the
    /// numbers: per constructed class, a few cases decoded from their
    /// request bytes and the recovery computed apart from the model.
    #[test]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
    )]
    fn constructed_classes_reach_their_branches() {
        for (i, case) in cases(&ER_OVERFLOW_VALID, 16) {
            let (h, header, r, s) = decode(&case);
            assert_eq!(header, OVERFLOW_HEADERS[stratum(i, 4)], "case {i}");
            let code = code_of(header);
            assert!(code & CODE_OVERFLOW != 0 && r < P_MINUS_N, "case {i}");
            let x_coord = arith::add_be(&r, &N).0;
            let x = decompress(&x_coord, code & CODE_ODD != 0).expect("r + N is an x");
            let (q, _, _) = recovery_sum(&h, &r, &s, &x);
            let (want, flag) = intent_key(&case.intents[0]).expect("a key");
            assert_eq!(finite(&q), Some(want), "case {i}: the key solved for");
            assert_eq!(flag, code & COMPACT_COMPRESSED != 0);
            // The recovered key verifies the signature at dcrd's step 10:
            // X.x = r + N.
            assert_eq!(x_of(&verify_point(&h, &r, &s, &want)), x_coord, "case {i}");
        }
        for (i, case) in cases(&ER_INFINITY, 16) {
            let (h, header, r, s) = decode(&case);
            let x = code_point(&r, code_of(header)).expect("an x coordinate");
            let (q, u1g, u2x) = recovery_sum(&h, &r, &s, &x);
            assert!(bool::from(q.is_identity()), "case {i}: Q = O");
            assert_eq!(u2x, -u1g, "case {i}");
            // s·X = e·G, the witness predicate.
            let s = scalar(&s).expect("s");
            assert_eq!(
                ProjectivePoint::from(x) * s,
                ProjectivePoint::GENERATOR * reduce(&h),
                "case {i}"
            );
            assert_eq!(
                code_of(header) & COMPACT_COMPRESSED != 0,
                stratum(i, 2) == 1
            );
        }
        for (i, case) in cases(&ER_DOUBLE, 16) {
            assert!(case.tags.has(Tag::Doubled));
            let (h, header, r, s) = decode(&case);
            let x = code_point(&r, code_of(header)).expect("an x coordinate");
            let (q, u1g, u2x) = recovery_sum(&h, &r, &s, &x);
            assert_eq!(u1g, u2x, "case {i}: u1·G = u2·X");
            assert_eq!(q, u1g.double(), "case {i}");
            let (want, _) = intent_key(&case.intents[0]).expect("a key");
            assert_eq!(finite(&q), Some(want), "case {i}");
        }
        for class in [&ER_HONEST, &ER_FLIP_PARITY, &ER_HIGH_S, &ER_HASH] {
            for (i, case) in cases(class, 16) {
                let (h, header, r, s) = decode(&case);
                let code = code_of(header);
                assert!(
                    code <= MAX_CODE && code & CODE_OVERFLOW == 0,
                    "{} {i}",
                    class.name
                );
                let (want, flag) = intent_key(&case.intents[0]).expect("a key");
                assert_eq!(flag, code & COMPACT_COMPRESSED != 0, "{} {i}", class.name);
                // The key verifies (r, s) over h through the point the code
                // names.
                let x = verify_point(&h, &r, &s, &want);
                assert_eq!(x_of(&x), r, "{} {i}", class.name);
                assert_eq!(y_is_odd(&x), code & CODE_ODD != 0, "{} {i}", class.name);
                if class.name == "ER-highS" {
                    assert!(r < N && s > arith::HALF_N, "{} {i}: a high S", class.name);
                }
            }
        }
        for (i, case) in cases(&ER_NOT_ON_CURVE, 24) {
            let (_, header, r, _) = decode(&case);
            let code = code_of(header);
            let overflow = code & CODE_OVERFLOW != 0;
            assert_eq!(overflow, stratum(i, 3) != 0, "case {i}");
            let x = if overflow {
                assert!(r < P_MINUS_N, "case {i}");
                arith::add_be(&r, &N).0
            } else {
                r
            };
            assert!(decompress(&x, false).is_none() && decompress(&x, true).is_none());
            if stratum(i, 3) == 2 {
                assert_eq!(arith::add_be(&x, &be(1)).0, arith::P, "x = P - 1");
            }
        }
        for (i, case) in cases(&ER_OVERFLOW_PRIME, 24) {
            let (_, header, r, _) = decode(&case);
            assert!(code_of(header) & CODE_OVERFLOW != 0, "case {i}");
            assert!(P_MINUS_N <= r && r < N, "case {i}");
        }
    }

    /// ER-header's 256 bytes, on one signature each: 248 invalid codes,
    /// 4 overflow codes, the signer's key under the two headers of its
    /// parity and another key under the two of the other.
    #[test]
    fn every_header_byte_is_covered() {
        let mut kinds = std::collections::BTreeMap::new();
        for (i, case) in cases(&ER_HEADER, 256) {
            let (h, header, r, s) = decode(&case);
            assert_eq!(u64::from(header), i);
            let label = match &case.intents[0] {
                Intent::RejectKind(kind) => (*kind).to_owned(),
                Intent::AcceptValue(_) => {
                    let (q, _) = intent_key(&case.intents[0]).expect("a key");
                    let x = verify_point(&h, &r, &s, &q);
                    assert_eq!(x_of(&x), r, "case {i}: the key verifies");
                    assert_eq!(
                        y_is_odd(&x),
                        code_of(header) & CODE_ODD != 0,
                        "case {i}: through the point of the header's parity"
                    );
                    "key".to_owned()
                }
                other => panic!("case {i}: {other:?}"),
            };
            let n = kinds.entry(label).or_insert(0u32);
            *n = n.saturating_add(1);
        }
        assert_eq!(
            kinds.into_iter().collect::<Vec<_>>(),
            [
                ("ErrSigInvalidRecoveryCode".to_owned(), 248),
                ("ErrSigOverflowsPrime".to_owned(), 4),
                ("key".to_owned(), 4),
            ]
        );
    }

    /// Every intent holds in the model: each accepting case's key and
    /// flag are the model's recovery, each rejecting case's kind the
    /// model's, for 16 cases per class and at least the per-PR count.
    #[test]
    fn every_intent_holds_in_the_model() {
        for class in CLASSES {
            for (i, case) in cases(class, class.pr_cases.max(16)) {
                let ctx = format!("{} case {i} ({})", class.name, case.variant);
                assert!(!case.tags.has(Tag::Fallback), "{ctx}: fallback");
                let got = recover_request(&case.requests[0]).expect("a recovery request");
                match &case.intents[0] {
                    Intent::AcceptValue(bytes) => {
                        let Ok(Recovery {
                            key,
                            compressed,
                            doubled,
                        }) = got
                        else {
                            panic!("{ctx}: {got:?}");
                        };
                        assert_eq!(&recovered(&key, compressed), bytes, "{ctx}");
                        assert_eq!(doubled, case.tags.has(Tag::Doubled), "{ctx}");
                    }
                    Intent::RejectKind(kind) => assert_eq!(got, Err(*kind), "{ctx}"),
                    other => panic!("{ctx}: {other:?}"),
                }
            }
        }
        // The model on a request of every length but 65.
        assert_eq!(recover(&[0; 64], &[0; 32]), Err("ErrSigInvalidLen"));
    }

    /// Each class's per-PR cases cover every variant it can produce, and
    /// send its command.
    #[test]
    fn per_pr_counts_cover_every_variant() {
        let all_labels: [(&ClassSpec, usize); 12] = [
            (&ER_HONEST, 2),
            (&ER_FLIP_PARITY, 2),
            (&ER_HIGH_S, 2),
            (&ER_OVERFLOW_VALID, 4),
            (&ER_OVERFLOW_PRIME, 3),
            (&ER_NOT_ON_CURVE, 3),
            (&ER_INFINITY, 2),
            (&ER_DOUBLE, 2),
            (&ER_HEADER, 256),
            (&ER_LENGTH, 2),
            (&ER_RANGE, 60),
            (&ER_HASH, 4),
        ];
        for (class, labels) in all_labels {
            let mut variants = BTreeSet::new();
            for (_, case) in cases(class, class.pr_cases) {
                assert_eq!(case.requests.len(), 1);
                assert_eq!(case.requests[0].cmd, Cmd::EcdsaRecoverCompact);
                variants.insert(case.variant.into_owned());
            }
            assert_eq!(variants.len(), labels, "{}: {variants:?}", class.name);
        }
        for (i, case) in cases(&ER_LENGTH, 48) {
            assert_ne!(case.requests[0].data.len(), 97, "case {i}: not 65 bytes");
            assert!(
                case.requests[0].data.len() <= 162,
                "case {i}: at most 130 bytes"
            );
        }
    }

    /// Whether the early check that fails with `kind` fails for this
    /// header, r and s.
    fn fails(kind: &str, header: u8, r: &[u8; 32], s: &[u8; 32]) -> bool {
        match kind {
            "ErrSigInvalidRecoveryCode" => header
                .checked_sub(COMPACT_MAGIC)
                .is_none_or(|code| code > MAX_CODE),
            "ErrSigRTooBig" => *r >= N,
            "ErrSigRIsZero" => *r == [0; 32],
            "ErrSigSTooBig" => *s >= N,
            "ErrSigSIsZero" => *s == [0; 32],
            other => panic!("no early check fails with {other}"),
        }
    }

    /// ER-range tells dcrd's order of the early checks from each other
    /// order a port could take: both range checks before both zero checks,
    /// both zero checks before both range checks, or r and s parsed before
    /// the header.  Each names another kind than dcrd's on a case of the
    /// per-PR count, and only where two failing checks of different kinds
    /// meet: one of r and s zero and the other at or above N, or an invalid
    /// header with r and s out of range.  dcrd's order gives every case's
    /// intent.
    #[test]
    fn other_check_orders_are_told_apart() {
        const HEADER: &str = "ErrSigInvalidRecoveryCode";
        const R_RANGE: &str = "ErrSigRTooBig";
        const R_ZERO: &str = "ErrSigRIsZero";
        const S_RANGE: &str = "ErrSigSTooBig";
        const S_ZERO: &str = "ErrSigSIsZero";
        const DCRD: [&str; 5] = [HEADER, R_RANGE, R_ZERO, S_RANGE, S_ZERO];
        let others: [(&str, [&str; 5]); 3] = [
            ("ranges first", [HEADER, R_RANGE, S_RANGE, R_ZERO, S_ZERO]),
            ("zeros first", [HEADER, R_ZERO, S_ZERO, R_RANGE, S_RANGE]),
            ("header last", [R_RANGE, R_ZERO, S_RANGE, S_ZERO, HEADER]),
        ];
        let first = |order: &[&'static str; 5], header: u8, r: &[u8; 32], s: &[u8; 32]| {
            order.iter().copied().find(|kind| fails(kind, header, r, s))
        };
        let mut told_apart: Vec<BTreeSet<String>> = vec![BTreeSet::new(); others.len()];
        for (i, case) in cases(&ER_RANGE, ER_RANGE.pr_cases) {
            let (_, header, r, s) = decode(&case);
            let dcrd = first(&DCRD, header, &r, &s);
            assert_eq!(
                dcrd.map(Intent::RejectKind).as_ref(),
                Some(&case.intents[0]),
                "case {i} ({})",
                case.variant
            );
            for ((_, order), told) in others.iter().zip(told_apart.iter_mut()) {
                if first(order, header, &r, &s) != dcrd {
                    told.insert(case.variant.clone().into_owned());
                }
            }
        }
        let labels = |stratum: &str, pairs: &[(&str, &str)]| -> BTreeSet<String> {
            pairs
                .iter()
                .map(|(r, s)| format!("{stratum}/{r}/{s}"))
                .collect()
        };
        let high = ["N", "N+1", "max", "random"];
        let header: Vec<(&str, &str)> = RANGE_VALUES
            .iter()
            .flat_map(|r| RANGE_VALUES.iter().map(move |s| (*r, *s)))
            .collect();
        let want = [
            labels("both", &high.map(|s| ("0", s))),
            labels("both", &high.map(|r| (r, "0"))),
            labels("header", &header),
        ];
        for (((name, _), told), want) in others.iter().zip(&told_apart).zip(want) {
            assert_eq!(*told, want, "{name}");
        }
    }

    #[test]
    fn headers_and_codes() {
        assert_eq!(header(MAX_CODE, true), 34);
        assert_eq!(header(0, false), 27);
        assert_eq!(header(3, false), 30);
        assert_eq!(header(1, true), 32);
        assert_eq!(header(3, true), 34);
        for (k, &h) in OVERFLOW_HEADERS.iter().enumerate() {
            assert_eq!(
                h,
                header(recovery_code(true, k & 1 == 1), k >= 2),
                "header {h}"
            );
        }
        for (k, &h) in PLAIN_HEADERS.iter().enumerate() {
            assert_eq!(h, header(recovery_code(false, k & 1 == 1), k >= 2));
        }
        assert_eq!(compact(28, &be(1), &be(2)).len(), 65);
        assert_eq!(
            code_point(&[0xff; 32], CODE_OVERFLOW),
            None,
            "r + N carries"
        );
        // The invalid headers are the 248 bytes outside 27..=34, each drawn.
        let mut rng = dcroxide_testutil::SplitMix64(0x4ead_e125);
        let mut d = Draw::new(&mut rng);
        let drawn: BTreeSet<u8> = (0..4_096).map(|_| invalid_header(&mut d)).collect();
        let want: BTreeSet<u8> = (0..=u8::MAX)
            .filter(|&b| !(COMPACT_MAGIC..=header(MAX_CODE, true)).contains(&b))
            .collect();
        assert_eq!(drawn, want);
        assert_eq!(want.len(), 248);
    }
}
