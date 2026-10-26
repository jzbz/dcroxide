// SPDX-License-Identifier: ISC
//! Ed25519 classes: signing (DS-*), public key parsing (DK-*), signature
//! parsing (DG-*) and raw verification (DV-*).
//!
//! dcrd's rules (`dcrec/edwards/v2`, which verifies through the January
//! 2017 `agl/ed25519`), as [`crate::model::ed25519`] models them: key
//! parsing decodes y reduced mod p and rejects x = 0 with the sign bit
//! set; signature parsing needs R to decode and S in [1, L − 1]; raw
//! verification rejects only an S with any of its top three bits set,
//! hashes the canonical key encoding, and compares s·B − k·A, A negated as
//! a point, byte for byte with R.  dcrd's Ed25519 errors carry no kind, and
//! dcroxide reproduces their text, so every rejection's text is compared.
//!
//! Honest signatures are (r·B, r + k·a) for random scalars a and r, with
//! k = SHA-512(R ‖ A ‖ m) mod L: never RFC 8032's seed expansion and never
//! dcroxide's signer, so the inputs cannot change when the signer does.
//!
//! The constructed classes (tier B) put a point T of order dividing 8 in
//! the key, A = a·B + T, and draw messages until the challenge k gives k·T
//! the value the class needs.  For an honest signature s·B − k·A is
//! R − k·T, so dcrd accepts exactly when k·T is the identity.  A verifier
//! that negates the scalar rather than the point computes R + (L − k)·T,
//! and L ≡ 5 (mod 8), so the two differ on some residues of k: those cases
//! carry [`Tag::FormsDiffer`].  `EIGHT_TORSION[i]` is i·T₈ for one
//! generator T₈ of the 8-torsion (curve25519-dalek's documented layout,
//! which the tests check), so its points have the orders 1, 8, 4, 8, 2, 8,
//! 4, 8 and the points of ⟨`EIGHT_TORSION[t]`⟩ are the j·t mod 8.

use std::borrow::Cow;
use std::cmp::Ordering;

use curve25519_dalek::constants::EIGHT_TORSION;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, IsIdentity};
use sha2::{Digest, Sha512};

use crate::arith::{self, ED25519_L, ED25519_P};
use crate::class::{Case, ClassSpec, Family, Intent, Mix, Size, Tag, Tags, Tier};
use crate::cmd::{self, Cmd, Request};
use crate::entropy::Entropy;
use crate::r#gen::{
    ALL_ACCEPTED, DECOMPRESS_TRIES, Draw, FLOOR_A, FLOOR_B, MIX_MIN_N, NONE_ACCEPTED, PR_CASES,
    SCALAR_TRIES, digit, single, stratum,
};

/// The signing command.
const SIGN: &[Cmd] = &[Cmd::Ed25519Sign];

/// The key parsing command.
const KEY_PARSE: &[Cmd] = &[Cmd::Ed25519PubkeyParse];

/// The signature parsing command.
const SIG_PARSE: &[Cmd] = &[Cmd::Ed25519Parse];

/// The raw verify command.
const VERIFY: &[Cmd] = &[Cmd::Ed25519Verify];

/// Draws for a message whose challenge must fall in one residue class
/// mod 8 (or mod a divisor of 8): each passes with odds of at least 1/8,
/// so 1,024 misses have odds of (7/8)^1024.
const GRIND_TRIES: u32 = 1_024;

/// `v` as a 32-byte little-endian value.
fn le(v: u64) -> [u8; 32] {
    arith::le_from_u64(v)
}

/// A uniform scalar: 64 random bytes reduced mod L.
fn random_scalar(d: &mut Draw) -> Scalar {
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&d.bytes32());
    wide[32..].copy_from_slice(&d.bytes32());
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// A point's canonical encoding: y below p, little-endian, with x's parity
/// in the top bit.
fn encode(p: &EdwardsPoint) -> [u8; 32] {
    p.compress().to_bytes()
}

/// The point an encoding names, decoded as dcrd and agl decode it: y is
/// the low 255 bits reduced mod p, x the root of x² = (y² − 1)/(dy² + 1)
/// of the parity the top bit asks for (zero when the root is zero).
/// `None` when no root exists.
fn decode(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    CompressedEdwardsY(*bytes).decompress()
}

/// The challenge k = SHA-512(R ‖ A ‖ m) mod L, over the encodings as
/// given.
fn challenge(r: &[u8; 32], key: &[u8; 32], msg: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    h.update(r);
    h.update(key);
    h.update(msg);
    Scalar::from_bytes_mod_order_wide(&h.finalize().into())
}

/// R ‖ S.
fn signature(r: &[u8; 32], s: &[u8; 32]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(r);
    out[32..].copy_from_slice(s);
    out
}

/// k mod 8, the low three bits of k's canonical value.  With 8·T the
/// identity, k·T = (k mod 8)·T for every T of order dividing 8.
fn residue(k: &Scalar) -> u8 {
    k.as_bytes()[0] & 7
}

/// k·T for a point T of order dividing 8: T added k mod 8 times.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "curve25519-dalek point operations only: modular group arithmetic, no integer operator here"
)]
fn torsion_multiple(t: &EdwardsPoint, k: &Scalar) -> EdwardsPoint {
    (0..residue(k)).fold(EdwardsPoint::identity(), |acc, _| acc + t)
}

/// Whether a point's x is zero: x² = (y² − 1)/(dy² + 1) vanishes exactly
/// for y = ±1, the identity and the point of order 2, which are the points
/// whose double is the identity.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "curve25519-dalek point operations only: modular group arithmetic, no integer operator here"
)]
fn x_is_zero(p: &EdwardsPoint) -> bool {
    (p + p).is_identity()
}

/// The forms a non-canonical encoding of a point takes, as labels: y + p
/// in place of y, with the sign bit kept, which fits in 255 bits only for
/// a y below 19; the sign bit set on an x of zero, which decoding ignores;
/// and both.
const NONCANONICAL_FORMS: [&str; 3] = ["y+p", "x0-signed", "y+p-x0-signed"];

/// The point's encoding in form `form` of [`NONCANONICAL_FORMS`], made
/// from its canonical encoding, for a point whose y is below 19 (for a
/// y + p form) and whose x is zero (for a signed form).
fn noncanonical_encoding(canonical: &[u8; 32], form: usize) -> [u8; 32] {
    let mut out = *canonical;
    if form != 1 {
        out = arith::add_le(&out, &ED25519_P).0;
    }
    if form != 0 {
        out[31] |= 0x80;
    }
    out
}

/// A verify case's inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Verify {
    /// The key's encoding, as the request carries it.
    key: [u8; 32],
    /// R ‖ S.
    sig: [u8; 64],
    /// The message.
    msg: Vec<u8>,
}

impl Verify {
    /// The `ed25519_verify` request.
    fn request(&self) -> Request {
        cmd::ed25519_verify(&self.key, &self.sig, &self.msg)
    }

    /// The inputs a construction falls back to when a retry runs out: the
    /// identity as key and as R, S = 0 and an empty message.
    fn fallback() -> Verify {
        let identity = encode(&EdwardsPoint::identity());
        Verify {
            key: identity,
            sig: signature(&identity, &[0; 32]),
            msg: Vec::new(),
        }
    }
}

/// A verify case of one request.
fn verify_case(variant: impl Into<Cow<'static, str>>, v: &Verify, intent: Intent) -> Case {
    single(variant, v.request(), intent)
}

/// The signature of `msg` by the secret scalar `a` whose key encodes as
/// `key`, and its challenge: R = r·B for a random r, S = r + k·a for the
/// challenge k of R, `key` and `msg`.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "curve25519-dalek scalar and point operations only: modular group arithmetic, no integer operator here"
)]
fn honest_signature(d: &mut Draw, a: &Scalar, key: &[u8; 32], msg: &[u8]) -> ([u8; 64], Scalar) {
    let r = random_scalar(d);
    let big_r = encode(&EdwardsPoint::mul_base(&r));
    let k = challenge(&big_r, key, msg);
    (signature(&big_r, &(r + k * a).to_bytes()), k)
}

/// A random key A = a·B and its signature of `msg`.
fn honest(d: &mut Draw, msg: Vec<u8>) -> Verify {
    let a = random_scalar(d);
    let key = encode(&EdwardsPoint::mul_base(&a));
    let (sig, _) = honest_signature(d, &a, &key, &msg);
    Verify { key, sig, msg }
}

/// A random message of a random length in `lo..=hi`.
fn random_message(d: &mut Draw, lo: usize, hi: usize) -> Vec<u8> {
    let len = d.len_in(lo, hi);
    d.bytes(len)
}

/// A 32-byte message whose challenge with `r` and `key` satisfies `want`,
/// and that challenge.  Falls back to the zero message.
fn grind(
    d: &mut Draw,
    r: &[u8; 32],
    key: &[u8; 32],
    want: impl Fn(&Scalar) -> bool,
) -> (Vec<u8>, Scalar) {
    d.retry(
        GRIND_TRIES,
        || (vec![0; 32], challenge(r, key, &[0; 32])),
        |d| {
            let msg = d.bytes(32);
            let k = challenge(r, key, &msg);
            want(&k).then_some((msg, k))
        },
    )
}

/// A signature by the secret scalar `a` over a message ground until its
/// challenge, hashed over `hashed` (the key's canonical encoding), is
/// `want` mod 8: the message, the signature and the challenge.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "curve25519-dalek scalar and point operations only: modular group arithmetic, no integer operator here"
)]
fn ground_signature(
    d: &mut Draw,
    a: &Scalar,
    hashed: &[u8; 32],
    want: u8,
) -> (Vec<u8>, [u8; 64], Scalar) {
    let r = random_scalar(d);
    let big_r = encode(&EdwardsPoint::mul_base(&r));
    let (msg, k) = grind(d, &big_r, hashed, |k| residue(k) == want);
    (msg, signature(&big_r, &(r + k * a).to_bytes()), k)
}

/// The intent and tags of an honest signature with challenge `k` by a key
/// whose torsion component is `t`: dcrd computes R − k·T and accepts
/// exactly when k·T is the identity; the scalar-negation form computes
/// R + (L − k)·T, and a case on which the two verdicts differ is tagged
/// [`Tag::FormsDiffer`].
#[allow(
    clippy::arithmetic_side_effects,
    reason = "curve25519-dalek scalar operations only: modular group arithmetic, no integer operator here"
)]
fn torsion_outcome(t: &EdwardsPoint, k: &Scalar) -> (Intent, Tags) {
    let accepts = torsion_multiple(t, k).is_identity();
    let negated_accepts = torsion_multiple(t, &-k).is_identity();
    let intent = if accepts {
        Intent::Accept
    } else {
        Intent::Reject
    };
    let tags = if accepts == negated_accepts {
        Tags::NONE
    } else {
        Tags::NONE.with(Tag::FormsDiffer)
    };
    (intent, tags)
}

/// The labels of DS-random's and DV-honest's message lengths.
const MESSAGE_LENGTHS: [&str; 7] = ["0", "1", "31", "32", "33", "64", "random"];

/// Message length `k` of [`MESSAGE_LENGTHS`]: 0, 1, 31, 32, 33, 64 or
/// uniform in 0..=1024, filled at random.
fn message(d: &mut Draw, k: usize) -> Vec<u8> {
    let len = match k {
        0 => 0,
        1 => 1,
        2 => 31,
        3 => 32,
        4 => 33,
        5 => 64,
        _ => d.len_in(0, 1024),
    };
    d.bytes(len)
}

/// A boundary-biased 32-byte value, with the distribution of `edgy_32` in
/// `crates/dcroxide-dcrec/tests/edwards_differential.rs`, and its kind:
/// random (two draws in five), within two of L, within two of p (a y just
/// below p, or a non-canonical one), or a y of 0, 1 or 2; the last three
/// with a random sign bit.
fn edgy_32(d: &mut Draw) -> ([u8; 32], &'static str) {
    let (mut out, kind) = match d.below(5) {
        0 | 1 => return (d.bytes32(), "random"),
        2 => {
            let mut out = ED25519_L;
            let tweak = u8::try_from(d.below(5)).unwrap_or(0);
            out[0] = out[0].wrapping_add(tweak).wrapping_sub(2);
            (out, "near-L")
        }
        3 => {
            let mut out = [0xff; 32];
            let tweak = u8::try_from(d.below(5)).unwrap_or(0);
            out[0] = 0xed_u8.wrapping_add(tweak).wrapping_sub(2);
            out[31] = 0x7f;
            (out, "near-p")
        }
        _ => {
            let mut out = [0u8; 32];
            out[0] = u8::try_from(d.below(3)).unwrap_or(0);
            (out, "tiny")
        }
    };
    if d.coin() {
        out[31] |= 0x80;
    }
    (out, kind)
}

fn ds_random(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let k = stratum(i, 7);
    let seed = d.bytes32();
    let msg = message(&mut d, k);
    d.finish(single(
        format!("len={}", MESSAGE_LENGTHS[k]),
        cmd::ed25519_sign(&seed, &msg),
        Intent::Accept,
    ))
}

fn dk_canonical(e: &mut dyn Entropy, _: u64) -> Case {
    let mut d = Draw::new(e);
    let key = encode(&EdwardsPoint::mul_base(&random_scalar(&mut d)));
    d.finish(single(
        "canonical",
        cmd::ed25519_pubkey_parse(&key),
        Intent::AcceptValue(key.to_vec()),
    ))
}

fn dk_random(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let (key, label): ([u8; 32], Cow<'static, str>) = if stratum(i, 2) == 0 {
        (d.bytes32(), "random".into())
    } else {
        let (key, kind) = edgy_32(&mut d);
        (key, format!("edgy/{kind}").into())
    };
    d.finish(single(label, cmd::ed25519_pubkey_parse(&key), Intent::Any))
}

/// DK-small's encodings: element `e` (below 57) of y in 0..=18 as y, then
/// the same y as y + p, then y in p − 19..p − 1, with its label.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "e is below 57: e - 19 is taken only from 19 on, and 57 - e is at least 1"
)]
fn small_y(e: usize) -> ([u8; 32], String) {
    let small = |v: usize| u64::try_from(v).unwrap_or(0);
    match e {
        0..19 => (le(small(e)), format!("y={e}")),
        19..38 => {
            let y = e - 19;
            (
                arith::add_le(&ED25519_P, &le(small(y))).0,
                format!("y=p+{y}"),
            )
        }
        _ => {
            let below = 57 - e;
            (
                arith::sub_le(&ED25519_P, &le(small(below))).0,
                format!("y=p-{below}"),
            )
        }
    }
}

fn dk_small(e: &mut dyn Entropy, i: u64) -> Case {
    let d = Draw::new(e);
    let signed = stratum(i, 2) == 1;
    let (mut key, label) = small_y(digit(i, 2, 57));
    if signed {
        key[31] |= 0x80;
    }
    let intent = match decode(&key) {
        Some(p) if !(signed && x_is_zero(&p)) => Intent::AcceptValue(encode(&p).to_vec()),
        _ => Intent::RejectPlain,
    };
    d.finish(single(
        format!("{label}/s{}", u8::from(signed)),
        cmd::ed25519_pubkey_parse(&key),
        intent,
    ))
}

fn dk_length(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let len = usize::try_from(i).unwrap_or(0);
    let case = match len {
        32 => {
            let key = encode(&EdwardsPoint::mul_base(&random_scalar(&mut d)));
            single(
                "32",
                cmd::ed25519_pubkey_parse(&key),
                Intent::AcceptValue(key.to_vec()),
            )
        }
        0 => single("0", cmd::ed25519_pubkey_parse(&[]), Intent::RejectPlain),
        _ => single(
            "other",
            cmd::ed25519_pubkey_parse(&d.bytes(len)),
            Intent::RejectPlain,
        ),
    };
    d.finish(case)
}

/// DG-edges' kinds of R.
const R_KINDS: [&str; 4] = ["canonical", "y+p", "x0-signed", "off-curve"];

/// DG-edges' values of S.
const S_VALUES: [&str; 8] = ["0", "1", "L-1", "L", "L+1", "2^253-1", "2^255", "2^256-1"];

/// Value `k` of [`S_VALUES`], little-endian.
fn s_value(k: usize) -> [u8; 32] {
    match k {
        0 => [0; 32],
        1 => le(1),
        2 => arith::sub_le(&ED25519_L, &le(1)).0,
        3 => ED25519_L,
        4 => arith::add_le(&ED25519_L, &le(1)).0,
        5 => {
            let mut v = [0xff; 32];
            v[31] = 0x1f;
            v
        }
        6 => {
            let mut v = [0; 32];
            v[31] = 0x80;
            v
        }
        _ => [0xff; 32],
    }
}

/// R of kind `k` of [`R_KINDS`]: a random point's canonical encoding; y + p
/// for a y below 19 that decodes, with a random sign bit; y = 1 or p − 1
/// (x = 0) with the sign bit set; or a canonical y that does not decode,
/// with a random sign bit.
fn edge_r(d: &mut Draw, k: usize) -> [u8; 32] {
    match k {
        0 => encode(&EdwardsPoint::mul_base(&random_scalar(d))),
        1 => d.retry(
            DECOMPRESS_TRIES,
            || arith::add_le(&ED25519_P, &le(1)).0,
            |d| {
                let mut r = arith::add_le(&ED25519_P, &le(d.below(19))).0;
                if d.coin() {
                    r[31] |= 0x80;
                }
                decode(&r).map(|_| r)
            },
        ),
        2 => {
            let mut r = if d.coin() {
                le(1)
            } else {
                arith::sub_le(&ED25519_P, &le(1)).0
            };
            r[31] |= 0x80;
            r
        }
        _ => d.retry(
            DECOMPRESS_TRIES,
            || le(2),
            |d| {
                let mut r = d.bytes32();
                r[31] &= 0x7f;
                let canonical = arith::cmp_le(&r, &ED25519_P) == Ordering::Less;
                if d.coin() {
                    r[31] |= 0x80;
                }
                (canonical && decode(&r).is_none()).then_some(r)
            },
        ),
    }
}

fn dg_edges(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let kind = stratum(i, 4);
    let which = digit(i, 4, 8);
    let r = edge_r(&mut d, kind);
    let sig = signature(&r, &s_value(which));
    // R decodes for every kind but the last, and S = 1 and L − 1 are the
    // two values in [1, L − 1].
    let intent = if kind != 3 && matches!(which, 1 | 2) {
        Intent::AcceptValue(sig.to_vec())
    } else {
        Intent::RejectPlain
    };
    d.finish(single(
        format!("{}/S={}", R_KINDS[kind], S_VALUES[which]),
        cmd::ed25519_parse(&sig),
        intent,
    ))
}

fn dg_random(e: &mut dyn Entropy, _: u64) -> Case {
    let mut d = Draw::new(e);
    // The signature parse generator of crates/dcroxide-dcrec/tests/
    // edwards_differential.rs: an honest signature one time in six, random
    // bytes of a random length up to 70 one in six, else two edgy halves.
    let (sig, label) = match d.below(6) {
        0 => {
            let msg = d.bytes(32);
            (honest(&mut d, msg).sig.to_vec(), "honest")
        }
        1 => (random_message(&mut d, 0, 70), "random-length"),
        _ => {
            let (r, _) = edgy_32(&mut d);
            let (s, _) = edgy_32(&mut d);
            (signature(&r, &s).to_vec(), "edgy")
        }
    };
    d.finish(single(label, cmd::ed25519_parse(&sig), Intent::Any))
}

fn dv_honest(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let k = stratum(i, 7);
    let msg = message(&mut d, k);
    let v = honest(&mut d, msg);
    d.finish(verify_case(
        format!("len={}", MESSAGE_LENGTHS[k]),
        &v,
        Intent::Accept,
    ))
}

/// Flips bit `bit` (below 8·len) of a little-endian byte string.
fn flip(bytes: &mut [u8], bit: u64) {
    let len = u64::try_from(bytes.len()).unwrap_or(1).max(1);
    bytes[digit(bit, 8, len)] ^= 1u8 << stratum(bit, 8);
}

/// DV-tamper's edits.
const TAMPER: [&str; 4] = ["R", "S", "message", "key"];

fn dv_tamper(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let edit = stratum(i, 4);
    let msg = random_message(&mut d, 1, 64);
    let mut v = honest(&mut d, msg);
    match edit {
        0 => flip(&mut v.sig[..32], d.below(256)),
        1 => flip(&mut v.sig[32..], d.below(256)),
        2 => {
            let bits = u64::try_from(v.msg.len()).map_or(8, |n| n.saturating_mul(8));
            flip(&mut v.msg, d.below(bits));
        }
        _ => flip(&mut v.key, d.below(256)),
    }
    d.finish(verify_case(TAMPER[edit], &v, Intent::Reject))
}

fn dv_s_plus_l(e: &mut dyn Entropy, _: u64) -> Case {
    let mut d = Draw::new(e);
    // S + L names the same s·B, and agl checks only S's top three bits:
    // redrawn in the rare case S + L reaches them.
    let v = d.retry(SCALAR_TRIES, Verify::fallback, |d| {
        let msg = random_message(d, 0, 64);
        let mut v = honest(d, msg);
        let s: [u8; 32] = v.sig[32..].try_into().expect("32 bytes");
        let (plus, _) = arith::add_le(&s, &ED25519_L);
        (plus[31] & 0xe0 == 0).then(|| {
            v.sig[32..].copy_from_slice(&plus);
            v
        })
    });
    d.finish(verify_case("S+L", &v, Intent::Accept))
}

/// DV-topBits' bits of S's last byte, its first four strata.
const TOP_BITS: [(u8, &str); 4] = [
    (0x20, "0x20"),
    (0x40, "0x40"),
    (0x80, "0x80"),
    (0xe0, "0xe0"),
];

fn dv_top_bits(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let which = stratum(i, 5);
    let msg = random_message(&mut d, 0, 64);
    let mut v = honest(&mut d, msg);
    let label = match TOP_BITS.get(which) {
        // A bit set in S changes S mod L as well, so s·B − k·A misses R.
        Some(&(bits, label)) => {
            v.sig[63] |= bits;
            label
        }
        // S + j·L for j in 2..=14 names the same s·B as S: at least 2L,
        // above 2^253, and below 15L, below 2^256.  Only the top-bits
        // check rejects it.
        None => {
            let mut s: [u8; 32] = v.sig[32..].try_into().expect("32 bytes");
            for _ in 0..d.below(13).saturating_add(2) {
                s = arith::add_le(&s, &ED25519_L).0;
            }
            v.sig[32..].copy_from_slice(&s);
            "S+jL"
        }
    };
    d.finish(verify_case(label, &v, Intent::Reject))
}

fn dv_random(e: &mut dyn Entropy, _: u64) -> Case {
    let mut d = Draw::new(e);
    let key = encode(&EdwardsPoint::mul_base(&random_scalar(&mut d)));
    let sig = signature(&d.bytes32(), &d.bytes32());
    let msg = random_message(&mut d, 0, 64);
    d.finish(verify_case(
        "random",
        &Verify { key, sig, msg },
        Intent::Reject,
    ))
}

/// The labels of the torsion classes' key forms: a = 0 (A = T) or a
/// random a.
const FORMS: [&str; 2] = ["a=0", "a=random"];

#[allow(
    clippy::arithmetic_side_effects,
    reason = "curve25519-dalek point operations only: modular group arithmetic, no integer operator here"
)]
fn dv_torsion(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let t = digit(i, 16, 8);
    let form = digit(i, 8, 2);
    let want = u8::try_from(stratum(i, 8)).unwrap_or(0);
    let torsion = EIGHT_TORSION[t];
    let a = if form == 1 {
        random_scalar(&mut d)
    } else {
        Scalar::ZERO
    };
    let key = encode(&(EdwardsPoint::mul_base(&a) + torsion));
    let (msg, sig, k) = ground_signature(&mut d, &a, &key, want);
    let (intent, tags) = torsion_outcome(&torsion, &k);
    let mut case = verify_case(
        format!("T{t}/{}/r{want}", FORMS[form]),
        &Verify { key, sig, msg },
        intent,
    );
    case.tags = tags;
    d.finish(case)
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "curve25519-dalek point operations only: modular group arithmetic, no integer operator here"
)]
fn dv_torsion_sweep(e: &mut dyn Entropy, _: u64) -> Case {
    let mut d = Draw::new(e);
    let t = usize::try_from(d.below(8)).unwrap_or(0);
    let torsion = EIGHT_TORSION[t];
    let form = usize::from(d.below(8) != 0);
    let a = if form == 1 {
        random_scalar(&mut d)
    } else {
        Scalar::ZERO
    };
    let key = encode(&(EdwardsPoint::mul_base(&a) + torsion));
    let msg = random_message(&mut d, 0, 63);
    let (sig, k) = honest_signature(&mut d, &a, &key, &msg);
    let (intent, tags) = torsion_outcome(&torsion, &k);
    let mut case = verify_case(
        format!("T{t}/{}", FORMS[form]),
        &Verify { key, sig, msg },
        intent,
    );
    case.tags = tags;
    d.finish(case)
}

/// DV-torsionNoncanon's keys: the identity as y = p + 1, and the two points
/// of order 4 (y = 0) as y = p with the sign bit clear and set.
const NONCANONICAL_KEYS: [&str; 3] = ["identity-p1", "order4-p-s0", "order4-p-s1"];

/// Key `k` of [`NONCANONICAL_KEYS`].
fn noncanonical_key(k: usize) -> [u8; 32] {
    match k {
        0 => arith::add_le(&ED25519_P, &le(1)).0,
        1 => ED25519_P,
        _ => {
            let mut key = ED25519_P;
            key[31] |= 0x80;
            key
        }
    }
}

fn dv_torsion_noncanon(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let which = digit(i, 8, 3);
    let want = u8::try_from(stratum(i, 8)).unwrap_or(0);
    let key = noncanonical_key(which);
    let torsion = decode(&key).expect("each key encodes a point");
    // dcrd hashes the parsed key's canonical encoding, so the residue is
    // ground on that; with a = 0, S = r.
    let canonical = encode(&torsion);
    let (msg, sig, k) = ground_signature(&mut d, &Scalar::ZERO, &canonical, want);
    let (intent, _) = torsion_outcome(&torsion, &k);
    d.finish(verify_case(
        format!("{}/r{want}", NONCANONICAL_KEYS[which]),
        &Verify { key, sig, msg },
        intent,
    ))
}

/// Every encoding but the canonical one that agl decodes to a torsion
/// point, as the point's index into `EIGHT_TORSION` and the form of
/// [`NONCANONICAL_FORMS`] that makes it: y + p for the identity (y = 1)
/// and the two points of order 4 (y = 0), the torsion points whose y is
/// below 19; the sign bit set for the identity and the point of order 2
/// (y = p − 1), the ones whose x is zero; and both for the identity.
const NONCANONICAL_ENCODINGS: [(usize, usize); 6] =
    [(0, 0), (0, 1), (0, 2), (2, 0), (4, 1), (6, 0)];

/// Whether `EIGHT_TORSION[m]` is in the subgroup `EIGHT_TORSION[t]`
/// generates: some j·t ≡ m (mod 8).
#[allow(
    clippy::arithmetic_side_effects,
    reason = "j and t are below 8, so j·t is below 64, and 8 is nonzero"
)]
fn in_subgroup(m: usize, t: usize) -> bool {
    (0..8).any(|j| j * t % 8 == m)
}

/// DV-zeroS-smallR's stratum `s` (below 86): T and R as indices into
/// `EIGHT_TORSION`, and the form of [`NONCANONICAL_FORMS`] R's encoding
/// takes, `None` for the canonical one.  First the 43 pairs with R in ⟨T⟩,
/// R canonical, by T then R; then, by T, the 43 non-canonical encodings
/// of [`NONCANONICAL_ENCODINGS`] whose point is in ⟨T⟩, in that list's
/// order.
fn zero_s_stratum(s: usize) -> (usize, usize, Option<usize>) {
    let canonical = (0..8).flat_map(|t| {
        (0..8)
            .filter(move |&m| in_subgroup(m, t))
            .map(move |m| (t, m, None))
    });
    let noncanonical = (0..8).flat_map(|t| {
        NONCANONICAL_ENCODINGS
            .into_iter()
            .filter(move |&(m, _)| in_subgroup(m, t))
            .map(move |(m, form)| (t, m, Some(form)))
    });
    canonical
        .chain(noncanonical)
        .nth(s)
        .expect("a stratum below 86")
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "curve25519-dalek point operations only: modular group arithmetic, no integer operator here"
)]
fn dv_zero_s_small_r(e: &mut dyn Entropy, i: u64) -> Case {
    let mut d = Draw::new(e);
    let (t, m, form) = zero_s_stratum(stratum(i, 86));
    let torsion = EIGHT_TORSION[t];
    let target = EIGHT_TORSION[m];
    let key = encode(&torsion);
    let canonical = encode(&target);
    let r = form.map_or(canonical, |form| noncanonical_encoding(&canonical, form));
    // With S = 0, s·B − k·A = −(k·T): ground until that is R's point.
    let (msg, _) = grind(&mut d, &r, &key, |k| {
        -torsion_multiple(&torsion, k) == target
    });
    let (label, intent) = match form {
        Some(form) => (
            format!("noncanonical/T{t}/T{m}/{}", NONCANONICAL_FORMS[form]),
            Intent::Reject,
        ),
        None => (format!("canonical/T{t}/T{m}"), Intent::Accept),
    };
    d.finish(verify_case(
        label,
        &Verify {
            key,
            sig: signature(&r, &[0; 32]),
            msg,
        },
        intent,
    ))
}

/// DS-random.
pub const DS_RANDOM: ClassSpec = ClassSpec {
    name: "DS-random",
    family: Family::Ed25519,
    commands: SIGN,
    size: Size::Stratified {
        strata: 7,
        floor: FLOOR_B,
    },
    tier: Tier::B,
    generator: ds_random,
    mix: ALL_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "a random seed signs a message of 0, 1, 31, 32, 33, 64 or up to 1024 random bytes \
          (i % 7): the signature and the public key, compared byte for byte",
};

/// DK-canonical.
pub const DK_CANONICAL: ClassSpec = ClassSpec {
    name: "DK-canonical",
    family: Family::Ed25519,
    commands: KEY_PARSE,
    size: Size::Sampled { floor: FLOOR_A },
    tier: Tier::A,
    generator: dk_canonical,
    mix: ALL_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "the canonical encoding of a·B for a random a: parses to itself",
};

/// DK-random.
pub const DK_RANDOM: ClassSpec = ClassSpec {
    name: "DK-random",
    family: Family::Ed25519,
    commands: KEY_PARSE,
    size: Size::Stratified {
        strata: 2,
        floor: FLOOR_A,
    },
    tier: Tier::A,
    generator: dk_random,
    // About half of all y decode, and edgy_32's own kinds come to a half
    // too.
    mix: &[Mix::AcceptRate {
        lo: 0.40,
        hi: 0.60,
        min_n: MIX_MIN_N,
    }],
    pr_cases: PR_CASES,
    doc: "32 random bytes, or a value near L, near p or a small y with a random sign bit (i % 2)",
};

/// DK-small.
pub const DK_SMALL: ClassSpec = ClassSpec {
    name: "DK-small",
    family: Family::Ed25519,
    commands: KEY_PARSE,
    size: Size::Finite { size: 114 },
    tier: Tier::Finite,
    generator: dk_small,
    mix: &[Mix::AcceptCount(69)],
    pr_cases: 114,
    doc: "every y in 0..=18 as y and y + p, and every y in p-19..p-1, with the sign bit clear \
          and set: accepted when y is on the curve and not x = 0 with the sign bit",
};

/// DK-length.
pub const DK_LENGTH: ClassSpec = ClassSpec {
    name: "DK-length",
    family: Family::Ed25519,
    commands: KEY_PARSE,
    size: Size::Finite { size: 65 },
    tier: Tier::Finite,
    generator: dk_length,
    mix: &[Mix::AcceptCount(1)],
    pr_cases: 65,
    doc: "every length 0..=64 (i): a valid key at 32, random bytes elsewhere",
};

/// DG-edges.
pub const DG_EDGES: ClassSpec = ClassSpec {
    name: "DG-edges",
    family: Family::Ed25519,
    commands: SIG_PARSE,
    size: Size::Stratified {
        strata: 32,
        floor: FLOOR_A,
    },
    tier: Tier::A,
    generator: dg_edges,
    // 6 of the 32 strata parse: three kinds of R that decode, each with S
    // = 1 and S = L - 1.
    mix: &[Mix::AcceptRate {
        lo: 0.1874,
        hi: 0.1876,
        min_n: MIX_MIN_N,
    }],
    pr_cases: PR_CASES,
    doc: "R canonical, y + p, x = 0 with the sign bit, or off the curve (i % 4) with S 0, 1, L-1, \
          L, L+1, 2^253-1, 2^255 or 2^256-1 ((i / 4) % 8): parses when R decodes and S is 1 or L-1",
};

/// DG-random.
pub const DG_RANDOM: ClassSpec = ClassSpec {
    name: "DG-random",
    family: Family::Ed25519,
    commands: SIG_PARSE,
    size: Size::Sampled { floor: FLOOR_A },
    tier: Tier::A,
    generator: dg_random,
    mix: &[],
    pr_cases: PR_CASES,
    doc: "honest signatures, random blobs up to 70 bytes, and halves near L, near p or small",
};

/// DV-honest.
pub const DV_HONEST: ClassSpec = ClassSpec {
    name: "DV-honest",
    family: Family::Ed25519,
    commands: VERIFY,
    size: Size::Stratified {
        strata: 7,
        floor: FLOOR_A,
    },
    tier: Tier::A,
    generator: dv_honest,
    mix: ALL_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "(r·B, r + k·a) by a random key over a message of 0, 1, 31, 32, 33, 64 or up to 1024 \
          random bytes (i % 7): valid",
};

/// DV-tamper.
pub const DV_TAMPER: ClassSpec = ClassSpec {
    name: "DV-tamper",
    family: Family::Ed25519,
    commands: VERIFY,
    size: Size::Stratified {
        strata: 4,
        floor: FLOOR_A,
    },
    tier: Tier::A,
    generator: dv_tamper,
    mix: NONE_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "an honest signature with one bit of R, S, the message or the key flipped (i % 4)",
};

/// DV-SplusL.
pub const DV_S_PLUS_L: ClassSpec = ClassSpec {
    name: "DV-SplusL",
    family: Family::Ed25519,
    commands: VERIFY,
    size: Size::Sampled { floor: FLOOR_A },
    tier: Tier::A,
    generator: dv_s_plus_l,
    mix: ALL_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "an honest signature with S + L below 2^253, which raw verification accepts",
};

/// DV-topBits.
pub const DV_TOP_BITS: ClassSpec = ClassSpec {
    name: "DV-topBits",
    family: Family::Ed25519,
    commands: VERIFY,
    size: Size::Stratified {
        strata: 5,
        floor: FLOOR_A,
    },
    tier: Tier::A,
    generator: dv_top_bits,
    mix: NONE_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "an honest signature with 0x20, 0x40, 0x80 or 0xe0 set in S's last byte, or with S + j·L \
          for j in 2..=14, which verifies but for its top bits (i % 5): rejected for the top bits",
};

/// DV-random.
pub const DV_RANDOM: ClassSpec = ClassSpec {
    name: "DV-random",
    family: Family::Ed25519,
    commands: VERIFY,
    size: Size::Sampled { floor: FLOOR_A },
    tier: Tier::A,
    generator: dv_random,
    mix: NONE_ACCEPTED,
    pr_cases: PR_CASES,
    doc: "a valid random key with a random 64-byte signature and message",
};

/// DV-torsion.
pub const DV_TORSION: ClassSpec = ClassSpec {
    name: "DV-torsion",
    family: Family::Ed25519,
    commands: VERIFY,
    size: Size::Finite { size: 128 },
    tier: Tier::Finite,
    generator: dv_torsion,
    // Per key form, 20 of the 64 (point, residue) pairs give k·T = O, and
    // the scalar-negation form differs on 24.
    mix: &[
        Mix::AcceptCount(40),
        Mix::TagRate {
            tag: Tag::FormsDiffer,
            lo: 0.375,
            hi: 0.375,
            min_n: 128,
        },
    ],
    pr_cases: 128,
    doc: "A = a·B + EIGHT_TORSION[i / 16] with a = 0 or random ((i / 8) % 2), signed over a \
          message ground until k = i (mod 8): accepted when k·T = O",
};

/// DV-torsionSweep.
pub const DV_TORSION_SWEEP: ClassSpec = ClassSpec {
    name: "DV-torsionSweep",
    family: Family::Ed25519,
    commands: VERIFY,
    size: Size::Sampled { floor: FLOOR_B },
    tier: Tier::B,
    generator: dv_torsion_sweep,
    // An eighth of the order-8 points' cases, a quarter of the order-4
    // points', half of the order-2 point's and all of the identity's are
    // accepted: 2.5 of 8.  The forms differ on 24 of 64.
    mix: &[
        Mix::AcceptRate {
            lo: 0.3025,
            hi: 0.3225,
            min_n: MIX_MIN_N,
        },
        Mix::TagRate {
            tag: Tag::FormsDiffer,
            lo: 0.365,
            hi: 0.385,
            min_n: MIX_MIN_N,
        },
    ],
    pr_cases: PR_CASES,
    doc: "A = a·B + T for T uniform among the eight small-order points and a = 0 one time in \
          eight, honestly signed over a message of 0..=63 bytes: accepted when k·T = O",
};

/// DV-torsionNoncanon.
pub const DV_TORSION_NONCANON: ClassSpec = ClassSpec {
    name: "DV-torsionNoncanon",
    family: Family::Ed25519,
    commands: VERIFY,
    size: Size::Stratified {
        strata: 24,
        floor: FLOOR_B,
    },
    tier: Tier::B,
    generator: dv_torsion_noncanon,
    // The identity accepts at all 8 residues, each order-4 key at 2: 12
    // of the 24 strata.
    mix: &[Mix::AcceptRate {
        lo: 0.4999,
        hi: 0.5001,
        min_n: MIX_MIN_N,
    }],
    pr_cases: PR_CASES,
    doc: "the identity as y = p + 1 and the order-4 points as y = p, sign 0 and 1 ((i / 8) % 3), \
          with R = r·B, S = r and k, over the canonical key, ground until k = i (mod 8): \
          accepted when k·T = O",
};

/// DV-zeroS-smallR.
pub const DV_ZERO_S_SMALL_R: ClassSpec = ClassSpec {
    name: "DV-zeroS-smallR",
    family: Family::Ed25519,
    commands: VERIFY,
    size: Size::Stratified {
        strata: 86,
        floor: FLOOR_B,
    },
    tier: Tier::B,
    generator: dv_zero_s_small_r,
    // The 43 canonical strata of 86 accept, and lead each cycle of 86: of
    // n cases, n/2 + min(n % 86, 43) - (n % 86)/2 accept, n/2 plus 0 to
    // 21.5, so from 10^5 cases on the share is in [0.5, 0.500215].
    mix: &[Mix::AcceptRate {
        lo: 0.4999,
        hi: 0.5003,
        min_n: MIX_MIN_N,
    }],
    pr_cases: 172,
    doc: "A = T of small order, S = 0, and R a point of <T> (i % 86), the message ground until \
          -k·T is R: accepted when R is encoded canonically, rejected in each other encoding \
          that decodes to it (y + p, the sign bit set on an x of zero, or both)",
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::class::generate;
    use crate::model::ed25519::{self as model, Outcome, Reason};
    use std::collections::BTreeSet;

    /// Every Ed25519 class.
    const CLASSES: [&ClassSpec; 16] = [
        &DS_RANDOM,
        &DK_CANONICAL,
        &DK_RANDOM,
        &DK_SMALL,
        &DK_LENGTH,
        &DG_EDGES,
        &DG_RANDOM,
        &DV_HONEST,
        &DV_TAMPER,
        &DV_S_PLUS_L,
        &DV_TOP_BITS,
        &DV_RANDOM,
        &DV_TORSION,
        &DV_TORSION_SWEEP,
        &DV_TORSION_NONCANON,
        &DV_ZERO_S_SMALL_R,
    ];

    fn cases(class: &ClassSpec, n: u64) -> impl Iterator<Item = (u64, Case)> + '_ {
        (0..n).map(move |i| (i, generate(class, 0x00ed_5eed, i)))
    }

    /// A class's cases for its tests: every element of a finite class, else
    /// its per-PR count and at least 16.
    fn all_cases(class: &ClassSpec) -> impl Iterator<Item = (u64, Case)> + '_ {
        cases(class, class.size.finite().unwrap_or(class.pr_cases.max(16)))
    }

    /// A verify request decoded: key, signature, message.
    fn decode_verify(case: &Case) -> ([u8; 32], [u8; 64], Vec<u8>) {
        let data = &case.requests[0].data;
        assert_eq!(case.requests[0].cmd, Cmd::Ed25519Verify);
        let key: [u8; 32] = data[..32].try_into().expect("key");
        let sig: [u8; 64] = data[32..96].try_into().expect("signature");
        (key, sig, data[96..].to_vec())
    }

    /// SHA-512(R ‖ A ‖ m) mod L, written out here apart from the generator.
    fn k_of(r: &[u8], a: &[u8; 32], msg: &[u8]) -> Scalar {
        let digest: [u8; 64] = Sha512::digest([r, a.as_slice(), msg].concat()).into();
        Scalar::from_bytes_mod_order_wide(&digest)
    }

    /// The torsion component of a point: A − (8⁻¹ mod L)·8A, since 8A
    /// keeps only the prime-order part, times 8.  `inv8` is 8⁻¹ mod L.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "curve25519-dalek scalar and point operations only: modular group arithmetic, no integer operator here"
    )]
    fn torsion_component(a: &EdwardsPoint, inv8: &Scalar) -> EdwardsPoint {
        a - inv8 * a.mul_by_cofactor()
    }

    /// Every intent holds in the model: each key and signature parse
    /// intent is what dcrd's parse rules, as the model has them, give, and
    /// every verify intent is the model's verdict, DV-topBits' for the top
    /// bits.  Every element of the finite classes, and the per-PR count
    /// and at least 16 of the others.
    #[test]
    fn every_intent_holds_in_the_model() {
        for class in CLASSES {
            for (i, case) in all_cases(class) {
                let ctx = format!("{} case {i} ({})", class.name, case.variant);
                assert!(!case.tags.has(Tag::Fallback), "{ctx}: fallback");
                let request = &case.requests[0];
                let intent = &case.intents[0];
                match request.cmd {
                    Cmd::Ed25519Sign => {
                        assert_eq!(*intent, Intent::Accept, "{ctx}");
                        assert!(request.data.len() >= 32, "{ctx}");
                    }
                    Cmd::Ed25519PubkeyParse => {
                        let got = model::parse_pub_key(&request.data);
                        match intent {
                            Intent::AcceptValue(want) => {
                                let key = got.unwrap_or_else(|e| panic!("{ctx}: {e}"));
                                assert_eq!(key.canonical.as_slice(), want.as_slice(), "{ctx}");
                            }
                            Intent::RejectPlain => assert!(got.is_err(), "{ctx}"),
                            Intent::Any => {}
                            other => panic!("{ctx}: {other:?}"),
                        }
                    }
                    Cmd::Ed25519Parse => {
                        let got = model::parse_signature(&request.data);
                        match intent {
                            Intent::AcceptValue(want) => {
                                assert_eq!(got.map(|s| s.to_vec()), Ok(want.clone()), "{ctx}");
                            }
                            Intent::RejectPlain => assert!(got.is_err(), "{ctx}"),
                            Intent::Any => {}
                            other => panic!("{ctx}: {other:?}"),
                        }
                    }
                    Cmd::Ed25519Verify => {
                        let got = model::verify_request(request).expect("a verify request");
                        match intent {
                            Intent::Accept => {
                                assert_eq!(got, Outcome::Verified(Ok(())), "{ctx}");
                            }
                            Intent::Reject => {
                                assert_ne!(got, Outcome::Verified(Ok(())), "{ctx}");
                            }
                            other => panic!("{ctx}: {other:?}"),
                        }
                        if class.name == "DV-topBits" {
                            assert_eq!(got, Outcome::Verified(Err(Reason::TopBitsSet)), "{ctx}");
                        }
                    }
                    other => panic!("{ctx}: {other:?}"),
                }
            }
        }
    }

    /// The finite classes' exact counts: 69 of DK-small's 114 encodings
    /// parse, 1 of DK-length's 65 lengths, and 40 of DV-torsion's 128
    /// signatures verify, 20 per key form, with the scalar-negation form
    /// differing on 48, 24 per key form.  The model agrees with each.
    #[test]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "counters of at most 128 cases in usize"
    )]
    fn finite_classes_have_their_counts() {
        let accepted = |class: &ClassSpec| {
            cases(class, class.size.finite().expect("finite"))
                .filter(|(_, c)| matches!(c.intents[0], Intent::Accept | Intent::AcceptValue(_)))
                .count()
        };
        assert_eq!(accepted(&DK_SMALL), 69);
        assert_eq!(accepted(&DK_LENGTH), 1);
        assert_eq!(accepted(&DV_TORSION), 40);
        let small_keys: BTreeSet<Vec<u8>> = cases(&DK_SMALL, 114)
            .map(|(_, c)| c.requests[0].data.clone())
            .collect();
        assert_eq!(small_keys.len(), 114, "every encoding once");
        let parsed = small_keys
            .iter()
            .filter(|k| model::parse_pub_key(k).is_ok())
            .count();
        assert_eq!(parsed, 69, "the model");

        let mut per_form = [(0, 0); 2];
        for (i, case) in cases(&DV_TORSION, 128) {
            let form = &mut per_form[digit(i, 8, 2)];
            let accepts =
                model::verify_request(&case.requests[0]) == Some(Outcome::Verified(Ok(())));
            assert_eq!(accepts, case.intents[0] == Intent::Accept, "case {i}");
            form.0 += usize::from(accepts);
            form.1 += usize::from(case.tags.has(Tag::FormsDiffer));
        }
        assert_eq!(per_form, [(20, 24); 2]);
        assert_eq!(
            DV_TORSION.mix[1],
            Mix::TagRate {
                tag: Tag::FormsDiffer,
                lo: 0.375,
                hi: 0.375,
                min_n: 128
            }
        );
        for (class, want) in [(&DK_SMALL, 69), (&DK_LENGTH, 1), (&DV_TORSION, 40)] {
            assert_eq!(class.mix[0], Mix::AcceptCount(want), "{}", class.name);
        }
    }

    /// The numbers the design's scratch derived, from curve25519-dalek:
    /// the on-curve y among 0..=18 and among p − 19..p − 1; the layout and
    /// orders of `EIGHT_TORSION`; every non-canonical encoding of a
    /// torsion point; and the 43 + 43 strata of DV-zeroS-smallR.
    #[test]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "curve25519-dalek scalar and point operations only: modular group arithmetic, no integer operator here"
    )]
    fn the_curve_facts_the_classes_rest_on() {
        let on_curve = |v: [u8; 32]| decode(&v).is_some();
        let low: Vec<u64> = (0..=18).filter(|&y| on_curve(le(y))).collect();
        assert_eq!(low, [0, 1, 3, 4, 5, 6, 9, 10, 14, 15, 16, 18]);
        let high: Vec<u64> = (1..=19)
            .rev()
            .filter(|&j| on_curve(arith::sub_le(&ED25519_P, &le(j)).0))
            .collect();
        assert_eq!(high, [19, 18, 16, 15, 14, 10, 9, 6, 5, 4, 3, 1], "p - j");
        for y in 0..=18 {
            let plus_p = arith::add_le(&ED25519_P, &le(y)).0;
            assert_eq!(decode(&plus_p), decode(&le(y)), "y + p decodes as y");
        }

        let identity = EdwardsPoint::identity();
        let generator = EIGHT_TORSION[1];
        let mut orders = Vec::new();
        let mut found = BTreeSet::new();
        for (i, point) in EIGHT_TORSION.iter().enumerate() {
            let i8 = u8::try_from(i).expect("below 8");
            assert_eq!(*point, Scalar::from(i8) * generator, "[{i}]T8");
            let order = [1u8, 2, 4, 8]
                .into_iter()
                .find(|&o| (Scalar::from(o) * point).is_identity())
                .expect("order divides 8");
            orders.push(order);
            assert_eq!(x_is_zero(point), i == 0 || i == 4, "T{i}");
            // Decoding reduces y mod p, so every encoding of the point has
            // its canonical y or, where that fits in 255 bits, y + p, under
            // either sign bit: these are all the candidates.
            let canonical = encode(point);
            let mut y = canonical;
            y[31] &= 0x7f;
            let (plus_p, _) = arith::add_le(&y, &ED25519_P);
            let fits = plus_p[31] & 0x80 == 0;
            for y in [Some(y), fits.then_some(plus_p)].into_iter().flatten() {
                for sign in [0, 0x80] {
                    let mut bytes = y;
                    bytes[31] |= sign;
                    if bytes != canonical && decode(&bytes) == Some(*point) {
                        found.insert((i, bytes));
                    }
                }
            }
        }
        assert_eq!(orders, [1, 8, 4, 8, 2, 8, 4, 8]);
        assert_eq!(encode(&identity), le(1));
        for m in [2, 6] {
            let mut y = encode(&EIGHT_TORSION[m]);
            y[31] &= 0x7f;
            assert_eq!(y, [0; 32], "the order-4 points have y = 0");
        }
        // The non-canonical encodings are exactly the list's: the identity
        // as y = 1 signed and as y = p + 1 under either sign, the points of
        // order 4 as y = p under their own signs, the point of order 2 as
        // y = p - 1 signed.
        let listed: BTreeSet<(usize, [u8; 32])> = NONCANONICAL_ENCODINGS
            .iter()
            .map(|&(m, form)| {
                let bytes = noncanonical_encoding(&encode(&EIGHT_TORSION[m]), form);
                assert_eq!(decode(&bytes), Some(EIGHT_TORSION[m]), "T{m} {form}");
                (m, bytes)
            })
            .collect();
        assert_eq!(found, listed, "every non-canonical torsion encoding");
        let bytes = |first: &str, fill: &str, last: &str| -> [u8; 32] {
            dcroxide_testutil::unhex(&format!("{first}{}{last}", fill.repeat(30)))
                .try_into()
                .expect("32 bytes")
        };
        assert_eq!(
            listed,
            BTreeSet::from([
                (0, bytes("01", "00", "80")),
                (0, bytes("ee", "ff", "7f")),
                (0, bytes("ee", "ff", "ff")),
                (2, bytes("ed", "ff", "ff")),
                (4, bytes("ec", "ff", "ff")),
                (6, bytes("ed", "ff", "7f")),
            ])
        );
        // DV-torsionNoncanon's keys are the y + p encodings of the
        // identity and of the two points of order 4, three distinct points.
        let mut keyed = BTreeSet::new();
        for (k, label) in NONCANONICAL_KEYS.iter().enumerate() {
            let key = noncanonical_key(k);
            let point = decode(&key).expect("the key decodes");
            let m = EIGHT_TORSION
                .iter()
                .position(|t| *t == point)
                .expect("a torsion point");
            let want: &[usize] = if k == 0 { &[0] } else { &[2, 6] };
            assert!(want.contains(&m), "{label}: T{m}");
            assert_eq!(noncanonical_encoding(&encode(&point), 0), key);
            assert!(listed.contains(&(m, key)), "{label}");
            keyed.insert(m);
        }
        assert_eq!(keyed.len(), 3);

        // 43 canonical strata, then 43 non-canonical: 20 as y + p (the
        // identity under all eight T, each point of order 4 under the six
        // T of order 4 or 8), 15 signed (the identity under all eight, the
        // point of order 2 under the seven T of even order) and 8 both.
        let strata: Vec<_> = (0..86).map(zero_s_stratum).collect();
        assert!(
            strata[..43].iter().all(|s| s.2.is_none()),
            "canonical first"
        );
        let per_form: Vec<usize> = (0..NONCANONICAL_FORMS.len())
            .map(|form| strata.iter().filter(|s| s.2 == Some(form)).count())
            .collect();
        assert_eq!(per_form, [20, 15, 8]);
        let distinct: BTreeSet<_> = strata.iter().collect();
        assert_eq!(distinct.len(), 86);
        for &(t, m, form) in &strata {
            let subgroup = (0..8u8).any(|j| Scalar::from(j) * EIGHT_TORSION[t] == EIGHT_TORSION[m]);
            assert!(subgroup, "T{m} in <T{t}>");
            if let Some(form) = form {
                assert!(NONCANONICAL_ENCODINGS.contains(&(m, form)), "T{m} {form}");
            }
        }
    }

    /// The torsion classes reach what they are built for, on the numbers:
    /// per case, the key's torsion component, the challenge written out
    /// here, and the verdict and the scalar-negation verdict from full
    /// scalar multiplications; and DV-torsionSweep's shares, exactly.
    #[test]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "curve25519-dalek scalar and point operations, residues below 16, counters and shares of 64 pairs"
    )]
    fn torsion_classes_reach_their_branches() {
        let identity = EdwardsPoint::identity();
        let verdicts = |t: &EdwardsPoint, k: &Scalar| {
            let agl = k * t == identity;
            let negated = -k * t == identity;
            (agl, agl != negated)
        };
        for (i, case) in cases(&DV_TORSION, 128) {
            let (key, sig, msg) = decode_verify(&case);
            let a = decode(&key).expect("the key decodes");
            assert_eq!(encode(&a), key, "case {i}: a canonical key");
            let t = EIGHT_TORSION[digit(i, 16, 8)];
            assert!((a - t).is_torsion_free(), "case {i}: A - T = a·B");
            if digit(i, 8, 2) == 0 {
                assert_eq!(a, t, "case {i}: a = 0");
            }
            let k = k_of(&sig[..32], &key, &msg);
            assert_eq!(
                usize::from(residue(&k)),
                stratum(i, 8),
                "case {i}: the residue"
            );
            let (accepts, differ) = verdicts(&t, &k);
            assert_eq!(case.intents[0] == Intent::Accept, accepts, "case {i}");
            assert_eq!(case.tags.has(Tag::FormsDiffer), differ, "case {i}");
        }

        let inv8 = Scalar::from(8u8).invert();
        assert_eq!(inv8 * Scalar::from(8u8), Scalar::ONE);
        for (i, case) in cases(&DV_TORSION_SWEEP, 96) {
            let (key, sig, msg) = decode_verify(&case);
            let a = decode(&key).expect("the key decodes");
            let t = torsion_component(&a, &inv8);
            assert!(EIGHT_TORSION.contains(&t), "case {i}");
            let k = k_of(&sig[..32], &key, &msg);
            let (accepts, forms_differ) = verdicts(&t, &k);
            assert_eq!(case.intents[0] == Intent::Accept, accepts, "case {i}");
            assert_eq!(case.tags.has(Tag::FormsDiffer), forms_differ, "case {i}");
        }
        // DV-torsionSweep draws T uniformly among the eight, and its
        // challenge is uniform mod 8, so its shares are those of the 64
        // pairs (T, k mod 8) under the outcome the generator computes,
        // which DV-torsion's cases above hold to full multiplications for
        // every pair: 20 accept and the two forms differ on 24, within the
        // class's bands.  Any nonzero k ≡ r (mod 8) negates to
        // L − k ≡ 5 − r, so r + 8 stands for them all; k = 0 alone would
        // negate to 0.
        let (mut accepted, mut differ) = (0u32, 0u32);
        for t in &EIGHT_TORSION {
            for r in 0..8u8 {
                let (intent, tags) = torsion_outcome(t, &Scalar::from(r + 8));
                accepted += u32::from(intent == Intent::Accept);
                differ += u32::from(tags.has(Tag::FormsDiffer));
            }
        }
        assert_eq!((accepted, differ), (20, 24));
        let share = |n: u32| f64::from(n) / 64.0;
        for mix in DV_TORSION_SWEEP.mix {
            let (lo, hi, want) = match *mix {
                Mix::AcceptRate { lo, hi, .. } => (lo, hi, share(accepted)),
                Mix::TagRate {
                    tag: Tag::FormsDiffer,
                    lo,
                    hi,
                    ..
                } => (lo, hi, share(differ)),
                other => panic!("{other:?}"),
            };
            assert!((lo..=hi).contains(&want), "{mix:?}: {want}");
        }

        let mut strata_accepting = BTreeSet::new();
        for (i, case) in cases(&DV_TORSION_NONCANON, 48) {
            let (key, sig, msg) = decode_verify(&case);
            let parsed = model::parse_pub_key(&key).expect("the key parses");
            assert_ne!(parsed.canonical, key, "case {i}: a non-canonical key");
            assert!(parsed.point.is_small_order(), "case {i}");
            let s = Scalar::from_canonical_bytes(sig[32..].try_into().expect("S"))
                .into_option()
                .expect("S below L");
            assert_eq!(
                encode(&EdwardsPoint::mul_base(&s)),
                sig[..32],
                "case {i}: S = r"
            );
            let k = k_of(&sig[..32], &parsed.canonical, &msg);
            assert_eq!(
                usize::from(residue(&k)),
                stratum(i, 8),
                "case {i}: the residue"
            );
            let (accepts, _) = verdicts(&parsed.point, &k);
            assert_eq!(case.intents[0] == Intent::Accept, accepts, "case {i}");
            if accepts {
                strata_accepting.insert(stratum(i, 24));
            }
        }
        assert_eq!(strata_accepting.len(), 12, "12 of the 24 strata accept");

        // A verifier that refuses a y at or above p but then compares R as
        // a decoded point accepts every case whose R, its point right, has
        // a reduced y: beside the canonical strata, exactly the 15 signed
        // ones, where dcrd's byte comparison rejects.
        let mut decoded_point_accepts = BTreeSet::new();
        for (i, case) in cases(&DV_ZERO_S_SMALL_R, 172) {
            let (key, sig, msg) = decode_verify(&case);
            assert_eq!(sig[32..], [0; 32], "case {i}: S = 0");
            let t = decode(&key).expect("the key decodes");
            assert!(t.is_small_order(), "case {i}");
            let r_bytes: [u8; 32] = sig[..32].try_into().expect("R");
            let r = decode(&r_bytes).expect("R decodes");
            assert!(r.is_small_order(), "case {i}");
            let k = k_of(&r_bytes, &key, &msg);
            assert_eq!(-(k * t), r, "case {i}: -k·T is R's point");
            let canonical = encode(&r) == r_bytes;
            assert_eq!(
                case.variant.starts_with("canonical/"),
                canonical,
                "case {i}"
            );
            assert_eq!(case.intents[0] == Intent::Accept, canonical, "case {i}");
            let mut y = r_bytes;
            y[31] &= 0x7f;
            let reduced = arith::cmp_le(&y, &ED25519_P) == Ordering::Less;
            let signed = r_bytes[31] & 0x80 != 0 && x_is_zero(&r);
            let form = case.variant.rsplit('/').next().expect("a label");
            if !canonical {
                assert_eq!(!reduced, form.starts_with("y+p"), "case {i}: {form}");
                assert_eq!(signed, form.ends_with("x0-signed"), "case {i}: {form}");
                if reduced {
                    decoded_point_accepts.insert(case.variant.into_owned());
                }
            }
        }
        assert_eq!(decoded_point_accepts.len(), 15);
        assert!(
            decoded_point_accepts
                .iter()
                .all(|v| v.ends_with("/T0/x0-signed") || v.ends_with("/T4/x0-signed")),
            "{decoded_point_accepts:?}"
        );
    }

    /// The parse-edge and malleation classes reach their edges: DG-edges'
    /// R kinds and S values, DV-SplusL's S at or above L whose S − L is an
    /// honest signature, and DV-topBits' S with a top bit set, in its last
    /// stratum an honest S plus j·L.
    #[test]
    fn edge_classes_reach_their_edges() {
        for (i, case) in cases(&DG_EDGES, 64) {
            let sig = &case.requests[0].data;
            let r: [u8; 32] = sig[..32].try_into().expect("R");
            let s: [u8; 32] = sig[32..].try_into().expect("S");
            let mut y = r;
            y[31] &= 0x7f;
            let ctx = format!("case {i} ({})", case.variant);
            match stratum(i, 4) {
                0 => assert_eq!(decode(&r).map(|p| encode(&p)), Some(r), "{ctx}"),
                1 => {
                    assert_ne!(arith::cmp_le(&y, &ED25519_P), Ordering::Less, "{ctx}");
                    assert!(decode(&r).is_some(), "{ctx}");
                }
                2 => {
                    assert_eq!(r[31] & 0x80, 0x80, "{ctx}: the sign bit");
                    assert!(decode(&r).is_some_and(|p| x_is_zero(&p)), "{ctx}");
                }
                _ => {
                    assert_eq!(arith::cmp_le(&y, &ED25519_P), Ordering::Less, "{ctx}");
                    assert!(decode(&r).is_none(), "{ctx}");
                }
            }
            assert_eq!(s, s_value(digit(i, 4, 8)), "{ctx}");
        }
        assert_eq!(arith::cmp_le(&s_value(5), &ED25519_L), Ordering::Greater);
        for (i, case) in cases(&DV_S_PLUS_L, 32) {
            let (key, sig, msg) = decode_verify(&case);
            let s: [u8; 32] = sig[32..].try_into().expect("S");
            assert_ne!(arith::cmp_le(&s, &ED25519_L), Ordering::Less, "case {i}");
            assert_eq!(s[31] & 0xe0, 0, "case {i}");
            let (reduced, _) = arith::sub_le(&s, &ED25519_L);
            assert!(
                bool::from(Scalar::from_canonical_bytes(reduced).is_some()),
                "case {i}"
            );
            let honest = signature(sig[..32].try_into().expect("R"), &reduced);
            let key = model::parse_pub_key(&key).expect("a valid key");
            assert_eq!(model::verify(&key, &msg, &honest), Ok(()), "case {i}");
        }
        for (i, case) in cases(&DV_TOP_BITS, 40) {
            let (key, sig, msg) = decode_verify(&case);
            let s: [u8; 32] = sig[32..].try_into().expect("S");
            assert_ne!(s[31] & 0xe0, 0, "case {i}: a top bit");
            if stratum(i, 5) != 4 {
                continue;
            }
            // S is S mod L plus j·L for a j in 2..=14, and S mod L signs.
            let reduced = Scalar::from_bytes_mod_order(s).to_bytes();
            let j = (1..=14)
                .scan(reduced, |m, j| {
                    *m = arith::add_le(m, &ED25519_L).0;
                    Some((j, *m))
                })
                .find(|(_, m)| *m == s)
                .map(|(j, _)| j);
            assert!(j.is_some_and(|j| j >= 2), "case {i}: S = S mod L + {j:?}·L");
            let honest = signature(sig[..32].try_into().expect("R"), &reduced);
            let key = model::parse_pub_key(&key).expect("a valid key");
            assert_eq!(model::verify(&key, &msg, &honest), Ok(()), "case {i}");
        }
    }

    /// Each class's per-PR cases cover every stratum it takes from the
    /// index, and send its command.
    #[test]
    fn per_pr_counts_cover_every_variant() {
        for (class, labels) in [
            (&DS_RANDOM, 7),
            (&DK_CANONICAL, 1),
            (&DK_SMALL, 114),
            (&DK_LENGTH, 3),
            (&DG_EDGES, 32),
            (&DV_HONEST, 7),
            (&DV_TAMPER, 4),
            (&DV_S_PLUS_L, 1),
            (&DV_TOP_BITS, 5),
            (&DV_RANDOM, 1),
            (&DV_TORSION, 128),
            (&DV_TORSION_NONCANON, 24),
            (&DV_ZERO_S_SMALL_R, 86),
        ] {
            let mut variants = BTreeSet::new();
            for (_, case) in cases(class, class.pr_cases) {
                assert_eq!(case.requests.len(), 1);
                assert!(class.commands.contains(&case.requests[0].cmd));
                variants.insert(case.variant.into_owned());
            }
            assert_eq!(variants.len(), labels, "{}: {variants:?}", class.name);
        }
        // The drawn labels stay within the ones the generators have.
        for (class, most) in [(&DK_RANDOM, 5), (&DG_RANDOM, 3), (&DV_TORSION_SWEEP, 16)] {
            let variants: BTreeSet<String> = cases(class, 256)
                .map(|(_, c)| c.variant.into_owned())
                .collect();
            assert!(variants.len() <= most, "{}: {variants:?}", class.name);
            assert!(variants.len() > 1, "{}: {variants:?}", class.name);
        }
    }

    /// The challenge and the honest signer follow the standard: the first
    /// row of dcrd's `TestGolden` data (`testdata/sign.input.gz`, from
    /// the Ed25519 reference's `sign.input`) satisfies S·B = R + k·A with
    /// the challenge as computed here, and a signature made the way the
    /// generators make one verifies in the model.
    #[test]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "curve25519-dalek scalar and point operations only: modular group arithmetic, no integer operator here"
    )]
    fn the_challenge_is_the_standards() {
        let b32 =
            |hex: &str| -> [u8; 32] { dcroxide_testutil::unhex(hex).try_into().expect("32 bytes") };
        let key = b32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let r = b32("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155");
        let s = b32("5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        let a = decode(&key).expect("the key");
        let k = challenge(&r, &key, &[]);
        let s = Scalar::from_canonical_bytes(s).into_option().expect("S");
        assert_eq!(
            encode(&(EdwardsPoint::mul_base(&s) - k * a)),
            r,
            "S·B - k·A = R"
        );

        let mut rng = dcroxide_testutil::SplitMix64(0x0515_79e5);
        let mut d = Draw::new(&mut rng);
        for _ in 0..8 {
            let msg = random_message(&mut d, 0, 64);
            let v = honest(&mut d, msg);
            let key = model::parse_pub_key(&v.key).expect("a valid key");
            assert_eq!(model::verify(&key, &v.msg, &v.sig), Ok(()));
        }
        assert!(!d.fell_back());
    }
}
