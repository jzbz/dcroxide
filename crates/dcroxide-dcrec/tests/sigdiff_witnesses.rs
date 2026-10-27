// SPDX-License-Identifier: ISC
//! The signature soak's witness vectors (`data/sigdiff_witness_vectors.txt`,
//! written by `dcroxide-sigdiff`'s `sigsoak emit-corpus`): for each class
//! built to reach a branch of dcrd's verification or recovery that only a
//! solved-for input reaches, the first case of each variant group and each
//! dcrd verdict, with dcrd's answer from `tools/oracle` at the parity pin.
//!
//! Each line's request is decoded in the oracle's layout and answered by
//! this crate, and the answer is held to dcrd's.  Each line must be the one
//! line of a (bucket, verdict) pair its class lists, a bucket being the
//! first `/`-separated component of the variant, so a lost or doubled line
//! fails.  Then the branch the class was built for is derived again with
//! `k256`, `curve25519-dalek`, SHA-512 and BLAKE-256, so a line that keeps
//! dcrd's verdict by another path fails as well, and a second test holds
//! each of those checks to a line off its branch.  Neither Go nor the
//! soak's crate is needed (that crate depends on this one); its
//! `witness_file_regenerates` test rebuilds the lines from its generators
//! and the oracle.
//!
//! This crate's `recover_compact` reports no error kind yet, so a recovery
//! line whose answer is dcrd's error is held to it as a rejection only.

// Byte offsets and big-endian carries over fixed lengths, and k256 and
// curve25519-dalek scalar and point arithmetic, which is modular.
#![allow(clippy::arithmetic_side_effects)]

use std::any::Any;
use std::collections::BTreeSet;

use curve25519_dalek::constants::{ED25519_BASEPOINT_COMPRESSED, EIGHT_TORSION};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar as Ed25519Scalar;
use curve25519_dalek::traits::IsIdentity;
use dcroxide_crypto::blake256;
use dcroxide_dcrec::edwards;
use dcroxide_dcrec::secp256k1::{FIELD_PRIME_BYTES, GROUP_ORDER_BYTES, PublicKey, ecdsa, schnorr};
use dcroxide_testutil::unhex;
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::group::Group;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::point::{AffineCoordinates, DecompressPoint};
use k256::elliptic_curve::subtle::Choice;
use k256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};
use sha2::{Digest, Sha512};

/// The four ECDSA verify presentations, each with one verdict.
const fn presentations(accepts: bool) -> [(&'static str, bool); 4] {
    [
        ("raw-compressed", accepts),
        ("raw-uncompressed", accepts),
        ("raw-hybrid", accepts),
        ("der-compressed", accepts),
    ]
}

/// Every class the file covers and the (bucket, dcrd accepts) pair of each
/// of its lines, as `dcroxide-sigdiff`'s `WITNESS_CLASSES` lists them:
/// dcrd accepts with a `true` verdict or a recovered key.
static WITNESS_CLASSES: [(&str, &[(&str, bool)]); 13] = [
    ("EV-xGEN-true", &presentations(true)),
    (
        "EV-xGEN-false",
        &[("s+1", false), ("hash", false), ("unrelated", false)],
    ),
    ("EV-xGEN-wrap", &presentations(false)),
    ("EV-infinity", &presentations(false)),
    ("EV-double", &presentations(true)),
    (
        "ER-overflowValid",
        &[("29", true), ("30", true), ("33", true), ("34", true)],
    ),
    (
        "ER-infinity",
        &[("uncompressed", false), ("compressed", false)],
    ),
    ("ER-double", &[("uncompressed", true), ("compressed", true)]),
    ("SV-rGEN-true", &[("r>=N", true)]),
    (
        "SV-unequalR",
        &[("random", false), ("xminusN", false), ("xplusN", false)],
    ),
    ("SV-double", &[("doubled", true)]),
    (
        "DV-torsionNoncanon",
        &[
            ("identity-p1", true),
            ("order4-p-s0", true),
            ("order4-p-s0", false),
            ("order4-p-s1", true),
            ("order4-p-s1", false),
        ],
    ),
    (
        "DV-zeroS-smallR",
        &[("canonical", true), ("noncanonical", false)],
    ),
];

/// N, the secp256k1 group order.
const N: [u8; 32] = GROUP_ORDER_BYTES;

/// P, the secp256k1 field prime.
const P: [u8; 32] = FIELD_PRIME_BYTES;

/// An answer, as a line records dcrd's and as this crate gives it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Answer {
    /// A verify command's verdict.
    Verdict(bool),
    /// A recovered key, serialized as its compressed flag says, and the
    /// flag.
    Recovered(Vec<u8>, bool),
    /// A rejection with one of dcrd's error kinds.
    Kind(String),
    /// A rejection with no kind: this crate's recovery errors, and an
    /// Ed25519 key error.
    Unnamed,
}

/// A line's answer field: `true`, `false`, `ok:<hex>:<flag>` or
/// `err:<kind>`.
fn recorded(text: &str) -> Answer {
    match text {
        "true" => Answer::Verdict(true),
        "false" => Answer::Verdict(false),
        _ => {
            if let Some(rest) = text.strip_prefix("ok:") {
                let (key, flag) = rest.split_once(':').expect("ok:<hex>:<flag>");
                Answer::Recovered(unhex(key), flag.parse().expect("a flag"))
            } else if let Some(kind) = text.strip_prefix("err:") {
                Answer::Kind(kind.to_owned())
            } else {
                panic!("answer {text:?}")
            }
        }
    }
}

/// Whether dcrd accepts: a `true` verdict or a recovered key.
fn accepts(answer: &Answer) -> bool {
    matches!(answer, Answer::Verdict(true) | Answer::Recovered(..))
}

/// A variant's bucket: its first `/`-separated component.
fn bucket(variant: &str) -> &str {
    variant.split('/').next().unwrap_or(variant)
}

/// A vector line of the file.
struct Line {
    /// The line as written.
    text: &'static str,
    class: &'static str,
    variant: &'static str,
    index: u64,
    cmd: &'static str,
    /// The request data, as the oracle received it.
    request: Vec<u8>,
    /// dcrd's answer.
    want: Answer,
}

/// The file's vector lines: every line that is neither empty nor a `#`
/// comment.
fn vector_lines() -> Vec<Line> {
    include_str!("data/sigdiff_witness_vectors.txt")
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|text| {
            let f: Vec<&str> = text.split('|').collect();
            let [class, variant, index, cmd, request, want] = f[..] else {
                panic!("{text}: not six fields");
            };
            Line {
                text,
                class,
                variant,
                index: index.parse().expect("a case index"),
                cmd,
                request: unhex(request),
                want: recorded(want),
            }
        })
        .collect()
}

/// An ECDSA verify request's key, hash and signature, decoded as
/// `tools/oracle` decodes them: `ecdsa_verify` is the 33-byte key ‖ hash ‖
/// DER, `ecdsa_verify_raw` is key_len ‖ key ‖ hash ‖ r ‖ s, whose range
/// errors the oracle names r first.  Or the kind dcrd rejects with.
fn ecdsa_inputs(cmd: &str, data: &[u8]) -> Result<(PublicKey, [u8; 32], ecdsa::Signature), String> {
    let (key, rest) = if cmd == "ecdsa_verify" {
        data.split_at(33)
    } else {
        let len = usize::from(data[0]);
        assert_eq!(data.len(), 1 + len + 96, "{cmd} layout");
        data[1..].split_at(len)
    };
    let (hash, sig) = rest.split_at(32);
    let key = PublicKey::parse(key).map_err(|e| e.kind_name().to_owned())?;
    let sig = if cmd == "ecdsa_verify" {
        ecdsa::parse_der_signature(sig).map_err(|e| e.kind_name().to_owned())?
    } else {
        let r: [u8; 32] = sig[..32].try_into().expect("32 bytes");
        let s: [u8; 32] = sig[32..].try_into().expect("32 bytes");
        ecdsa::Signature::new(r, s).ok_or_else(|| {
            if r >= N {
                "ErrSigRTooBig".to_owned()
            } else {
                "ErrSigSTooBig".to_owned()
            }
        })?
    };
    Ok((key, hash.try_into().expect("32 bytes"), sig))
}

/// This crate's answer to `cmd` with request bytes `data`, decoded in the
/// oracle's layout and called as the oracle calls dcrd.
fn answer(cmd: &str, data: &[u8]) -> Answer {
    match cmd {
        "ecdsa_verify" | "ecdsa_verify_raw" => match ecdsa_inputs(cmd, data) {
            Ok((key, hash, sig)) => Answer::Verdict(sig.verify(&hash, &key)),
            Err(kind) => Answer::Kind(kind),
        },
        "ecdsa_recover_compact" => {
            let (hash, sig) = data.split_at(32);
            match ecdsa::recover_compact(sig, hash.try_into().expect("32 bytes")) {
                Ok((key, true)) => Answer::Recovered(key.serialize_compressed().to_vec(), true),
                Ok((key, false)) => Answer::Recovered(key.serialize_uncompressed().to_vec(), false),
                Err(()) => Answer::Unnamed,
            }
        }
        "schnorr_verify" => {
            assert_eq!(data.len(), 33 + 32 + 64, "{cmd} layout");
            let key = match PublicKey::parse(&data[..33]) {
                Ok(key) => key,
                Err(e) => return Answer::Kind(e.kind_name().to_owned()),
            };
            match schnorr::parse_signature(&data[65..]) {
                Ok(sig) => Answer::Verdict(sig.verify(&data[33..65], &key)),
                Err(e) => Answer::Kind(e.kind_name().to_owned()),
            }
        }
        "ed25519_verify" => {
            let Ok(key) = edwards::parse_pub_key(&data[..32]) else {
                return Answer::Unnamed;
            };
            let sig: &[u8; 64] = data[32..96].try_into().expect("64 bytes");
            Answer::Verdict(edwards::verify_raw(&key, &data[96..], sig))
        }
        other => panic!("no command {other} in the witness file"),
    }
}

/// a + b, big-endian, and whether it carried out of 256 bits.
fn add(a: &[u8; 32], b: &[u8; 32]) -> ([u8; 32], bool) {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let sum = u16::from(a[i]) + u16::from(b[i]) + carry;
        out[i] = sum as u8;
        carry = sum >> 8;
    }
    (out, carry != 0)
}

/// a − b, big-endian, and whether it borrowed.
fn sub(a: &[u8; 32], b: &[u8; 32]) -> ([u8; 32], bool) {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut diff = i16::from(a[i]) - i16::from(b[i]) - borrow;
        borrow = i16::from(diff < 0);
        if diff < 0 {
            diff += 256;
        }
        out[i] = diff as u8;
    }
    (out, borrow != 0)
}

/// P − N.
fn p_minus_n() -> [u8; 32] {
    sub(&P, &N).0
}

/// Whether a signature component lies in [1, N − 1], so that neither
/// verification's step 1 nor recovery's range checks decide the line.
fn in_range(v: &[u8; 32]) -> bool {
    *v != [0; 32] && *v < N
}

/// `bytes` as a scalar; they are below N.
fn scalar(bytes: &[u8; 32]) -> Scalar {
    Option::from(Scalar::from_repr((*bytes).into())).expect("a value below N")
}

/// `bytes` mod N, as dcrd reduces a hash.
fn reduce(bytes: &[u8; 32]) -> Scalar {
    <Scalar as Reduce<FieldBytes>>::reduce(&(*bytes).into())
}

/// The inverse of a nonzero scalar.
fn invert(s: &Scalar) -> Scalar {
    Option::from(s.invert()).expect("a nonzero scalar")
}

/// A parsed key's point.
fn point(key: &PublicKey) -> ProjectivePoint {
    let u = key.serialize_uncompressed();
    let x: [u8; 32] = u[1..33].try_into().expect("32 bytes");
    let y: [u8; 32] = u[33..].try_into().expect("32 bytes");
    let p: AffinePoint = Option::from(AffinePoint::from_coordinates(&x.into(), &y.into()))
        .expect("a parsed key is on the curve");
    p.into()
}

/// A finite point's x coordinate, big-endian.
fn x_of(p: &ProjectivePoint) -> [u8; 32] {
    assert!(!bool::from(p.is_identity()), "a finite point");
    p.to_affine().x().into()
}

/// The point with x coordinate `x` and a y of parity `odd`.
fn decompress(x: &[u8; 32], odd: bool) -> ProjectivePoint {
    let p: AffinePoint = Option::from(AffinePoint::decompress(
        &(*x).into(),
        Choice::from(u8::from(odd)),
    ))
    .expect("an x coordinate");
    p.into()
}

/// An ECDSA verify request's two summands, u1·G and u2·Q with e the hash
/// mod N, w = s⁻¹, u1 = e·w and u2 = r·w, and r, for a key, hash and s
/// given in place of the request's.
fn ecdsa_summands(
    q: &ProjectivePoint,
    hash: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
) -> (ProjectivePoint, ProjectivePoint) {
    let w = invert(&scalar(s));
    (
        ProjectivePoint::GENERATOR * (reduce(hash) * w),
        *q * (scalar(r) * w),
    )
}

/// The branch an EV line was built for: X = u1·G + u2·Q against r.
fn ecdsa_branch(class: &str, variant: &str, cmd: &str, data: &[u8]) {
    let (key, hash, sig) = ecdsa_inputs(cmd, data).expect("the key and signature parse");
    let (q, r, s) = (point(&key), *sig.r_bytes(), *sig.s_bytes());
    assert!(in_range(&r) && in_range(&s), "r and s in [1, N - 1]");
    let (u1g, u2q) = ecdsa_summands(&q, &hash, &r, &s);
    let big_x = u1g + u2q;
    let (r_plus_n, carried) = add(&r, &N);
    match class {
        "EV-xGEN-true" => {
            assert!(r < p_minus_n() && !carried, "r < P - N");
            assert_eq!(x_of(&big_x), r_plus_n, "X.x = r + N");
        }
        "EV-xGEN-false" => {
            assert!(r < p_minus_n() && !carried, "r < P - N");
            let x = x_of(&big_x);
            assert!(x != r && x != r_plus_n, "X.x is neither r nor r + N");
            match bucket(variant) {
                "s+1" => {
                    // The EV-xGEN-true case it was made from.
                    let s_minus_1: [u8; 32] = (scalar(&s) - Scalar::ONE).to_repr().into();
                    let (u1g, u2q) = ecdsa_summands(&q, &hash, &r, &s_minus_1);
                    assert_eq!(x_of(&(u1g + u2q)), r_plus_n, "s - 1 gives X.x = r + N");
                }
                // The line records no flipped hash bit, and an unrelated
                // key comes from no case.
                "hash" | "unrelated" => {}
                other => panic!("{class}: bucket {other}"),
            }
        }
        "EV-xGEN-wrap" => {
            assert!(p_minus_n() <= r && r < N, "P - N <= r < N");
            assert_eq!(x_of(&big_x), sub(&r, &p_minus_n()).0, "X.x = r + N - P");
        }
        "EV-infinity" => assert!(bool::from(big_x.is_identity()), "X = O"),
        "EV-double" => {
            assert_eq!(u1g, u2q, "u1·G = u2·Q");
            assert_eq!(x_of(&big_x), r, "X.x = r");
        }
        _ => unreachable!("{class}"),
    }
}

/// The branch an ER line was built for, from the compact signature's
/// header, r and s, and the point X its header names for r.
fn recover_branch(class: &str, data: &[u8]) {
    let (hash, sig) = data.split_at(32);
    let hash: [u8; 32] = hash.try_into().expect("32 bytes");
    assert_eq!(sig.len(), 65, "a compact signature");
    let code = sig[0]
        .checked_sub(27)
        .filter(|c| *c < 8)
        .expect("a header in 27..=34");
    let (overflow, odd) = (code & 2 != 0, code & 1 != 0);
    let r: [u8; 32] = sig[1..33].try_into().expect("32 bytes");
    let s: [u8; 32] = sig[33..].try_into().expect("32 bytes");
    assert!(in_range(&r) && in_range(&s), "r and s in [1, N - 1]");
    let x = if overflow {
        let (x, carried) = add(&r, &N);
        assert!(!carried, "r + N below 2^256");
        x
    } else {
        r
    };
    match class {
        "ER-overflowValid" => {
            assert!(overflow, "the header's overflow bit is set");
            assert!(r < p_minus_n(), "r < P - N");
        }
        "ER-infinity" => {
            // Q = r⁻¹·(s·X − e·G) is the point at infinity.
            let big_x = decompress(&x, odd);
            assert_eq!(
                big_x * scalar(&s),
                ProjectivePoint::GENERATOR * reduce(&hash),
                "s·X = e·G"
            );
        }
        "ER-double" => {
            let big_x = decompress(&x, odd);
            let w = invert(&scalar(&r));
            let u1 = -(reduce(&hash) * w);
            let u2 = scalar(&s) * w;
            assert_eq!(ProjectivePoint::GENERATOR * u1, big_x * u2, "u1·G = u2·X");
        }
        _ => unreachable!("{class}"),
    }
}

/// R's x coordinate, once R is finite and its y even: neither of dcrd's
/// steps 8 and 9 decides the line, and step 10 compares R.x with r.
fn step_10_x(big_r: &ProjectivePoint) -> [u8; 32] {
    assert!(!bool::from(big_r.is_identity()), "R is finite");
    let big_r = big_r.to_affine();
    assert!(!bool::from(big_r.y_is_odd()), "R.y is even");
    big_r.x().into()
}

/// The branch an SV line was built for: R = s·G + e·Q with e =
/// BLAKE-256(r ‖ hash), against r.
fn schnorr_branch(class: &str, variant: &str, data: &[u8]) {
    let q = point(&PublicKey::parse(&data[..33]).expect("the key parses"));
    let hash = &data[33..65];
    let r: [u8; 32] = data[65..97].try_into().expect("32 bytes");
    // dcrd's signature parse refuses an r at or above P before any step of
    // verification runs.
    assert!(r < P, "r < P");
    let s = scalar(&data[97..].try_into().expect("32 bytes"));
    let e = scalar(&blake256::sum256(&[&r[..], hash].concat()));
    let (sg, eq) = (ProjectivePoint::GENERATOR * s, q * e);
    match class {
        "SV-rGEN-true" => {
            assert!(r >= N, "r >= N");
            assert_eq!(step_10_x(&(sg + eq)), r, "R.x = r");
        }
        "SV-unequalR" => {
            let x = step_10_x(&(sg + eq));
            assert_ne!(x, r, "R.x != r");
            match bucket(variant) {
                "random" => {}
                "xminusN" => {
                    let (sum, carried) = add(&r, &N);
                    assert!(!carried && x == sum, "R.x = r + N");
                }
                "xplusN" => {
                    let (diff, borrowed) = sub(&r, &N);
                    assert!(!borrowed && x == diff, "R.x = r - N");
                }
                other => panic!("{class}: bucket {other}"),
            }
        }
        "SV-double" => assert_eq!(sg, eq, "s·G = e·Q"),
        _ => unreachable!("{class}"),
    }
}

/// The branch a DV line was built for, on the key and R ‖ S as given:
/// agl's s·B − k·A against R's bytes, with k = SHA-512(R ‖ A ‖ M) mod L
/// over the parsed key's canonical encoding A.
fn ed25519_branch(class: &str, data: &[u8], accepts: bool) {
    let decode = |bytes: &[u8]| {
        CompressedEdwardsY(bytes.try_into().expect("32 bytes"))
            .decompress()
            .expect("a point")
    };
    let canonical = edwards::parse_pub_key(&data[..32])
        .expect("the key parses")
        .serialize();
    let key = decode(&canonical);
    let (r, s) = (&data[32..64], &data[64..96]);
    let mut h = Sha512::new();
    h.update(r);
    h.update(canonical);
    h.update(&data[96..]);
    let k = Ed25519Scalar::from_bytes_mod_order_wide(&h.finalize().into());
    match class {
        "DV-torsionNoncanon" => {
            assert_ne!(canonical[..], data[..32], "the key is not canonical");
            assert!(key.is_small_order(), "the key is small-order");
            assert_eq!(s[31] & 0xe0, 0, "S's top three bits are clear");
            let s = Ed25519Scalar::from_bytes_mod_order(s.try_into().expect("32 bytes"));
            assert_eq!(
                EdwardsPoint::mul_base(&s).compress().as_bytes()[..],
                r[..],
                "R is S·B"
            );
            assert_eq!(
                (k * key).is_identity(),
                accepts,
                "accepted exactly when k·A is the identity"
            );
        }
        "DV-zeroS-smallR" => {
            assert_eq!(s, [0; 32], "S is zero");
            let big_r = decode(r);
            assert!(big_r.is_small_order(), "R is small-order");
            // With S = 0 verify computes −k·A, R's point, so only R's
            // encoding decides.
            assert_eq!(-(k * key), big_r, "-k·A is R's point");
            assert_eq!(
                big_r.compress().as_bytes()[..] == r[..],
                accepts,
                "R is canonical exactly when accepted"
            );
        }
        _ => unreachable!("{class}"),
    }
}

/// The branch a line's class was built for, derived again.
fn branch(class: &str, variant: &str, cmd: &str, data: &[u8], accepts: bool) {
    match class.split('-').next() {
        Some("EV") => ecdsa_branch(class, variant, cmd, data),
        Some("ER") => recover_branch(class, data),
        Some("SV") => schnorr_branch(class, variant, data),
        Some("DV") => ed25519_branch(class, data, accepts),
        _ => unreachable!("{class}"),
    }
}

#[test]
fn sigdiff_witness_vectors() {
    let lines = vector_lines();
    let mut seen = BTreeSet::new();
    for line in &lines {
        let text = line.text;
        let (_, pairs) = WITNESS_CLASSES
            .iter()
            .find(|(class, _)| *class == line.class)
            .unwrap_or_else(|| panic!("{text}: class {}", line.class));

        let got = answer(line.cmd, &line.request);
        match (&got, &line.want) {
            // Until recovery names dcrd's kinds, any rejection matches one.
            (Answer::Unnamed, Answer::Kind(_)) if line.cmd == "ecdsa_recover_compact" => {}
            _ => assert_eq!(got, line.want, "{text}"),
        }

        let pair = (bucket(line.variant), accepts(&line.want));
        assert!(
            pairs.contains(&pair),
            "{text}: {pair:?} is no line of its class"
        );
        assert!(
            seen.insert((line.class, pair)),
            "{text}: a second line for {pair:?}"
        );
        branch(line.class, line.variant, line.cmd, &line.request, pair.1);
    }
    let missing: Vec<String> = WITNESS_CLASSES
        .iter()
        .flat_map(|&(class, pairs)| pairs.iter().map(move |&pair| (class, pair)))
        .filter(|key| !seen.contains(key))
        .map(|(class, (bucket, accepts))| format!("{class} {bucket} {accepts}"))
        .collect();
    assert!(missing.is_empty(), "no line for {missing:?}");
    assert_eq!(lines.len(), 39, "one line for each listed pair");
    println!(
        "{} witness lines over {} classes",
        lines.len(),
        WITNESS_CLASSES.len()
    );
}

/// What a failed check says: an `assert!`'s or a `panic!`'s message, or
/// the message of an `assert_eq!` or `assert_ne!` without its values.
fn check_failed(payload: &(dyn Any + Send)) -> String {
    let text = payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .expect("a panic message");
    let first = text.lines().next().unwrap_or_default();
    first
        .strip_prefix("assertion `left == right` failed: ")
        .or_else(|| first.strip_prefix("assertion `left != right` failed: "))
        .unwrap_or(first)
        .to_owned()
}

/// A line run through a class's checks as if it were one of the class's
/// own, and the check that must refuse it.
struct Probe {
    what: &'static str,
    class: &'static str,
    variant: &'static str,
    cmd: &'static str,
    request: Vec<u8>,
    accepts: bool,
    refused_by: &'static str,
}

impl Line {
    /// This line, with its variant and verdict, checked as `class`.
    fn probe(&self, what: &'static str, class: &'static str, refused_by: &'static str) -> Probe {
        Probe {
            what,
            class,
            variant: self.variant,
            cmd: self.cmd,
            request: self.request.clone(),
            accepts: accepts(&self.want),
            refused_by,
        }
    }
}

impl Probe {
    /// With the variant `variant`.
    fn labelled(self, variant: &'static str) -> Probe {
        Probe { variant, ..self }
    }

    /// With the request bytes from `at` replaced by `bytes`.
    fn with(mut self, at: usize, bytes: &[u8]) -> Probe {
        self.request[at..at + bytes.len()].copy_from_slice(bytes);
        self
    }

    /// With the other verdict.
    fn flipped(self) -> Probe {
        Probe {
            accepts: !self.accepts,
            ..self
        }
    }
}

/// A finite point's compressed encoding.
fn compressed(p: &ProjectivePoint) -> [u8; 33] {
    let p = p.to_affine();
    let mut out = [0u8; 33];
    out[0] = 2 | u8::from(bool::from(p.y_is_odd()));
    out[1..].copy_from_slice(&p.x());
    out
}

/// Each branch check refuses, with its own message, a line that is off
/// its branch: a line of another class, one given another variant or
/// verdict, or one with bytes changed.  Every line of the file passes
/// every check, so the file alone would not show that a check holds
/// anything.
#[test]
fn each_branch_check_refuses_a_line_off_its_branch() {
    let lines = vector_lines();
    let line = |class: &str, index: u64| {
        lines
            .iter()
            .find(|l| l.class == class && l.index == index)
            .unwrap_or_else(|| panic!("no line {class} {index}"))
    };
    // The raw-compressed ECDSA layout (33 ‖ key ‖ hash ‖ r ‖ s), the
    // compact recovery one (hash ‖ header ‖ r ‖ s), the Schnorr one (key ‖
    // hash ‖ r ‖ s) and the Ed25519 one (key ‖ R ‖ S ‖ message).
    let (ev_key, ev_hash, ev_r) = (1, 34, 66);
    let (er_r, er_s) = (33, 65);
    let (sv_hash, sv_r, sv_s) = (33, 65, 97);
    let (dv_r, dv_s) = (32, 64);

    // A doubling whose r is not X.x: r + 1 with Q = (e/(r + 1))·G keeps
    // u2·Q = u1·G.
    let double = line("EV-double", 0);
    let mut one = [0u8; 32];
    one[31] = 1;
    let r1 = add(
        double.request[ev_r..ev_r + 32]
            .try_into()
            .expect("32 bytes"),
        &one,
    )
    .0;
    let hash: [u8; 32] = double.request[ev_hash..ev_hash + 32]
        .try_into()
        .expect("32 bytes");
    let q = ProjectivePoint::GENERATOR * (reduce(&hash) * invert(&scalar(&r1)));
    // The SV-double key negated: s·G − e·Q is the point at infinity.
    let sv_double = line("SV-double", 0);
    let negated = [sv_double.request[0] ^ 1];
    // SV-unequalR line 0 with the r given and R = G: Q = G and s = 1 − e
    // for that r and the line's hash.  Against R.x = G.x, r + N and r − N
    // are each tried without a carry or borrow (r = 1, r = N) and with one
    // (r = G.x + (2^256 − N) and r = G.x − (2^256 − N), which r + N and
    // r − N take back to G.x).
    let unequal = line("SV-unequalR", 0);
    let generator = compressed(&ProjectivePoint::GENERATOR);
    let at_g =
        |what: &'static str, variant: &'static str, refused_by: &'static str, r: [u8; 32]| {
            let e = scalar(&blake256::sum256(
                &[&r[..], &unequal.request[sv_hash..sv_r]].concat(),
            ));
            let s: [u8; 32] = (Scalar::ONE - e).to_repr().into();
            unequal
                .probe(what, "SV-unequalR", refused_by)
                .labelled(variant)
                .with(0, &generator)
                .with(sv_r, &r)
                .with(sv_s, &s)
        };
    let gx = x_of(&ProjectivePoint::GENERATOR);
    let n_to_2_256 = sub(&[0; 32], &N).0;
    // 2^256 − 3: an r at or above P with which SV-unequalR line 0 passes
    // every other check, and which dcrd refuses as ErrSigRTooBig.
    let mut past_p = [0xff; 32];
    past_p[31] = 0xfd;
    let wrap = line("EV-xGEN-wrap", 0);
    let hash_bit = [wrap.request[ev_hash + 5] ^ 1];
    let torsion = line("DV-torsionNoncanon", 8);
    let top_bit = [torsion.request[dv_s + 31] | 0x20];

    let probes = [
        line("EV-xGEN-false", 0).probe("an s+1 case", "EV-xGEN-true", "X.x = r + N"),
        line("EV-xGEN-wrap", 0).probe("a wrapping r", "EV-xGEN-true", "r < P - N"),
        line("EV-xGEN-true", 0)
            .probe(
                "an r + N case",
                "EV-xGEN-false",
                "X.x is neither r nor r + N",
            )
            .labelled("unrelated/raw-compressed"),
        line("EV-xGEN-wrap", 0).probe("a wrapping r", "EV-xGEN-false", "r < P - N"),
        line("EV-xGEN-false", 1)
            .probe("a hash case", "EV-xGEN-false", "s - 1 gives X.x = r + N")
            .labelled("s+1/raw-compressed"),
        line("EV-xGEN-false", 2)
            .probe(
                "an unknown bucket",
                "EV-xGEN-false",
                "EV-xGEN-false: bucket other",
            )
            .labelled("other/raw-compressed"),
        line("EV-xGEN-false", 0)
            .probe("r = 0", "EV-xGEN-false", "r and s in [1, N - 1]")
            .with(ev_r, &[0; 32]),
        line("EV-xGEN-true", 0).probe("an r + N case", "EV-xGEN-wrap", "P - N <= r < N"),
        wrap.probe("a hash bit flipped", "EV-xGEN-wrap", "X.x = r + N - P")
            .with(ev_hash + 5, &hash_bit),
        line("EV-xGEN-true", 0).probe("an r + N case", "EV-infinity", "X = O"),
        line("EV-xGEN-true", 0).probe("an r + N case", "EV-double", "u1·G = u2·Q"),
        double
            .probe("a doubling with r + 1", "EV-double", "X.x = r")
            .with(ev_key, &compressed(&q))
            .with(ev_r, &r1),
        line("ER-double", 1).probe(
            "a doubling",
            "ER-overflowValid",
            "the header's overflow bit is set",
        ),
        line("ER-overflowValid", 0)
            .probe("r = P - N", "ER-overflowValid", "r < P - N")
            .with(er_r, &p_minus_n()),
        line("ER-infinity", 0)
            .probe(
                "s = 0 and a zero hash",
                "ER-infinity",
                "r and s in [1, N - 1]",
            )
            .with(0, &[0; 32])
            .with(er_s, &[0; 32]),
        line("ER-double", 0).probe("a doubling", "ER-infinity", "s·X = e·G"),
        line("ER-infinity", 0).probe("a sum at infinity", "ER-double", "u1·G = u2·X"),
        line("SV-unequalR", 1).probe("an xminusN case", "SV-rGEN-true", "r >= N"),
        line("SV-unequalR", 2).probe("an xplusN case", "SV-rGEN-true", "R.x = r"),
        unequal
            .probe("an r at or above P", "SV-unequalR", "r < P")
            .with(sv_r, &past_p),
        sv_double
            .probe("a doubling", "SV-unequalR", "R.x != r")
            .labelled("random"),
        sv_double
            .probe("a sum at infinity", "SV-unequalR", "R is finite")
            .labelled("random")
            .with(0, &negated),
        at_g("an r + N other than R.x", "xminusN", "R.x = r + N", one),
        at_g(
            "an r + N that carries to R.x",
            "xminusN",
            "R.x = r + N",
            add(&gx, &n_to_2_256).0,
        ),
        at_g("an r - N other than R.x", "xplusN", "R.x = r - N", N),
        at_g(
            "an r - N that borrows to R.x",
            "xplusN",
            "R.x = r - N",
            sub(&gx, &n_to_2_256).0,
        ),
        line("SV-unequalR", 0)
            .probe(
                "an unknown bucket",
                "SV-unequalR",
                "SV-unequalR: bucket other",
            )
            .labelled("other"),
        line("SV-rGEN-true", 0).probe("an r at or above N", "SV-double", "s·G = e·Q"),
        line("DV-zeroS-smallR", 0).probe(
            "a canonical key",
            "DV-torsionNoncanon",
            "the key is not canonical",
        ),
        torsion
            .probe(
                "S's top bit set",
                "DV-torsionNoncanon",
                "S's top three bits are clear",
            )
            .with(dv_s + 31, &top_bit),
        torsion
            .probe("another case's R", "DV-torsionNoncanon", "R is S·B")
            .with(dv_r, &line("DV-torsionNoncanon", 9).request[dv_r..dv_s]),
        line("DV-torsionNoncanon", 9)
            .probe(
                "the other verdict",
                "DV-torsionNoncanon",
                "accepted exactly when k·A is the identity",
            )
            .flipped(),
        line("DV-torsionNoncanon", 0).probe("a nonzero S", "DV-zeroS-smallR", "S is zero"),
        line("DV-zeroS-smallR", 0)
            .probe("R the base point", "DV-zeroS-smallR", "R is small-order")
            .with(dv_r, ED25519_BASEPOINT_COMPRESSED.as_bytes()),
        line("DV-zeroS-smallR", 0)
            .probe("R of order 2", "DV-zeroS-smallR", "-k·A is R's point")
            .with(dv_r, EIGHT_TORSION[4].compress().as_bytes()),
        line("DV-zeroS-smallR", 43)
            .probe(
                "the other verdict",
                "DV-zeroS-smallR",
                "R is canonical exactly when accepted",
            )
            .flipped(),
    ];
    for p in &probes {
        let refused = std::panic::catch_unwind(|| {
            branch(p.class, p.variant, p.cmd, &p.request, p.accepts);
        });
        let Err(payload) = refused else {
            panic!("{}: passed as {}", p.what, p.class);
        };
        assert_eq!(
            check_failed(&*payload),
            p.refused_by,
            "{} as {}",
            p.what,
            p.class
        );
    }
    println!("{} lines off their branches refused", probes.len());
}
