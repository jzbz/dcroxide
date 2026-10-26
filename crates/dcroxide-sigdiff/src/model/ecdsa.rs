// SPDX-License-Identifier: ISC
//! dcrd's ECDSA verification (`ecdsa/signature.go`, `Signature.Verify`) as
//! a model that names the step deciding each case, on this crate's own
//! `k256` arithmetic.
//!
//! dcrd's steps, which [`EcdsaBranch`] names:
//!
//! 1. fail if r or s is zero;
//! 2. e = hash mod N;
//! 3. w = s⁻¹;
//! 4. u1 = e·w, u2 = r·w;
//! 5. X = u1·G + u2·Q, with an addition that doubles when its two points
//!    are equal;
//! 6. fail if X is the point at infinity;
//! 7. (z = X.z², the projective form of the comparisons below);
//! 8. accept if r = X.x (as field elements: r·z² = X.x);
//! 9. fail if r ≥ P − N, where r + N would not fit below P;
//! 10. accept if r + N = X.x, else fail.
//!
//! The model computes X with `k256`'s complete projective addition and
//! compares its affine x with r and r + N as 32-byte values.  Since
//! r < N < P, the value r is its own field element, so that is dcrd's
//! comparison.  The model takes r and s as dcrd's `Signature` holds them,
//! below N: a value at or above N never reaches dcrd's verify (DER parsing
//! and the oracle's raw command reject it first).
//!
//! Compact recovery (`ecdsa/signature.go`, `RecoverCompact`) is [`recover`],
//! dcrd's checks in dcrd's order with dcrd's error kinds:
//!
//! 1. ErrSigInvalidLen unless the signature is 65 bytes;
//! 2. ErrSigInvalidRecoveryCode unless the header is in 27..=34, which
//!    then gives the recovery code (header − 27) & 3 and the compressed
//!    flag (header − 27) & 4;
//! 3. ErrSigRTooBig, ErrSigRIsZero, ErrSigSTooBig, ErrSigSIsZero, in that
//!    order, unless r and s are in [1, N − 1];
//! 4. with the code's overflow bit, ErrSigOverflowsPrime when r ≥ P − N,
//!    else x = r + N; without it, x = r;
//! 5. ErrPointNotOnCurve unless x decompresses, with the code's parity, to
//!    a point X;
//! 6. Q = u1·G + u2·X with u1 = −e/r and u2 = s/r, e = hash mod N, with an
//!    addition that doubles when its two points are equal;
//! 7. ErrPointNotOnCurve when Q is the point at infinity.
//!
//! [`verify_with`] and [`recover_with`] run the same steps with one
//! [`Break`] switched on, for the canaries; [`verify`] and [`recover`] are
//! dcrd's algorithms.

use k256::{AffinePoint, ProjectivePoint, Scalar};

use crate::arith::{self, N, P_MINUS_N};
use crate::cmd::{Cmd, Request};
use crate::r#gen::{decompress, from_xy, reduce, scalar, y_is_odd};
use crate::model::{Break, Coords, EcdsaBranch, ModelOutcome, add};

/// What dcrd's `RecoverCompact` returns for a signature it accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recovery {
    /// The recovered public key.
    pub key: AffinePoint,
    /// The header's compressed flag.
    pub compressed: bool,
    /// Whether u1·G and u2·X were the same point, so that dcrd's addition
    /// doubled.
    pub doubled: bool,
}

/// The first header byte of a compact signature (dcrd's
/// `compactSigMagicOffset`).
pub const COMPACT_MAGIC: u8 = 27;

/// The header's compressed-key flag, above the recovery code (dcrd's
/// `compactSigCompPubKey`).
pub const COMPACT_COMPRESSED: u8 = 4;

/// The recovery code's bit for an x coordinate at or above N (dcrd's
/// `pubKeyRecoveryCodeOverflowBit`).
pub const CODE_OVERFLOW: u8 = 2;

/// The recovery code's bit for an odd y (dcrd's
/// `pubKeyRecoveryCodeOddnessBit`).
pub const CODE_ODD: u8 = 1;

/// dcrd's `RecoverCompact` of `sig` over `hash`: the key, its compressed
/// flag and whether the sum doubled, or the `ErrorKind` name of the first
/// check that fails, in dcrd's order (the module documentation lists
/// them).
pub fn recover(sig: &[u8], hash: &[u8; 32]) -> Result<Recovery, &'static str> {
    let got = recover_with(sig, hash, Break::None)?;
    Ok(Recovery {
        key: got
            .key
            .point()
            .expect("without a break the recovered key is a point of the curve"),
        compressed: got.compressed,
        doubled: got.doubled,
    })
}

/// What [`recover_with`] returns for a signature it accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recovered {
    /// The recovered key's coordinates: a point of the curve, except under
    /// [`Break::RecoverIncompleteAdd`] (an incomplete sum) and
    /// [`Break::RecoverAcceptsInfinity`] (the point at infinity, whose
    /// coordinates read with the inverse of zero taken as zero are (0, 0)).
    pub key: Coords,
    /// The header's compressed flag.
    pub compressed: bool,
    /// Whether u1·G and u2·X were the same point.
    pub doubled: bool,
}

impl Recovered {
    /// The key serialized as the flag says, as `ecdsa_recover_compact`
    /// answers it: compressed (33 bytes) or uncompressed (65).
    pub fn serialized(&self) -> Vec<u8> {
        if self.compressed {
            self.key.compressed().to_vec()
        } else {
            self.key.uncompressed().to_vec()
        }
    }
}

/// [`recover`] with `brk` switched on: [`Break::RecoverIgnoresOverflow`]
/// takes x = r under every header, without step 4's check;
/// [`Break::RecoverIncompleteAdd`] adds at step 6 with incomplete affine
/// addition ([`add`]); [`Break::RecoverAcceptsInfinity`] returns the point
/// at infinity's (0, 0) at step 7.  Any other break is dcrd's algorithm.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
)]
pub fn recover_with(sig: &[u8], hash: &[u8; 32], brk: Break) -> Result<Recovered, &'static str> {
    // Step 1.
    let [header, rest @ ..]: &[u8; 65] = sig.try_into().map_err(|_| "ErrSigInvalidLen")?;
    // Step 2.
    let code = header
        .checked_sub(COMPACT_MAGIC)
        .filter(|&code| code <= COMPACT_COMPRESSED | CODE_OVERFLOW | CODE_ODD)
        .ok_or("ErrSigInvalidRecoveryCode")?;
    let compressed = code & COMPACT_COMPRESSED != 0;
    // Step 3.
    let (r, s) = rest.split_at(32);
    let r: &[u8; 32] = r.try_into().expect("32 bytes");
    let s: &[u8; 32] = s.try_into().expect("32 bytes");
    let r_scalar = scalar(r).ok_or("ErrSigRTooBig")?;
    if bool::from(r_scalar.is_zero()) {
        return Err("ErrSigRIsZero");
    }
    let s_scalar = scalar(s).ok_or("ErrSigSTooBig")?;
    if bool::from(s_scalar.is_zero()) {
        return Err("ErrSigSIsZero");
    }
    // Step 4.
    let x = if code & CODE_OVERFLOW != 0 && brk != Break::RecoverIgnoresOverflow {
        if *r >= P_MINUS_N {
            return Err("ErrSigOverflowsPrime");
        }
        arith::add_be(r, &N).0
    } else {
        *r
    };
    // Step 5.
    let big_x = decompress(&x, code & CODE_ODD != 0).ok_or("ErrPointNotOnCurve")?;
    // Step 6.
    let w: Scalar = Option::from(r_scalar.invert()).expect("a nonzero r is invertible");
    let u1 = -(reduce(hash) * w);
    let u2 = s_scalar * w;
    let u1g: ProjectivePoint = ProjectivePoint::GENERATOR * u1;
    let u2x: ProjectivePoint = ProjectivePoint::from(big_x) * u2;
    let doubled = u1g == u2x;
    let q = add(&u1g, &u2x, brk == Break::RecoverIncompleteAdd);
    // Step 7.
    let key = match q {
        Some(key) => key,
        None if brk == Break::RecoverAcceptsInfinity => Coords {
            x: [0; 32],
            y: [0; 32],
        },
        None => return Err("ErrPointNotOnCurve"),
    };
    Ok(Recovered {
        key,
        compressed,
        doubled,
    })
}

/// The model's recovery for an `ecdsa_recover_compact` request (32-byte
/// hash ‖ signature): [`recover`]'s answer, or `None` when the request is
/// not a recovery request or is shorter than its hash.
pub fn recover_request(request: &Request) -> Option<Result<Recovery, &'static str>> {
    if request.cmd != Cmd::EcdsaRecoverCompact {
        return None;
    }
    let (hash, sig) = request.data.split_first_chunk::<32>()?;
    Some(recover(sig, hash))
}

/// dcrd's verify of (r, s) over `hash` for key `q`: the step that decides,
/// and whether step 5's two summands were the same point.  `None` when r
/// or s is at or above N, which dcrd's signature cannot hold.
pub fn verify(
    q: &AffinePoint,
    hash: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
) -> Option<(EcdsaBranch, bool)> {
    let decision = verify_with(q, hash, r, s, Break::None)?;
    let branch = decision
        .branch
        .expect("without a break, one of dcrd's steps decides");
    Some((branch, decision.doubled))
}

/// What [`verify_with`] decides for one signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    /// The step of dcrd's verify that decided, or `None` where the break
    /// changed the step that decided.
    pub branch: Option<EcdsaBranch>,
    /// The verdict.
    pub accepts: bool,
    /// Whether step 5's two summands were the same point.
    pub doubled: bool,
}

/// [`verify`] with `brk` switched on: [`Break::EcdsaIncompleteAdd`] adds at
/// step 5 with incomplete affine addition ([`add`]);
/// [`Break::EcdsaAcceptsInfinity`] accepts at step 6;
/// [`Break::EcdsaNoRPlusN`] rejects whatever step 8 does not accept;
/// [`Break::EcdsaNoStep9`] skips step 9's guard, so an r at or above
/// P − N reaches step 10 and is compared as (r + N) mod P.  Any other
/// break is dcrd's algorithm.  `None` when r or s is at or above N.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
)]
pub fn verify_with(
    q: &AffinePoint,
    hash: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
    brk: Break,
) -> Option<Decision> {
    let (r_scalar, s_scalar) = (scalar(r)?, scalar(s)?);
    let at = |branch: EcdsaBranch, doubled: bool| Decision {
        branch: Some(branch),
        accepts: branch.accepts(),
        doubled,
    };
    let broken = |accepts: bool, doubled: bool| Decision {
        branch: None,
        accepts,
        doubled,
    };
    // Step 1.
    if bool::from(r_scalar.is_zero()) || bool::from(s_scalar.is_zero()) {
        return Some(at(EcdsaBranch::Step1Zero, false));
    }
    // Steps 2-4.
    let e = reduce(hash);
    let w: Scalar = Option::from(s_scalar.invert())?;
    let u1 = e * w;
    let u2 = r_scalar * w;
    // Step 5.
    let u1g: ProjectivePoint = ProjectivePoint::GENERATOR * u1;
    let u2q: ProjectivePoint = ProjectivePoint::from(*q) * u2;
    let doubled = u1g == u2q;
    let x = add(&u1g, &u2q, brk == Break::EcdsaIncompleteAdd);
    // Step 6.
    let Some(Coords { x, .. }) = x else {
        if brk == Break::EcdsaAcceptsInfinity {
            return Some(broken(true, doubled));
        }
        return Some(at(EcdsaBranch::Step6Infinity, doubled));
    };
    // Step 8.
    if x == *r {
        return Some(at(EcdsaBranch::Step8Accept, doubled));
    }
    if brk == Break::EcdsaNoRPlusN {
        return Some(broken(false, doubled));
    }
    // Step 9.
    if *r >= P_MINUS_N {
        if brk == Break::EcdsaNoStep9 {
            // r + N reaches P, and the field addition wraps it.
            return Some(broken(x == arith::add_mod_p(r, &N), doubled));
        }
        return Some(at(EcdsaBranch::Step9Reject, doubled));
    }
    // Step 10.
    let (r_plus_n, carry) = arith::add_be(r, &N);
    debug_assert!(!carry, "r < P - N, so r + N < P");
    let branch = if x == r_plus_n {
        EcdsaBranch::Step10Accept
    } else {
        EcdsaBranch::Step10Reject
    };
    Some(at(branch, doubled))
}

/// A public key as dcrd's `ParsePubKey` accepts it, decoded with this
/// crate's own arithmetic: 02/03 ‖ x decompressed, 04 ‖ x ‖ y on the
/// curve, 06/07 ‖ x ‖ y on the curve with y of the byte's parity.  `None`
/// for anything dcrd rejects.
pub fn decode_key(key: &[u8]) -> Option<AffinePoint> {
    let (&format, rest) = key.split_first()?;
    match (format, rest.len()) {
        (0x02 | 0x03, 32) => decompress(rest.try_into().ok()?, format == 0x03),
        (0x04 | 0x06 | 0x07, 64) => {
            let (x, y) = rest.split_at(32);
            let point = from_xy(x.try_into().ok()?, y.try_into().ok()?)?;
            let parity_ok = format == 0x04 || y_is_odd(&point) == (format == 0x07);
            parity_ok.then_some(point)
        }
        _ => None,
    }
}

/// (r, s) from a DER signature in the strict form `30 L 02 rl R 02 sl S`,
/// every length consistent, each integer non-negative and at most 32
/// significant bytes.  `None` for anything else.  This reads what the
/// generators write; it is not a model of dcrd's parser, whose checks
/// `ecdsa_parse_der` compares directly.
pub fn decode_der(der: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    let (&[0x30, len], rest) = der.split_first_chunk::<2>()? else {
        return None;
    };
    if usize::from(len) != rest.len() {
        return None;
    }
    let (r, rest) = der_integer(rest)?;
    let (s, rest) = der_integer(rest)?;
    rest.is_empty().then_some((r, s))
}

fn der_integer(der: &[u8]) -> Option<([u8; 32], &[u8])> {
    let (&[0x02, len], rest) = der.split_first_chunk::<2>()? else {
        return None;
    };
    let (body, rest) = rest.split_at_checked(usize::from(len))?;
    if body.first().is_none_or(|&b| b & 0x80 != 0) {
        return None;
    }
    let first = body.iter().position(|&b| b != 0).unwrap_or(body.len());
    let digits = &body[first..];
    let mut out = [0u8; 32];
    let at = 32usize.checked_sub(digits.len())?;
    out[at..].copy_from_slice(digits);
    Some((out, rest))
}

/// The model's outcome for an ECDSA verify request: the oracle's layout
/// decoded (a raw request's key of any format, or `ecdsa_verify`'s
/// compressed key and DER signature), then [`verify`].  `None` when the
/// request is not a verify request or its key or signature does not
/// decode.
pub fn request_outcome(request: &Request) -> Option<ModelOutcome> {
    let (q, hash, r, s) = match request.cmd {
        Cmd::EcdsaVerifyRaw => {
            let (&len, rest) = request.data.split_first()?;
            let (key, rest) = rest.split_at_checked(usize::from(len))?;
            let (hash, rest) = rest.split_first_chunk::<32>()?;
            let (r, rest) = rest.split_first_chunk::<32>()?;
            let s: &[u8; 32] = rest.try_into().ok()?;
            (decode_key(key)?, *hash, *r, *s)
        }
        Cmd::EcdsaVerify => {
            let (key, rest) = request.data.split_first_chunk::<33>()?;
            let (hash, der) = rest.split_first_chunk::<32>()?;
            let (r, s) = decode_der(der)?;
            (decode_key(key)?, *hash, r, s)
        }
        _ => return None,
    };
    let (branch, doubled) = verify(&q, &hash, &r, &s)?;
    Some(ModelOutcome::Ecdsa { branch, doubled })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd;
    use crate::r#gen::{base_mul, compressed, der_minimal, hybrid, uncompressed, x_of};
    use dcroxide_testutil::unhex;
    use k256::Scalar;

    fn b32(hex: &str) -> [u8; 32] {
        unhex(hex).try_into().expect("32 bytes")
    }

    /// The rows of dcrd's own `TestVerifyFailures`
    /// (`ecdsa/signature_test.go`, copied into the oracle's tests) and the
    /// signature they vary, each ending at the step its name gives.
    #[test]
    fn dcrds_verify_rows_end_where_they_say() {
        let q = base_mul(&Scalar::ONE);
        let hash = b32("c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7");
        let r = b32("c6c4137b0e5fbfc88ae3f293d7e80c8566c43ae20340075d44f75b009c943d09");
        let s = b32("00ba213513572e35943d5acdd17215561b03f11663192a7252196cc8b2a99560");
        let zero = [0u8; 32];
        for (name, r, s, want) in [
            ("valid", r, s, EcdsaBranch::Step8Accept),
            ("R is 0", zero, s, EcdsaBranch::Step1Zero),
            ("S is 0", r, zero, EcdsaBranch::Step1Zero),
            (
                "u1G + u2Q is the point at infinity",
                b32("3cfe45621a29fac355260a14b9adc0fe43ac2f13e918fc9ddfa117e964b61a8a"),
                s,
                EcdsaBranch::Step6Infinity,
            ),
            (
                "R < P-N, but invalid",
                b32("000000000000000000000000000000014551231950b75fc4402da1722fc9baed"),
                s,
                EcdsaBranch::Step10Reject,
            ),
        ] {
            assert_eq!(verify(&q, &hash, &r, &s), Some((want, false)), "{name}");
        }
        let mut other = hash;
        other[0] ^= 1;
        assert_eq!(
            verify(&q, &other, &r, &s),
            Some((EcdsaBranch::Step9Reject, false)),
            "a random r is at or above P - N, so step 9 rejects"
        );
        assert_eq!(
            verify(&q, &hash, &P_MINUS_N, &s),
            Some((EcdsaBranch::Step9Reject, false)),
            "r = P - N is the smallest r step 9 rejects"
        );
        assert_eq!(verify(&q, &hash, &N, &s), None, "r at N is out of range");
        assert_eq!(verify(&q, &hash, &r, &[0xff; 32]), None);

        // The four presentations decode to the same request.
        for request in [
            cmd::ecdsa_verify_raw(&compressed(&q), &hash, &r, &s),
            cmd::ecdsa_verify_raw(&uncompressed(&q), &hash, &r, &s),
            cmd::ecdsa_verify_raw(&hybrid(&q), &hash, &r, &s),
            cmd::ecdsa_verify(&compressed(&q), &hash, &der_minimal(&r, &s)),
        ] {
            assert_eq!(
                request_outcome(&request),
                Some(ModelOutcome::Ecdsa {
                    branch: EcdsaBranch::Step8Accept,
                    doubled: false
                })
            );
        }
        assert_eq!(request_outcome(&cmd::ecdsa_parse_der(&[])), None);
        let bad_key = cmd::ecdsa_verify_raw(&[0x05; 33], &hash, &r, &s);
        assert_eq!(request_outcome(&bad_key), None);
    }

    /// A doubling is seen: with Q = (e/r)·G, u2·Q = (e/s)·G = u1·G.
    #[test]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
    )]
    fn a_doubling_is_reported() {
        let s = Scalar::from(7u64);
        let hash = [0x42u8; 32];
        let e = reduce(&hash);
        let w = Option::<Scalar>::from(s.invert()).expect("nonzero");
        let x = base_mul(&(e * w + e * w));
        let r = reduce(&x_of(&x));
        let r_inv = Option::<Scalar>::from(r.invert()).expect("nonzero");
        let q = base_mul(&(e * r_inv));
        let r_bytes = crate::r#gen::scalar_bytes(&r);
        let s_bytes = crate::r#gen::scalar_bytes(&s);
        let got = verify(&q, &hash, &r_bytes, &s_bytes).expect("in range");
        assert!(got.1, "doubled");
        assert!(got.0.accepts());
    }

    /// The rows of dcrd's own `TestRecoverCompactErrors`
    /// (`ecdsa/signature_test.go`), each failing with its kind, and the
    /// signature they vary, `TestSignAndRecoverCompact`'s key 2 row, whose
    /// recovery code has the oddness bit: under that code it recovers 2·G
    /// with either flag, under the other parity another key, and under
    /// either overflow code it fails, since its r is at or above P − N.
    #[test]
    fn dcrds_recovery_rows_fail_where_they_say() {
        let hash = b32("c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7");
        let r = "e6f137b52377250760cc702e19b7aee3c63b0e7d95a91939b14ab3b5c4771e59";
        let s = "44b9bc4620afa158b7efdfea5234ff2d5f2f78b42886f02cf581827ee55318ea";
        let n = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
        let n1 = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142";
        let zero = "0000000000000000000000000000000000000000000000000000000000000000";
        for (name, sig, hash, want) in [
            ("empty signature", String::new(), hash, "ErrSigInvalidLen"),
            ("no header", format!("{r}{s}"), hash, "ErrSigInvalidLen"),
            (
                "one byte too long",
                format!("1f{r}00{s}"),
                hash,
                "ErrSigInvalidLen",
            ),
            (
                "code too low",
                format!("1a{r}{s}"),
                hash,
                "ErrSigInvalidRecoveryCode",
            ),
            (
                "code too high",
                format!("23{r}{s}"),
                hash,
                "ErrSigInvalidRecoveryCode",
            ),
            ("R == N", format!("1f{n}{s}"), hash, "ErrSigRTooBig"),
            ("R == N + 1", format!("1f{n1}{s}"), hash, "ErrSigRTooBig"),
            ("R == 0", format!("1f{zero}{s}"), hash, "ErrSigRIsZero"),
            // dcrd's order: r's zero check comes before s's range check.
            (
                "R == 0, S == N",
                format!("1f{zero}{n}"),
                hash,
                "ErrSigRIsZero",
            ),
            ("S == N", format!("1f{r}{n}"), hash, "ErrSigSTooBig"),
            ("S == N + 1", format!("1f{r}{n1}"), hash, "ErrSigSTooBig"),
            (
                "S == 0",
                format!("1f{r}{zero}"),
                b32("393bec84f1a04037751c0d6c2817f37953eaa204ac0898de7adb038c33a20438"),
                "ErrSigSIsZero",
            ),
            (
                "R >= P - N with the overflow bit",
                format!("21000000000000000000000000000000014551231950b75fc4402da1722fc9baee{s}"),
                hash,
                "ErrSigOverflowsPrime",
            ),
            (
                "R > N with the overflow bit",
                format!("21000000000000000000000000000000014551231950b75fc4402da1722fc9baed{s}"),
                hash,
                "ErrPointNotOnCurve",
            ),
            (
                "a signature for secp256r1",
                "1f2a81d1b3facc22185267d3f8832c5104902591bc471253f1cfc5eb25f4f740f2\
                 72e65d019f9b09d769149e2be0b55de9b0224d34095bddc6a5dba90bfda33c45"
                    .to_owned(),
                b32("9165e957708bc95cf62d020769c150b2d7b08e7ab7981860815b1eaabd41d695"),
                "ErrPointNotOnCurve",
            ),
            (
                "the recovered key at infinity",
                "1fc6c4137b0e5fbfc88ae3f293d7e80c8566c43ae20340075d44f75b009c943d09\
                 1281d8d90a5774045abd57b453c7eadbc830dbadec89ae8dd7639b9cc55641d0"
                    .to_owned(),
                hash,
                "ErrPointNotOnCurve",
            ),
        ] {
            assert_eq!(recover(&unhex(&sig), &hash), Err(want), "{name}");
        }

        let two_g = base_mul(&Scalar::from(2u64));
        for (header, compressed) in [(0x1c, false), (0x20, true)] {
            let got = recover(&unhex(&format!("{header:02x}{r}{s}")), &hash).expect("recovers");
            assert_eq!(
                got,
                Recovery {
                    key: two_g,
                    compressed,
                    doubled: false
                },
                "header {header}"
            );
        }
        let other = recover(&unhex(&format!("1f{r}{s}")), &hash).expect("recovers");
        assert_ne!(other.key, two_g, "the other parity names another point");
        assert!(other.compressed);
        for header in ["1d", "1e", "21", "22"] {
            assert_eq!(
                recover(&unhex(&format!("{header}{r}{s}")), &hash),
                Err("ErrSigOverflowsPrime"),
                "header {header}"
            );
        }
        let request = cmd::ecdsa_recover_compact(&hash, &unhex(&format!("20{r}{s}")));
        assert_eq!(
            recover_request(&request).map(|r| r.map(|r| r.key)),
            Some(Ok(two_g))
        );
        assert_eq!(recover_request(&cmd::ecdsa_parse_der(&[])), None);
        let short = cmd::Request {
            cmd: Cmd::EcdsaRecoverCompact,
            data: vec![0; 31],
        };
        assert_eq!(recover_request(&short), None);
    }

    /// A doubling in recovery is seen: X = A = a·G with r = A.x and
    /// e = −s·a, so u1·G = (s·a/r)·G = u2·A and Q = 2·u1·G.
    #[test]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
    )]
    fn a_recovery_doubling_is_reported() {
        let a = Scalar::from(5u64);
        let s = Scalar::from(11u64);
        let big_a = base_mul(&a);
        let r = x_of(&big_a);
        let r_scalar = scalar(&r).expect("5·G's x is below N");
        let e = -(s * a);
        let header = COMPACT_MAGIC.saturating_add(u8::from(y_is_odd(&big_a)));
        let mut sig = vec![header];
        sig.extend_from_slice(&r);
        sig.extend_from_slice(&crate::r#gen::scalar_bytes(&s));
        let got = recover(&sig, &crate::r#gen::scalar_bytes(&e)).expect("recovers");
        let u1 = s * a * Option::<Scalar>::from(r_scalar.invert()).expect("nonzero");
        assert!(got.doubled);
        assert_eq!(got.key, base_mul(&(u1 + u1)));
        assert!(!got.compressed);

        // An incomplete addition gives (−2x, −y) of u1·G instead, which
        // is no key: −2x is the x of no point the test computes, so it is
        // checked as −2x + 2x = 0 mod P, and −y is the negated point's y.
        let hash = crate::r#gen::scalar_bytes(&e);
        let broken = recover_with(&sig, &hash, Break::RecoverIncompleteAdd).expect("recovers");
        let u1g = base_mul(&u1);
        let two_x = arith::add_mod_p(&x_of(&u1g), &x_of(&u1g));
        assert_eq!(arith::add_mod_p(&broken.key.x, &two_x), [0; 32]);
        assert_eq!(broken.key.y, crate::r#gen::y_of(&base_mul(&-u1)));
        assert!(broken.doubled && broken.key.point().is_none());
        assert_eq!(broken.serialized(), broken.key.uncompressed());
        let unbroken = recover_with(&sig, &hash, Break::None).expect("recovers");
        assert_eq!(unbroken.key, Coords::of(&base_mul(&(u1 + u1))));
    }

    /// The point N + t for the smallest t that is an x coordinate.
    fn overflow_point() -> ([u8; 32], AffinePoint) {
        (1u64..)
            .find_map(|t| {
                let t = arith::be_from_u64(t);
                decompress(&arith::add_be(&N, &t).0, false).map(|p| (t, p))
            })
            .expect("half of all values are x coordinates")
    }

    /// Each verify break changes the step it names and nothing before it:
    /// a signature through r + N (step 10), one whose r + N wraps (step
    /// 9), one whose sum is the point at infinity (step 6) and one whose
    /// sum doubles (step 8), each under every ECDSA break.
    #[test]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
    )]
    fn verify_breaks_change_their_step() {
        use crate::r#gen::{scalar_bytes, solve_key};
        let hash = [0x5au8; 32];
        let e = reduce(&hash);
        let s = Scalar::from(7u64);
        let s_bytes = scalar_bytes(&s);
        let decide = |q: &AffinePoint, r: &[u8; 32], brk| {
            verify_with(q, &hash, r, &s_bytes, brk).expect("in range")
        };
        let at = |branch: EcdsaBranch, doubled| Decision {
            branch: Some(branch),
            accepts: branch.accepts(),
            doubled,
        };
        let broken = |accepts, doubled| Decision {
            branch: None,
            accepts,
            doubled,
        };

        // Step 10: X = N + t, r = t.
        let (t, big_x) = overflow_point();
        let r = scalar(&t).expect("small");
        let q = solve_key(&r, &s, &e, &big_x).expect("finite");
        assert_eq!(
            decide(&q, &t, Break::None),
            at(EcdsaBranch::Step10Accept, false)
        );
        assert_eq!(decide(&q, &t, Break::EcdsaNoRPlusN), broken(false, false));
        for brk in [
            Break::EcdsaNoStep9,
            Break::EcdsaAcceptsInfinity,
            Break::EcdsaIncompleteAdd,
            Break::SchnorrRModN,
        ] {
            assert_eq!(decide(&q, &t, brk), at(EcdsaBranch::Step10Accept, false));
        }

        // Step 9: X = G, whose x is below 2N − P, and r = X.x + P − N.
        let g = base_mul(&Scalar::ONE);
        let r = arith::add_be(&x_of(&g), &P_MINUS_N).0;
        let q = solve_key(&scalar(&r).expect("below N"), &s, &e, &g).expect("finite");
        assert_eq!(
            decide(&q, &r, Break::None),
            at(EcdsaBranch::Step9Reject, false)
        );
        assert_eq!(decide(&q, &r, Break::EcdsaNoStep9), broken(true, false));
        assert_eq!(decide(&q, &r, Break::EcdsaNoRPlusN), broken(false, false));

        // Step 6: Q = −(e/r)·G, so u2·Q = −u1·G.
        let r = Scalar::from(3u64);
        let r_inv = Option::<Scalar>::from(r.invert()).expect("nonzero");
        let q = base_mul(&-(e * r_inv));
        let r = scalar_bytes(&r);
        assert_eq!(
            decide(&q, &r, Break::None),
            at(EcdsaBranch::Step6Infinity, false)
        );
        assert_eq!(
            decide(&q, &r, Break::EcdsaAcceptsInfinity),
            broken(true, false)
        );
        // An incomplete sum is no point at infinity, so the verify goes on
        // and rejects at step 10.
        assert_eq!(
            decide(&q, &r, Break::EcdsaIncompleteAdd),
            at(EcdsaBranch::Step10Reject, false)
        );

        // Step 8 with a doubling: X = 2·(e/s)·G, r = X.x, Q = (e/r)·G.
        let w = Option::<Scalar>::from(s.invert()).expect("nonzero");
        let x = base_mul(&(e * w + e * w));
        let r = reduce(&x_of(&x));
        let q = base_mul(&(e * Option::<Scalar>::from(r.invert()).expect("nonzero")));
        let r = scalar_bytes(&r);
        assert!(r >= P_MINUS_N, "a random x is far above P - N");
        assert_eq!(
            decide(&q, &r, Break::None),
            at(EcdsaBranch::Step8Accept, true)
        );
        assert_eq!(
            decide(&q, &r, Break::EcdsaIncompleteAdd),
            at(EcdsaBranch::Step9Reject, true)
        );
        assert_eq!(
            decide(&q, &r, Break::EcdsaNoRPlusN),
            at(EcdsaBranch::Step8Accept, true)
        );
    }

    /// Each recovery break changes the step it names: the overflow bit
    /// ignored recovers another key (or none) from a valid overflow
    /// signature and passes dcrd's OverflowsPrime row on; a key at
    /// infinity comes back as (0, 0).
    #[test]
    fn recovery_breaks_change_their_step() {
        use crate::r#gen::{scalar_bytes, solve_key};
        let hash = [0x33u8; 32];
        let s = Scalar::from(9u64);
        let (t, big_x) = overflow_point();
        let r = scalar(&t).expect("small");
        let q = solve_key(&r, &s, &reduce(&hash), &big_x).expect("finite");
        // The overflow bit and even y: header 27 + 2.
        let sig = [&[29u8][..], &t, &scalar_bytes(&s)].concat();
        let got = recover_with(&sig, &hash, Break::None).expect("recovers");
        assert_eq!(got.key, Coords::of(&q));
        assert_eq!(got.serialized(), uncompressed(&q));
        let ignored = recover_with(&sig, &hash, Break::RecoverIgnoresOverflow);
        assert_ne!(ignored.map(|r| r.key), Ok(Coords::of(&q)));
        for brk in [Break::RecoverIncompleteAdd, Break::RecoverAcceptsInfinity] {
            assert_eq!(recover_with(&sig, &hash, brk), Ok(got));
        }

        let s = "44b9bc4620afa158b7efdfea5234ff2d5f2f78b42886f02cf581827ee55318ea";
        let prime = unhex(&format!(
            "21000000000000000000000000000000014551231950b75fc4402da1722fc9baee{s}"
        ));
        assert_eq!(recover(&prime, &hash), Err("ErrSigOverflowsPrime"));
        assert_ne!(
            recover_with(&prime, &hash, Break::RecoverIgnoresOverflow),
            Err("ErrSigOverflowsPrime")
        );

        // dcrd's "the recovered key at infinity" row, under a compressed
        // header.
        let hash = b32("c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7");
        let infinity = unhex(
            "1fc6c4137b0e5fbfc88ae3f293d7e80c8566c43ae20340075d44f75b009c943d09\
             1281d8d90a5774045abd57b453c7eadbc830dbadec89ae8dd7639b9cc55641d0",
        );
        assert_eq!(recover(&infinity, &hash), Err("ErrPointNotOnCurve"));
        let got = recover_with(&infinity, &hash, Break::RecoverAcceptsInfinity).expect("a key");
        assert_eq!(got.serialized(), [&[2u8][..], &[0; 32]].concat());
        // An incomplete sum is no point at infinity either.
        let got = recover_with(&infinity, &hash, Break::RecoverIncompleteAdd).expect("a key");
        assert!(got.key.point().is_none());
    }

    #[test]
    fn keys_and_der_decode_strictly() {
        let q = base_mul(&Scalar::from(3u64));
        assert_eq!(decode_key(&compressed(&q)), Some(q));
        assert_eq!(decode_key(&uncompressed(&q)), Some(q));
        assert_eq!(decode_key(&hybrid(&q)), Some(q));
        let mut wrong = hybrid(&q);
        wrong[0] ^= 1;
        assert_eq!(decode_key(&wrong), None, "mismatched oddness");
        assert_eq!(decode_key(&compressed(&q)[..32]), None);
        assert_eq!(decode_key(&[]), None);

        let (r, s) = ([0x11u8; 32], [0x80u8; 32]);
        assert_eq!(decode_der(&der_minimal(&r, &s)), Some((r, s)));
        assert_eq!(
            decode_der(&der_minimal(&[0; 32], &s)),
            Some(([0; 32], s)),
            "zero is one zero byte"
        );
        let der = der_minimal(&r, &s);
        assert_eq!(decode_der(der.split_last().expect("bytes").1), None);
        let mut long = der.clone();
        long.push(0);
        assert_eq!(decode_der(&long), None);
        let mut negative = der;
        negative[4] = 0x91;
        assert_eq!(decode_der(&negative), None);
    }
}
