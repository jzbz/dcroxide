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

use k256::elliptic_curve::group::Group;
use k256::{AffinePoint, ProjectivePoint, Scalar};

use crate::arith::{self, N, P_MINUS_N};
use crate::cmd::{Cmd, Request};
use crate::r#gen::{decompress, from_xy, reduce, scalar, x_of, y_is_odd};
use crate::model::{EcdsaBranch, ModelOutcome};

/// dcrd's verify of (r, s) over `hash` for key `q`: the step that decides,
/// and whether step 5's two summands were the same point.  `None` when r
/// or s is at or above N, which dcrd's signature cannot hold.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
)]
pub fn verify(
    q: &AffinePoint,
    hash: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
) -> Option<(EcdsaBranch, bool)> {
    let (r_scalar, s_scalar) = (scalar(r)?, scalar(s)?);
    // Step 1.
    if bool::from(r_scalar.is_zero()) || bool::from(s_scalar.is_zero()) {
        return Some((EcdsaBranch::Step1Zero, false));
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
    let x: ProjectivePoint = u1g + u2q;
    // Step 6.
    if bool::from(x.is_identity()) {
        return Some((EcdsaBranch::Step6Infinity, doubled));
    }
    let x = x_of(&x.to_affine());
    // Step 8.
    if x == *r {
        return Some((EcdsaBranch::Step8Accept, doubled));
    }
    // Step 9.
    if *r >= P_MINUS_N {
        return Some((EcdsaBranch::Step9Reject, doubled));
    }
    // Step 10.
    let (r_plus_n, carry) = arith::add_be(r, &N);
    debug_assert!(!carry, "r < P - N, so r + N < P");
    let branch = if x == r_plus_n {
        EcdsaBranch::Step10Accept
    } else {
        EcdsaBranch::Step10Reject
    };
    Some((branch, doubled))
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
    use crate::r#gen::{base_mul, compressed, der_minimal, hybrid, uncompressed};
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
