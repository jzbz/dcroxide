// SPDX-License-Identifier: ISC
//! dcrd's EC-Schnorr-DCRv0 verification (`schnorr/signature.go`,
//! `schnorrVerify`) as a model that names dcrd's internal reason for each
//! case, on this crate's own `k256` arithmetic and BLAKE-256.
//!
//! dcrd's steps, and the reason each fails with:
//!
//! 1. the hash is 32 bytes (ErrInvalidHashLen; every oracle request's is);
//! 2. the key is on the curve (ErrPubKeyNotOnCurve; every parsed key is);
//! 3. r < P and 4. s < N (parsing has already rejected anything else);
//! 5. e = BLAKE-256(r ‖ m);
//! 6. ErrSchnorrHashValue if e ≥ N;
//! 7. R = s·G + e·Q, with an addition that doubles when its two points
//!    are equal;
//! 8. ErrSigRNotOnCurve if R is the point at infinity;
//! 9. ErrSigRYIsOdd if R.y is odd;
//! 10. ErrUnequalRValues unless R.x = r.
//!
//! The model computes R with `k256`'s complete projective addition and
//! compares its affine x with r as 32-byte values; r < P, so that is
//! dcrd's field comparison.  [`verify_with`] runs the same steps with one
//! [`Break`] switched on, for the canaries.

use k256::{AffinePoint, ProjectivePoint};

use crate::arith::{self, N, P};
use crate::cmd::{Cmd, Request};
use crate::r#gen::scalar;
use crate::r#gen::schnorr::challenge;
use crate::model::ecdsa::decode_key;
use crate::model::{Break, ModelOutcome, add};

/// dcrd's verify of (r, s) over `hash` for key `q`: `Ok` or the reason it
/// fails, and whether step 7's two summands were the same point.  `None`
/// when r is at or above P or s at or above N, which dcrd's signature
/// cannot hold.
pub fn verify(
    q: &AffinePoint,
    hash: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
) -> Option<(Result<(), &'static str>, bool)> {
    verify_with(q, hash, r, s, Break::None)
}

/// [`verify`] with `brk` switched on: [`Break::SchnorrIncompleteAdd`] adds
/// at step 7 with incomplete affine addition ([`add`]), so a sum that
/// doubles or cancels is neither 2·(s·G) nor the point at infinity;
/// [`Break::SchnorrRModN`] compares R.x mod N with r mod N at step 10.
/// Any other break is dcrd's algorithm.
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
) -> Option<(Result<(), &'static str>, bool)> {
    // Steps 3 and 4.
    if *r >= P {
        return None;
    }
    let s = scalar(s)?;
    // Steps 5 and 6.
    let Some(e) = challenge(r, hash) else {
        return Some((Err("ErrSchnorrHashValue"), false));
    };
    // Step 7.
    let sg: ProjectivePoint = ProjectivePoint::GENERATOR * s;
    let eq: ProjectivePoint = ProjectivePoint::from(*q) * e;
    let doubled = sg == eq;
    // Step 8.
    let Some(big_r) = add(&sg, &eq, brk == Break::SchnorrIncompleteAdd) else {
        return Some((Err("ErrSigRNotOnCurve"), doubled));
    };
    // Step 9.
    if big_r.y_is_odd() {
        return Some((Err("ErrSigRYIsOdd"), doubled));
    }
    // Step 10.
    let equal = if brk == Break::SchnorrRModN {
        mod_n(&big_r.x) == mod_n(r)
    } else {
        big_r.x == *r
    };
    if !equal {
        return Some((Err("ErrUnequalRValues"), doubled));
    }
    Some((Ok(()), doubled))
}

/// v mod N for a v below P, which is below 2N.
fn mod_n(v: &[u8; 32]) -> [u8; 32] {
    if *v >= N { arith::sub_be(v, &N).0 } else { *v }
}

/// The model's outcome for a `schnorr_verify` request (33-byte key ‖
/// hash ‖ r ‖ s): the key decoded as dcrd's `ParsePubKey` accepts it, then
/// [`verify`].  `None` when the request is not a Schnorr verify request,
/// or its key or signature does not parse.
pub fn request_outcome(request: &Request) -> Option<ModelOutcome> {
    if request.cmd != Cmd::SchnorrVerify {
        return None;
    }
    let (key, rest) = request.data.split_first_chunk::<33>()?;
    let (hash, rest) = rest.split_first_chunk::<32>()?;
    let (r, rest) = rest.split_first_chunk::<32>()?;
    let s: &[u8; 32] = rest.try_into().ok()?;
    let (reason, doubled) = verify(&decode_key(key)?, hash, r, s)?;
    Some(ModelOutcome::Schnorr { reason, doubled })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd;
    use crate::r#gen::{base_mul, compressed, decompress, scalar_bytes, x_of, y_is_odd};
    use dcroxide_testutil::unhex;
    use k256::Scalar;

    fn b32(hex: &str) -> [u8; 32] {
        unhex(hex).try_into().expect("32 bytes")
    }

    /// The rows of dcrd's own `TestVerifyErrors`
    /// (`schnorr/signature_test.go`) that reach verify with key 1, each
    /// ending with the reason its name gives, and the signature they vary,
    /// valid.  Its range rows are the ones the model declines.
    #[test]
    fn dcrds_verify_rows_end_where_they_say() {
        let g = base_mul(&Scalar::ONE);
        let hash = b32("c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7");
        let r = b32("4c68976afe187ff0167919ad181cb30f187e2af1c8233b2cbebbbe0fc97fff61");
        let s = b32("e9ae2d0e306497236d4e328dc1a34244045745e87da69d806859348bc2a74525");
        for (name, hash, r, s, want) in [
            ("valid", hash, r, s, Ok(())),
            (
                "calculated R point at infinity",
                hash,
                r,
                b32("14cc9e0544dd8fe6baa7c20fd2a141d0ee60114c419377efc850a49bd5c1ed36"),
                Err("ErrSigRNotOnCurve"),
            ),
            (
                "odd R",
                b32("ccf8c53a7631aad469d412963d495c729ff219dd2ae9a0c4de4bd1b4c777d49c"),
                b32("2c2c71f7bf3e183238b1f20d856e068dc6d37805c8b2d872d0f23d906bc95789"),
                b32("eb7670ca6ff95c1d5c6785bc72e0781f27c9778758317d82d3053fdbcc9c17b0"),
                Err("ErrSigRYIsOdd"),
            ),
            (
                "mismatched R",
                b32("d4f9aea8c329f57a81397f0418269a8bd495957ea56ae0af0dfa886fb5977046"),
                r,
                s,
                Err("ErrUnequalRValues"),
            ),
        ] {
            assert_eq!(verify(&g, &hash, &r, &s), Some((want, false)), "{name}");
        }
        let p = b32("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
        assert_eq!(verify(&g, &hash, &p, &s), None, "r == field prime");
        assert_eq!(verify(&g, &hash, &r, &N), None, "s == group order");

        let request = cmd::schnorr_verify(
            &compressed(&g),
            &hash,
            &crate::r#gen::schnorr::signature(&r, &s),
        );
        assert_eq!(
            request_outcome(&request),
            Some(ModelOutcome::Schnorr {
                reason: Ok(()),
                doubled: false
            })
        );
        assert_eq!(request_outcome(&cmd::schnorr_parse(&[0; 64])), None);
        let mut bad_key = request.clone();
        bad_key.data[0] = 0x05;
        assert_eq!(request_outcome(&bad_key), None);
    }

    /// dcrd checks R's y before its x: an odd R ends at step 9 with
    /// ErrSigRYIsOdd whether or not R.x is r, never at step 10.
    #[test]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
    )]
    fn an_odd_r_ends_at_step_9_whatever_its_x() {
        let hash = [0x55u8; 32];
        let s = Scalar::from(5u64);
        let big_r = base_mul(&Scalar::from(3u64));
        let big_r = if y_is_odd(&big_r) { big_r } else { -big_r };
        let x = x_of(&big_r);
        for r in [x, arith::add_be(&x, &arith::be_from_u64(1)).0] {
            let e = challenge(&r, &hash).expect("below N");
            let e_inv = Option::<Scalar>::from(e.invert()).expect("nonzero");
            let q = ((ProjectivePoint::from(big_r) - ProjectivePoint::GENERATOR * s) * e_inv)
                .to_affine();
            assert_eq!(
                verify(&q, &hash, &r, &scalar_bytes(&s)),
                Some((Err("ErrSigRYIsOdd"), false)),
                "R.x = r: {}",
                r == x
            );
        }
    }

    /// A doubling is seen: with Q = (s/e)·G, e·Q = s·G.
    #[test]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
    )]
    fn a_doubling_is_reported() {
        let s = Scalar::from(9u64);
        let r = [0x42u8; 32];
        let hash = [7u8; 32];
        let e = challenge(&r, &hash).expect("below N");
        let q = base_mul(&(s * Option::<Scalar>::from(e.invert()).expect("nonzero")));
        let (_, doubled) = verify(&q, &hash, &r, &scalar_bytes(&s)).expect("in range");
        assert!(doubled);
    }

    /// Each break changes the step it names: an incomplete addition turns
    /// a doubling's valid signature and a sum at infinity into a point
    /// that is neither, and comparing x mod N accepts an R whose x is
    /// r + N or r − N.
    #[test]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "k256 scalar and point operations only: modular group arithmetic, no integer operator here"
    )]
    fn breaks_change_their_step() {
        let hash = [0x77u8; 32];
        // SV-double's construction: R = 2s·G of even y, r = R.x and
        // Q = (s/e)·G, so e·Q = s·G.
        let mut s = Scalar::from(9u64);
        let mut big_r = base_mul(&(s + s));
        if y_is_odd(&big_r) {
            s = -s;
            big_r = -big_r;
        }
        let r = x_of(&big_r);
        let e = challenge(&r, &hash).expect("below N");
        let e_inv = Option::<Scalar>::from(e.invert()).expect("nonzero");
        let s_bytes = scalar_bytes(&s);
        let q = base_mul(&(s * e_inv));
        assert_eq!(verify(&q, &hash, &r, &s_bytes), Some((Ok(()), true)));
        let (broken, doubled) =
            verify_with(&q, &hash, &r, &s_bytes, Break::SchnorrIncompleteAdd).expect("in range");
        assert!(broken.is_err() && doubled, "{broken:?}");
        for brk in [Break::SchnorrRModN, Break::EcdsaIncompleteAdd] {
            assert_eq!(
                verify_with(&q, &hash, &r, &s_bytes, brk),
                Some((Ok(()), true))
            );
        }

        // A sum at infinity: Q = −(s/e)·G.
        let q = base_mul(&-(s * e_inv));
        assert_eq!(
            verify(&q, &hash, &r, &s_bytes),
            Some((Err("ErrSigRNotOnCurve"), false))
        );
        let (broken, _) =
            verify_with(&q, &hash, &r, &s_bytes, Break::SchnorrIncompleteAdd).expect("in range");
        assert!(
            matches!(broken, Err("ErrSigRYIsOdd" | "ErrUnequalRValues")),
            "{broken:?}"
        );

        // SV-unequalR's shifted strata: R.x = N + t with r = t, and
        // R.x = t with r = t + N, each R of even y and Q solved for.
        let x_coordinate = |shift: bool| {
            (1u64..)
                .map(arith::be_from_u64)
                .find_map(|t| {
                    let x = if shift { arith::add_be(&N, &t).0 } else { t };
                    decompress(&x, false).map(|p| (t, p))
                })
                .expect("half of all values are x coordinates")
        };
        let (t, above) = x_coordinate(true);
        let (u, below) = x_coordinate(false);
        for (big_r, r) in [(above, t), (below, arith::add_be(&u, &N).0)] {
            let e = challenge(&r, &hash).expect("below N");
            let e_inv = Option::<Scalar>::from(e.invert()).expect("nonzero");
            let q = ((ProjectivePoint::from(big_r) - ProjectivePoint::GENERATOR * s) * e_inv)
                .to_affine();
            assert_eq!(
                verify(&q, &hash, &r, &s_bytes),
                Some((Err("ErrUnequalRValues"), false))
            );
            assert_eq!(
                verify_with(&q, &hash, &r, &s_bytes, Break::SchnorrRModN),
                Some((Ok(()), false))
            );
        }
    }
}
