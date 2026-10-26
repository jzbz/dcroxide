// SPDX-License-Identifier: ISC
//! dcrd's Ed25519 (`dcrec/edwards/v2`) as a model, on this crate's own
//! `curve25519-dalek` arithmetic and SHA-512: key and signature parsing
//! with dcrd's error texts, and the January 2017 `agl/ed25519` verification
//! dcrd's `Verify` calls, with the reason it rejects.
//!
//! Key parsing (`ParsePubKey`, `pubkey.go`):
//!
//! 1. "pubkey string is empty" for no bytes;
//! 2. "malformed public key: invalid length: N" unless 32 bytes;
//! 3. "point not on curve" unless the encoding decodes ([`decode`]: y is
//!    the low 255 bits reduced mod p, x the root of the parity the top bit
//!    asks for);
//! 4. "pubkey X parameter is >= to P" when the top bit asks for the odd
//!    root and the root is zero: dcrd then holds x as P − 0 = P.  Its
//!    "pubkey Y parameter is >= to P" cannot happen, since y is reduced.
//!
//! The parsed key's encoding is canonical whatever the input's was.
//!
//! Signature parsing (`parseSig`, `signature.go`): "bad signature size;
//! have N, want 64" unless 64 bytes; "point not on curve" unless R decodes
//! (R's bytes are kept as they are, decoded only to check them); "s scalar
//! is empty or larger than the order of the curve" unless S, little-endian,
//! is in [1, L − 1].
//!
//! Verification (`Verify`, `ecdsa.go`, which serializes the parsed key and
//! the raw R and S and calls agl's `Verify`, `ed25519.go`):
//!
//! 1. reject when S has any of its top three bits set ([`Reason::TopBitsSet`]);
//! 2. A, the point the key's canonical encoding decodes to, which is the
//!    parsed key's point;
//! 3. k = SHA-512(R ‖ A ‖ m) mod L, over R's bytes as given and A's
//!    canonical encoding;
//! 4. R' = s·B − k·A, A negated as a point, with s the 256-bit integer S,
//!    whose s·B is (s mod L)·B;
//! 5. accept exactly when R' encodes to R's bytes ([`Reason::RMismatch`]
//!    otherwise), so a non-canonical R never verifies.
//!
//! The model computes s·B and k·A apart and subtracts them; it shares no
//! code with the generators or with the code under test.  [`verify_with`]
//! runs the same steps with one [`Break`] switched on, for the canaries.

use std::cmp::Ordering;

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

use crate::arith::{self, ED25519_L, ED25519_P};
use crate::cmd::{Cmd, Request};
use crate::model::Break;

/// dcrd's text for an empty key.
pub const PUBKEY_EMPTY: &str = "pubkey string is empty";

/// dcrd's text for an encoding that does not decode, key or R.
pub const POINT_NOT_ON_CURVE: &str = "point not on curve";

/// dcrd's text for a key encoding x = 0 with the sign bit set.
pub const PUBKEY_X_TOO_BIG: &str = "pubkey X parameter is >= to P";

/// dcrd's text for an S of zero or at or above L.
pub const S_OUT_OF_RANGE: &str = "s scalar is empty or larger than the order of the curve";

/// Why agl's `Verify` rejects a signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    /// S has one of its top three bits set.
    TopBitsSet,
    /// s·B − k·A does not encode to R's bytes.
    RMismatch,
    /// S is zero or at or above L: no reason of agl's, only of the verify
    /// [`Break::Ed25519SRange`] breaks.
    SRange,
}

/// A key dcrd's `ParsePubKey` accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey {
    /// The encoding as given.
    pub encoded: [u8; 32],
    /// Its canonical encoding, which dcrd serializes, answers and hashes.
    pub canonical: [u8; 32],
    /// The point both encode, which verification takes as A.
    pub point: EdwardsPoint,
}

/// The point an encoding names, as agl's `FromBytes` decodes it: y is the
/// low 255 bits reduced mod p, x the root of x² = (y² − 1)/(dy² + 1) whose
/// parity the top bit names (zero when the root is zero, whatever the
/// bit).  `None` when (y² − 1)/(dy² + 1) is no square.  curve25519-dalek's
/// decompression is that rule.
pub fn decode(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    CompressedEdwardsY(*bytes).decompress()
}

/// Whether a canonical encoding's point has x = 0: x² = (y² − 1)/(dy² + 1)
/// vanishes exactly when y = 1 or y = p − 1.
fn x_is_zero(canonical: &[u8; 32]) -> bool {
    let mut y = *canonical;
    y[31] &= 0x7f;
    y == arith::le_from_u64(1) || y == arith::sub_le(&ED25519_P, &arith::le_from_u64(1)).0
}

/// dcrd's `ParsePubKey`: the key, or dcrd's error text.
pub fn parse_pub_key(key: &[u8]) -> Result<PublicKey, String> {
    if key.is_empty() {
        return Err(PUBKEY_EMPTY.to_owned());
    }
    let encoded: [u8; 32] = key
        .try_into()
        .map_err(|_| format!("malformed public key: invalid length: {}", key.len()))?;
    let point = decode(&encoded).ok_or_else(|| POINT_NOT_ON_CURVE.to_owned())?;
    let canonical = point.compress().to_bytes();
    if encoded[31] & 0x80 != 0 && x_is_zero(&canonical) {
        return Err(PUBKEY_X_TOO_BIG.to_owned());
    }
    Ok(PublicKey {
        encoded,
        canonical,
        point,
    })
}

/// dcrd's `ParseSignature`: R ‖ S as given, or dcrd's error text.
pub fn parse_signature(sig: &[u8]) -> Result<[u8; 64], String> {
    let sig: [u8; 64] = sig
        .try_into()
        .map_err(|_| format!("bad signature size; have {}, want 64", sig.len()))?;
    let (r, s) = sig.split_at(32);
    let r: &[u8; 32] = r.try_into().expect("32 bytes");
    let s: &[u8; 32] = s.try_into().expect("32 bytes");
    if decode(r).is_none() {
        return Err(POINT_NOT_ON_CURVE.to_owned());
    }
    if arith::is_zero(s) || arith::cmp_le(s, &ED25519_L) != Ordering::Less {
        return Err(S_OUT_OF_RANGE.to_owned());
    }
    Ok(sig)
}

/// The challenge k = SHA-512(R ‖ A ‖ m) mod L.
fn challenge(r: &[u8], key: &[u8; 32], msg: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    h.update(r);
    h.update(key);
    h.update(msg);
    Scalar::from_bytes_mod_order_wide(&h.finalize().into())
}

/// agl's `Verify` of the raw signature R ‖ S over `msg` for a parsed
/// `key`: `Ok` when it accepts, else the reason it rejects.
pub fn verify(key: &PublicKey, msg: &[u8], sig: &[u8; 64]) -> Result<(), Reason> {
    verify_with(key, msg, sig, Break::None)
}

/// [`verify`] with `brk` switched on: [`Break::Ed25519SRange`] rejects an S
/// of zero or at or above L after step 1; [`Break::Ed25519HashInputKey`]
/// hashes the key's encoding as given at step 3;
/// [`Break::Ed25519ScalarNegation`] computes s·B + (L − k)·A at step 4,
/// which differs from s·B − k·A by L·T for A's torsion component T;
/// [`Break::Ed25519CompareDecodedR`] compares R's decoded point with R' at
/// step 5, so a non-canonical R of the right point verifies.  Any other
/// break is agl's algorithm.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "curve25519-dalek scalar and point operations only: modular group arithmetic, no integer operator here"
)]
pub fn verify_with(key: &PublicKey, msg: &[u8], sig: &[u8; 64], brk: Break) -> Result<(), Reason> {
    let (r, s) = sig.split_at(32);
    let r: &[u8; 32] = r.try_into().expect("32 bytes");
    let s: [u8; 32] = s.try_into().expect("32 bytes");
    // Step 1.
    if s[31] & 0xe0 != 0 {
        return Err(Reason::TopBitsSet);
    }
    if brk == Break::Ed25519SRange
        && (arith::is_zero(&s) || arith::cmp_le(&s, &ED25519_L) != Ordering::Less)
    {
        return Err(Reason::SRange);
    }
    // Steps 2 and 3.
    let a = key.point;
    let hashed = if brk == Break::Ed25519HashInputKey {
        &key.encoded
    } else {
        &key.canonical
    };
    let k = challenge(r, hashed, msg);
    // Step 4.
    let s_b = EdwardsPoint::mul_base(&Scalar::from_bytes_mod_order(s));
    let r_prime = if brk == Break::Ed25519ScalarNegation {
        s_b + (-k) * a
    } else {
        s_b - k * a
    };
    // Step 5.
    let equal = if brk == Break::Ed25519CompareDecodedR {
        decode(r) == Some(r_prime)
    } else {
        r_prime.compress().as_bytes() == r
    };
    if equal {
        Ok(())
    } else {
        Err(Reason::RMismatch)
    }
}

/// The model's answer to an `ed25519_verify` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The key did not parse: dcrd's error text.
    KeyRejected(String),
    /// The key parsed, and [`verify`] answered.
    Verified(Result<(), Reason>),
}

/// The model's outcome for an `ed25519_verify` request (32-byte key ‖ raw
/// 64-byte signature ‖ message): the key parsed as [`parse_pub_key`] does,
/// then [`verify`].  `None` when the request is not an Ed25519 verify
/// request or is too short for its layout.
pub fn verify_request(request: &Request) -> Option<Outcome> {
    if request.cmd != Cmd::Ed25519Verify {
        return None;
    }
    let (key, rest) = request.data.split_first_chunk::<32>()?;
    let (sig, msg) = rest.split_first_chunk::<64>()?;
    Some(match parse_pub_key(key) {
        Ok(key) => Outcome::Verified(verify(&key, msg, sig)),
        Err(text) => Outcome::KeyRejected(text),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd;
    use dcroxide_testutil::unhex;

    fn b32(hex: &str) -> [u8; 32] {
        unhex(hex).try_into().expect("32 bytes")
    }

    fn b64(hex: &str) -> [u8; 64] {
        unhex(hex).try_into().expect("64 bytes")
    }

    /// The first two rows of dcrd's `TestGolden` data
    /// (`testdata/sign.input.gz`, from the Ed25519 reference's
    /// `sign.input`): each verifies, and fails for the reason each edit
    /// gives it.
    #[test]
    fn dcrds_golden_rows_verify() {
        for (key, msg, sig) in [
            (
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
                 5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
                 085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
        ] {
            let key = parse_pub_key(&b32(key)).expect("a valid key");
            assert_eq!(key.canonical, key.encoded);
            let msg = unhex(msg);
            let sig = b64(sig);
            assert_eq!(verify(&key, &msg, &sig), Ok(()));
            assert_eq!(parse_signature(&sig), Ok(sig));

            let mut other = msg.clone();
            other.push(0);
            assert_eq!(verify(&key, &other, &sig), Err(Reason::RMismatch));
            let mut bad_r = sig;
            bad_r[0] ^= 1;
            assert_eq!(verify(&key, &msg, &bad_r), Err(Reason::RMismatch));
            for bits in [0x20, 0x40, 0x80] {
                let mut top = sig;
                top[63] |= bits;
                assert_eq!(verify(&key, &msg, &top), Err(Reason::TopBitsSet));
            }
            // S + j·L for j in 2..=14 names the same s·B as S, so s·B − k·A
            // is still R: only step 1 rejects it.
            let s: [u8; 32] = sig[32..].try_into().expect("32 bytes");
            let mut plus = arith::add_le(&s, &ED25519_L).0;
            for j in 2..=14 {
                plus = arith::add_le(&plus, &ED25519_L).0;
                let mut wrapped = sig;
                wrapped[32..].copy_from_slice(&plus);
                assert_eq!(
                    verify(&key, &msg, &wrapped),
                    Err(Reason::TopBitsSet),
                    "S + {j}L"
                );
            }

            let request = cmd::ed25519_verify(&key.encoded, &sig, &msg);
            assert_eq!(verify_request(&request), Some(Outcome::Verified(Ok(()))));
        }
    }

    /// Parsing's rejections, each with dcrd's text, and its acceptances of
    /// non-canonical encodings, which re-encode canonically.
    #[test]
    fn parsing_follows_dcrds_rules() {
        let le = arith::le_from_u64;
        let p_plus = |v: u64| arith::add_le(&ED25519_P, &le(v)).0;
        let signed = |mut v: [u8; 32]| {
            v[31] |= 0x80;
            v
        };
        assert_eq!(parse_pub_key(&[]), Err(PUBKEY_EMPTY.to_owned()));
        assert_eq!(
            parse_pub_key(&[1; 31]),
            Err("malformed public key: invalid length: 31".to_owned())
        );
        // y = 2 is off the curve.
        assert_eq!(parse_pub_key(&le(2)), Err(POINT_NOT_ON_CURVE.to_owned()));
        // x = 0 (y = 1 and y = p - 1) with the sign bit, either encoding.
        for y in [le(1), p_plus(1), arith::sub_le(&ED25519_P, &le(1)).0] {
            assert_eq!(parse_pub_key(&signed(y)), Err(PUBKEY_X_TOO_BIG.to_owned()));
        }
        // The identity as y = 1 and y = p + 1; an order-4 point as y = p,
        // both signs; each re-encodes canonically.
        let identity = parse_pub_key(&p_plus(1)).expect("y = p + 1");
        assert_eq!(identity.canonical, le(1));
        assert_eq!(identity.encoded, p_plus(1));
        assert_eq!(parse_pub_key(&le(1)).expect("y = 1").point, identity.point);
        let order4 = parse_pub_key(&ED25519_P).expect("y = p");
        assert_eq!(order4.canonical, le(0));
        let other = parse_pub_key(&signed(ED25519_P)).expect("y = p, signed");
        assert_eq!(other.canonical, signed(le(0)));
        assert_ne!(other.point, order4.point);

        assert_eq!(
            parse_signature(&[0; 63]),
            Err("bad signature size; have 63, want 64".to_owned())
        );
        let r = le(1);
        let with_s = |s: [u8; 32]| [r, s].concat();
        assert_eq!(
            parse_signature(&with_s(le(1))).map(|s| s.to_vec()),
            Ok(with_s(le(1)))
        );
        let l_minus_1 = arith::sub_le(&ED25519_L, &le(1)).0;
        assert!(parse_signature(&with_s(l_minus_1)).is_ok());
        for s in [le(0), ED25519_L, [0xff; 32]] {
            assert_eq!(parse_signature(&with_s(s)), Err(S_OUT_OF_RANGE.to_owned()));
        }
        assert_eq!(
            parse_signature(&[le(2), le(1)].concat()),
            Err(POINT_NOT_ON_CURVE.to_owned())
        );
        // R is checked before S: an R that does not decode with an S out
        // of range is refused for R.
        assert_eq!(
            parse_signature(&[le(2), le(0)].concat()),
            Err(POINT_NOT_ON_CURVE.to_owned())
        );
        // R is only decoded: x = 0 with the sign bit, and y + p, both
        // parse and are kept as given.
        for r in [signed(le(1)), p_plus(1), signed(ED25519_P)] {
            let sig = [r, le(1)].concat();
            assert_eq!(parse_signature(&sig).map(|s| s.to_vec()), Ok(sig));
        }

        let short = cmd::ed25519_verify(&le(2), &[0; 64], &[]);
        assert_eq!(
            verify_request(&short),
            Some(Outcome::KeyRejected(POINT_NOT_ON_CURVE.to_owned()))
        );
        assert_eq!(verify_request(&cmd::ed25519_parse(&[0; 96])), None);
        let mut truncated = short;
        truncated.data.truncate(95);
        assert_eq!(verify_request(&truncated), None);
    }

    /// A non-canonical R never verifies: with the identity key and S = 0,
    /// s·B − k·A is the identity, whose canonical encoding verifies and
    /// whose encoding as y = p + 1 does not.
    #[test]
    fn r_is_compared_as_bytes() {
        let le = arith::le_from_u64;
        let key = parse_pub_key(&le(1)).expect("the identity");
        let canonical: [u8; 64] = [le(1), [0; 32]].concat().try_into().expect("64 bytes");
        assert_eq!(verify(&key, b"m", &canonical), Ok(()));
        let p_plus_1 = arith::add_le(&ED25519_P, &le(1)).0;
        let other: [u8; 64] = [p_plus_1, [0; 32]].concat().try_into().expect("64 bytes");
        assert_eq!(verify(&key, b"m", &other), Err(Reason::RMismatch));

        // Comparing R as a point accepts the identity encoded as y = p + 1;
        // rejecting S = 0 rejects the canonical encoding.
        assert_eq!(
            verify_with(&key, b"m", &other, Break::Ed25519CompareDecodedR),
            Ok(())
        );
        assert_eq!(
            verify_with(&key, b"m", &canonical, Break::Ed25519SRange),
            Err(Reason::SRange)
        );
        assert_eq!(
            verify_with(&key, b"m", &canonical, Break::Ed25519CompareDecodedR),
            Ok(())
        );
    }

    /// The first message `m0`, `m1`, ... whose challenges for R = the
    /// identity's canonical encoding meet `want` (keys as given).
    fn grind(keys: [&[u8; 32]; 2], want: impl Fn(u8, u8) -> bool) -> Vec<u8> {
        let r = arith::le_from_u64(1);
        (0u32..4_096)
            .map(|i| format!("m{i}").into_bytes())
            .find(|m| {
                let residue = |key| challenge(&r, key, m).as_bytes()[0] & 7;
                want(residue(keys[0]), residue(keys[1]))
            })
            .expect("one in eight messages meets each residue")
    }

    /// The scalar-negation and input-key breaks change verification only
    /// where the key has a torsion component: with A of order 8 (or 4), a
    /// zero S and R the identity, agl accepts exactly when k·A is the
    /// identity, the negated scalar computes (L − k)·A = (5 − k)·A, and the
    /// input-key hash draws another k.  An S + L that agl accepts is out of
    /// range for the S-range break.
    #[test]
    fn breaks_change_their_step() {
        use curve25519_dalek::constants::EIGHT_TORSION;
        let le = arith::le_from_u64;
        let identity_r: [u8; 64] = [le(1), [0; 32]].concat().try_into().expect("64 bytes");

        let t8 = EIGHT_TORSION[1].compress().to_bytes();
        let key = parse_pub_key(&t8).expect("an order-8 point");
        let m = grind([&t8, &t8], |k, _| k == 0);
        assert_eq!(verify(&key, &m, &identity_r), Ok(()));
        assert_eq!(
            verify_with(&key, &m, &identity_r, Break::Ed25519ScalarNegation),
            Err(Reason::RMismatch)
        );
        for brk in [
            Break::Ed25519HashInputKey,
            Break::Ed25519CompareDecodedR,
            Break::SchnorrRModN,
        ] {
            assert_eq!(verify_with(&key, &m, &identity_r, brk), Ok(()), "{brk:?}");
        }

        // An order-4 point encoded as y = p: its canonical encoding is
        // y = 0, and the challenge over the input bytes differs.
        let key = parse_pub_key(&ED25519_P).expect("y = p");
        assert_eq!(key.canonical, le(0));
        let m = grind([&key.canonical, &key.encoded], |canonical, input| {
            canonical & 3 == 0 && input & 3 != 0
        });
        assert_eq!(verify(&key, &m, &identity_r), Ok(()));
        assert_eq!(
            verify_with(&key, &m, &identity_r, Break::Ed25519HashInputKey),
            Err(Reason::RMismatch)
        );

        // S + L verifies as S does, and is out of range.
        let key = parse_pub_key(&b32(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        ))
        .expect("a valid key");
        let mut sig = b64(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );
        let s: [u8; 32] = sig[32..].try_into().expect("32 bytes");
        sig[32..].copy_from_slice(&arith::add_le(&s, &ED25519_L).0);
        assert_eq!(verify(&key, &[], &sig), Ok(()));
        assert_eq!(
            verify_with(&key, &[], &sig, Break::Ed25519SRange),
            Err(Reason::SRange)
        );
    }

    /// The crate's Ed25519 constants are curve25519-dalek's: L is the group
    /// order (L − 1 is the largest canonical scalar, and L reduces to
    /// zero), and p the field prime (y = p decodes as y = 0, and y = p − 1
    /// re-encodes as itself).
    #[test]
    fn the_constants_are_the_curves() {
        let le = arith::le_from_u64;
        let l_minus_1 = arith::sub_le(&ED25519_L, &le(1)).0;
        assert!(bool::from(
            Scalar::from_canonical_bytes(l_minus_1).is_some()
        ));
        assert!(bool::from(
            Scalar::from_canonical_bytes(ED25519_L).is_none()
        ));
        assert_eq!(Scalar::from_bytes_mod_order(ED25519_L), Scalar::ZERO);
        assert_eq!(decode(&ED25519_P), decode(&le(0)));
        let p_minus_1 = arith::sub_le(&ED25519_P, &le(1)).0;
        let point = decode(&p_minus_1).expect("y = p - 1 is on the curve");
        assert_eq!(point.compress().to_bytes(), p_minus_1);
    }
}
