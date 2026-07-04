// SPDX-License-Identifier: ISC
//! Ed25519 signatures (Decred signature type 1), mirroring dcrd
//! `dcrec/edwards/v2` (v2.0.4) — including its exact acceptance semantics,
//! which are those of the January 2017 `agl/ed25519` code it delegates to
//! plus dcrd's own parse-time validation. Verifier behavior differences are
//! exactly where Ed25519 reimplementations diverge (project brief risk R4),
//! so nothing here relies on a packaged verifier: the checks are implemented
//! explicitly on `curve25519-dalek` primitives and pinned differentially.
//!
//! The load-bearing quirks, all reproduced and differentially tested:
//!
//! - Signature parsing requires the R component to decode as a curve point.
//!   Non-canonical encodings (y >= p, or x = 0 with the sign bit set) are
//!   *accepted* — decoding reduces y mod p and ignores the impossible sign.
//! - Public key parsing performs the same decode but *rejects* x = 0 with
//!   the sign bit set (dcrd represents that x as the unreduced big integer
//!   P, tripping its `X >= P` check). Parsed keys re-serialize canonically,
//!   and verification hashes the canonical form, not the input bytes.
//! - Raw verification (dcrd `edwards.Verify`, reachable with components that
//!   skip parse validation) checks only that the top three bits of S are
//!   clear — the 2017-agl behavior predating full `s < L` enforcement — and
//!   is cofactorless, comparing the re-encoded commitment point byte-wise.
//!   Full `s ∈ [1, L)` enforcement happens at *parse* time, which is the
//!   path consensus takes.

// The flagged operators are curve25519-dalek scalar/point operations —
// modular group arithmetic by definition; overflow is not representable.
// The one byte-level addition (test-only s + L) checks its carry.
#![allow(clippy::arithmetic_side_effects)]

use core::fmt;

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

/// The length of a serialized public key in bytes.
pub const PUB_KEY_BYTES_LEN: usize = 32;

/// The length of a serialized signature in bytes.
pub const SIGNATURE_SIZE: usize = 64;

/// Ed25519 parsing errors. dcrd's edwards package uses plain error strings
/// rather than kinds, so differential tests compare verdicts only; the
/// variants exist for our callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The public key is empty (dcrd checks this before the length).
    PubKeyEmpty,
    /// The public key is not exactly 32 bytes.
    PubKeyInvalidLen(usize),
    /// The public key encodes x = 0 with the sign bit set, which dcrd
    /// rejects via its `X >= P` check.
    PubKeyXTooBig,
    /// The encoding does not decode to a curve point.
    PointNotOnCurve,
    /// The signature is not exactly 64 bytes.
    SigBadLen(usize),
    /// The signature S component is zero or >= the group order.
    SigSInvalid,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::PubKeyEmpty => f.write_str("pubkey string is empty"),
            Error::PubKeyInvalidLen(len) => {
                write!(f, "malformed public key: invalid length: {len}")
            }
            Error::PubKeyXTooBig => f.write_str("pubkey X parameter is >= to P"),
            Error::PointNotOnCurve => f.write_str("point not on curve"),
            Error::SigBadLen(len) => {
                write!(f, "bad signature size; have {len}, want 64")
            }
            Error::SigSInvalid => {
                f.write_str("s scalar is empty or larger than the order of the curve")
            }
        }
    }
}

impl core::error::Error for Error {}

/// A validated Ed25519 public key.
///
/// Holds the decoded point plus its canonical serialization: like dcrd,
/// keys parsed from non-canonical encodings re-serialize canonically, and
/// the canonical bytes are what verification hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey {
    point: EdwardsPoint,
    compressed: [u8; PUB_KEY_BYTES_LEN],
}

impl PublicKey {
    /// The canonical 32-byte serialization (dcrd `PublicKey.Serialize`).
    pub fn serialize(&self) -> [u8; PUB_KEY_BYTES_LEN] {
        self.compressed
    }
}

/// Parse a public key with dcrd's exact acceptance rules
/// (`edwards.ParsePubKey`): exactly 32 bytes decoding to a curve point.
/// Non-canonical y encodings are accepted (and re-serialize canonically);
/// x = 0 with the sign bit set is rejected (the dcrd `X >= P` quirk).
pub fn parse_pub_key(serialized: &[u8]) -> Result<PublicKey, Error> {
    if serialized.is_empty() {
        return Err(Error::PubKeyEmpty);
    }
    if serialized.len() != PUB_KEY_BYTES_LEN {
        return Err(Error::PubKeyInvalidLen(serialized.len()));
    }
    let bytes: [u8; 32] = serialized.try_into().expect("32 bytes");

    let point = CompressedEdwardsY(bytes)
        .decompress()
        .ok_or(Error::PointNotOnCurve)?;
    let canonical = point.compress().to_bytes();

    // Decompression applies the requested x sign, so the canonical sign bit
    // matches the input's — except when x = 0, where the "negative" request
    // is impossible. dcrd materializes that case as the unreduced integer P
    // and rejects it with its X >= P check.
    if bytes[31] >> 7 == 1 && canonical[31] >> 7 == 0 {
        return Err(Error::PubKeyXTooBig);
    }

    Ok(PublicKey {
        point,
        compressed: canonical,
    })
}

/// An Ed25519 signature: R (a point encoding) and S (a scalar), each 32
/// little-endian bytes, stored exactly as parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    r: [u8; 32],
    s: [u8; 32],
}

impl Signature {
    /// The R component bytes.
    pub fn r_bytes(&self) -> &[u8; 32] {
        &self.r
    }

    /// The S component bytes.
    pub fn s_bytes(&self) -> &[u8; 32] {
        &self.s
    }

    /// The 64-byte `R || S` serialization (dcrd `Signature.Serialize`).
    pub fn serialize(&self) -> [u8; SIGNATURE_SIZE] {
        let mut out = [0u8; SIGNATURE_SIZE];
        out[..32].copy_from_slice(&self.r);
        out[32..].copy_from_slice(&self.s);
        out
    }

    /// Whether the signature is valid for the message and public key (dcrd
    /// `Signature.Verify`). The message is the raw bytes dcrd passes (the
    /// 32-byte sighash in consensus, but any length is accepted, matching
    /// dcrd).
    pub fn verify(&self, message: &[u8], pub_key: &PublicKey) -> bool {
        verify_raw(pub_key, message, &self.serialize())
    }
}

/// Parse a signature with dcrd's exact rules (`edwards.ParseSignature`):
/// exactly 64 bytes; R must decode as a curve point (non-canonical
/// encodings accepted — including x = 0 with the sign bit set, which the
/// *pubkey* parser rejects); S must be in `[1, L-1]`.
pub fn parse_signature(sig: &[u8]) -> Result<Signature, Error> {
    if sig.len() != SIGNATURE_SIZE {
        return Err(Error::SigBadLen(sig.len()));
    }
    let r: [u8; 32] = sig[..32].try_into().expect("32 bytes");
    let s: [u8; 32] = sig[32..].try_into().expect("32 bytes");

    // R must decode as a point; the decoded value is discarded — the raw
    // bytes are kept, exactly like dcrd's big.Int round trip.
    CompressedEdwardsY(r)
        .decompress()
        .ok_or(Error::PointNotOnCurve)?;

    // S interpreted as a 256-bit little-endian integer must be canonical
    // (< L) and nonzero.
    let s_scalar: Option<Scalar> = Scalar::from_canonical_bytes(s).into();
    match s_scalar {
        Some(scalar) if scalar != Scalar::ZERO => {}
        _ => return Err(Error::SigSInvalid),
    }

    Ok(Signature { r, s })
}

/// Verify raw signature bytes against a public key, reproducing dcrd's
/// `edwards.Verify` → 2017-`agl/ed25519` semantics exactly: reject if the
/// top three bits of S are set (no full range check at this layer);
/// cofactorless equation with the commitment recomputed as `S·B - k·A` and
/// compared byte-wise against the R bytes.
///
/// This is reachable in dcrd with components that never went through
/// `ParseSignature` (e.g. `NewSignature`), which is why S values in
/// `[L, 2^253)` verify here; the consensus path always parses first.
pub fn verify_raw(pub_key: &PublicKey, message: &[u8], sig: &[u8; SIGNATURE_SIZE]) -> bool {
    if sig[63] & 224 != 0 {
        return false;
    }

    // k = SHA-512(R || A || m) mod L, hashing the canonical key encoding
    // (dcrd re-serializes the parsed key before hashing).
    let mut h = Sha512::new();
    h.update(&sig[..32]);
    h.update(pub_key.compressed);
    h.update(message);
    let k = Scalar::from_bytes_mod_order_wide(&h.finalize().into());

    // R' = s*B - k*A; the scalar multiplication implicitly reduces any
    // s >= L, matching the byte-driven ladder in agl/ed25519.
    let s_bytes: [u8; 32] = sig[32..].try_into().expect("32 bytes");
    let s = Scalar::from_bytes_mod_order(s_bytes);
    let r_prime = EdwardsPoint::vartime_double_scalar_mul_basepoint(&-k, &pub_key.point, &s);

    r_prime.compress().as_bytes() == &sig[..32]
}

/// A standard Ed25519 secret: the 32-byte seed (dcrd `PrivKeyFromSecret`).
/// The scalar-based signing flavor dcrd also carries (`PrivKeyFromScalar`,
/// `SignFromScalar`) is wallet-side legacy and intentionally not
/// implemented; see PARITY.md.
#[derive(Clone)]
pub struct SecretKey {
    seed: [u8; 32],
}

impl SecretKey {
    /// Wrap a 32-byte seed.
    pub fn from_seed(seed: [u8; 32]) -> SecretKey {
        SecretKey { seed }
    }

    /// The corresponding public key (`A = clamp(SHA-512(seed)[..32])·B`).
    pub fn public_key(&self) -> PublicKey {
        let (a, _) = self.expand();
        let point = ED25519_BASEPOINT_TABLE * &a;
        PublicKey {
            point,
            compressed: point.compress().to_bytes(),
        }
    }

    /// The clamped secret scalar and the hash prefix used for nonces.
    fn expand(&self) -> (Scalar, [u8; 32]) {
        let digest: [u8; 64] = Sha512::digest(self.seed).into();
        let mut a_bytes: [u8; 32] = digest[..32].try_into().expect("32 bytes");
        a_bytes[0] &= 248;
        a_bytes[31] &= 127;
        a_bytes[31] |= 64;
        let prefix: [u8; 32] = digest[32..].try_into().expect("32 bytes");
        (Scalar::from_bytes_mod_order(a_bytes), prefix)
    }
}

/// Produce a standard (RFC 8032) Ed25519 signature over the message,
/// byte-compatible with dcrd's seed-based `edwards.Sign` path (verified
/// differentially).
pub fn sign(secret: &SecretKey, message: &[u8]) -> Signature {
    let pub_bytes = secret.public_key().compressed;
    sign_with_pub_key_bytes(secret, &pub_bytes, message)
}

/// Sign with an explicitly provided public key encoding used as `A` in the
/// commitment hash, reproducing the 2017-`agl` `ed25519.Sign` over a
/// 64-byte `seed || pubkey` private key — the path dcrd's
/// `edwards.PrivKeyFromBytes` + `Sign` takes, where the embedded public
/// key (canonically re-serialized) participates rather than one derived
/// from the seed. With a matching public key this is identical to
/// [`sign`].
pub fn sign_with_pub_key_bytes(
    secret: &SecretKey,
    pub_bytes: &[u8; 32],
    message: &[u8],
) -> Signature {
    let (a, prefix) = secret.expand();

    // r = SHA-512(prefix || m) mod L; R = r·B.
    let mut h = Sha512::new();
    h.update(prefix);
    h.update(message);
    let r = Scalar::from_bytes_mod_order_wide(&h.finalize().into());
    let big_r = (ED25519_BASEPOINT_TABLE * &r).compress().to_bytes();

    // k = SHA-512(R || A || m) mod L; s = k*a + r.
    let mut h = Sha512::new();
    h.update(big_r);
    h.update(pub_bytes);
    h.update(message);
    let k = Scalar::from_bytes_mod_order_wide(&h.finalize().into());
    let s = k * a + r;

    Signature {
        r: big_r,
        s: s.to_bytes(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcroxide_testutil::unhex;

    /// RFC 8032 section 7.1 TEST 1: empty message.
    #[test]
    fn rfc8032_test_1() {
        let seed: [u8; 32] =
            unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .try_into()
                .expect("32 bytes");
        let secret = SecretKey::from_seed(seed);

        let pub_key = secret.public_key();
        assert_eq!(
            dcroxide_testutil::hex(&pub_key.serialize()),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );

        let sig = sign(&secret, b"");
        assert_eq!(
            dcroxide_testutil::hex(&sig.serialize()),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        assert!(sig.verify(b"", &pub_key));

        // Round trip through parse.
        let parsed = parse_signature(&sig.serialize()).expect("own signature parses");
        assert_eq!(parsed, sig);
    }

    #[test]
    fn pubkey_parse_quirks() {
        // (0, 1) is the identity: y = 1 with sign bit clear parses (x = 0
        // is a legal coordinate)...
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert!(parse_pub_key(&identity).is_ok());

        // ...but the same y with the sign bit set trips dcrd's X >= P check.
        let mut bad = identity;
        bad[31] |= 0x80;
        assert_eq!(parse_pub_key(&bad), Err(Error::PubKeyXTooBig));

        // Non-canonical y (y = p + 1, i.e. 1 mod p) is accepted and
        // re-serializes canonically as the identity encoding.
        let mut noncanonical = [0xffu8; 32];
        noncanonical[0] = 0xee; // p + 1 = 2^255 - 18 little-endian
        noncanonical[31] = 0x7f;
        let parsed = parse_pub_key(&noncanonical).expect("non-canonical y accepted");
        assert_eq!(parsed.serialize(), identity);

        // Length errors, empty first.
        assert_eq!(parse_pub_key(&[]), Err(Error::PubKeyEmpty));
        assert_eq!(parse_pub_key(&[0u8; 31]), Err(Error::PubKeyInvalidLen(31)));
    }

    #[test]
    fn signature_parse_quirks() {
        let secret = SecretKey::from_seed([7u8; 32]);
        let sig = sign(&secret, b"quirks").serialize();

        // Signature R accepts what pubkey parsing rejects: x = 0 with the
        // sign bit set.
        let mut x0_sign1 = sig;
        x0_sign1[..32].fill(0);
        x0_sign1[0] = 1; // R = (0, 1) encoding
        x0_sign1[31] |= 0x80; // impossible sign
        assert!(parse_signature(&x0_sign1).is_ok());

        // S = 0 rejected; S = L rejected; S = L - 1 accepted.
        let ell: [u8; 32] =
            unhex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
                .try_into()
                .expect("32 bytes");
        let mut s_zero = sig;
        s_zero[32..].fill(0);
        assert_eq!(parse_signature(&s_zero), Err(Error::SigSInvalid));
        let mut s_ell = sig;
        s_ell[32..].copy_from_slice(&ell);
        assert_eq!(parse_signature(&s_ell), Err(Error::SigSInvalid));
        let mut s_ell_minus_1 = sig;
        let mut ell_minus_1 = ell;
        ell_minus_1[0] -= 1;
        s_ell_minus_1[32..].copy_from_slice(&ell_minus_1);
        assert!(parse_signature(&s_ell_minus_1).is_ok());

        // Wrong lengths.
        assert_eq!(parse_signature(&sig[..63]), Err(Error::SigBadLen(63)));
    }

    #[test]
    fn raw_verify_agl_semantics() {
        let secret = SecretKey::from_seed([9u8; 32]);
        let pub_key = secret.public_key();
        let msg = b"malleability";
        let sig = sign(&secret, msg);

        // The s + L malleated form fails *parse*, but raw verification
        // accepts it (2017-agl semantics: only the top three bits of S are
        // checked). This mirrors dcrd exactly and is confirmed against the
        // oracle differentially.
        let ell = unhex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
        let mut s_plus_ell = [0u8; 32];
        let mut carry = 0u16;
        for i in 0..32 {
            let sum = u16::from(sig.s_bytes()[i]) + u16::from(ell[i]) + carry;
            s_plus_ell[i] = sum as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0, "s + L fits 256 bits");

        let mut malleated = sig.serialize();
        malleated[32..].copy_from_slice(&s_plus_ell);
        assert!(parse_signature(&malleated).is_err(), "parse rejects s >= L");
        if s_plus_ell[31] & 224 == 0 {
            assert!(
                verify_raw(&pub_key, msg, &malleated),
                "raw verify accepts s + L when the top bits stay clear"
            );
        }

        // Top-three-bits check.
        let mut top_bits = sig.serialize();
        top_bits[63] |= 0xE0;
        assert!(!verify_raw(&pub_key, msg, &top_bits));

        // Ordinary negative cases.
        assert!(!sig.verify(b"other message", &pub_key));
        let other = SecretKey::from_seed([10u8; 32]).public_key();
        assert!(!sig.verify(msg, &other));
    }
}
