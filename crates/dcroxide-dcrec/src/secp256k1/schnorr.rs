// SPDX-License-Identifier: ISC
//! EC-Schnorr-DCRv0 signatures (Decred signature type 2), mirroring dcrd
//! `dcrec/secp256k1/v4/schnorr`.
//!
//! This is Decred's own Schnorr scheme — not BIP340: the challenge is
//! `BLAKE-256(R.x || m)` (rejected if >= N), R.y is forced even by nonce
//! negation, `s = k - e*d`, signatures are 64 raw bytes `r || s`, and public
//! keys are ordinary 33-byte compressed keys.
//!
//! Curve arithmetic uses the pure-Rust `k256` backend per ADR-0006 (the
//! scheme needs raw scalar/point operations no packaged API exposes);
//! correctness is pinned by dcrd's test vectors and live differential tests.

// The flagged operators are k256 scalar/point operations, which are modular
// group arithmetic by definition — overflow is not a representable state.
#![allow(clippy::arithmetic_side_effects)]

use core::fmt;

use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::group::Group;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};

use super::nonce::nonce_rfc6979;
use super::{FIELD_PRIME_BYTES, GROUP_ORDER_BYTES, PrivateKey, PublicKey};

/// The size of an encoded EC-Schnorr-DCRv0 signature in bytes.
pub const SIGNATURE_SIZE: usize = 64;

/// Extra data fed to RFC6979 nonce generation to domain-separate
/// EC-Schnorr-DCRv0 nonces from other schemes; equals
/// `BLAKE-256("EC-Schnorr-DCRv0")` (dcrd `rfc6979ExtraDataV0`).
const RFC6979_EXTRA_DATA_V0: [u8; 32] = [
    0x0b, 0x75, 0xf9, 0x7b, 0x60, 0xe8, 0xa5, 0x76, 0x28, 0x76, 0xc0, 0x04, 0x82, 0x9e, 0xe9, 0xb9,
    0x26, 0xfa, 0x6f, 0x0d, 0x2e, 0xea, 0xec, 0x3a, 0x4f, 0xd1, 0x44, 0x6a, 0x76, 0x83, 0x31, 0xcb,
];

/// EC-Schnorr-DCRv0 errors, 1:1 with dcrd `schnorr.ErrorKind` (kinds that
/// are unreachable through this API — `ErrPrivateKeyIsZero`,
/// `ErrPubKeyNotOnCurve` — are excluded because our key types cannot
/// represent those states; see PARITY.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The message hash is not 32 bytes (`ErrInvalidHashLen`).
    InvalidHashLen,
    /// `BLAKE-256(r || m)` is >= the group order (`ErrSchnorrHashValue`).
    SchnorrHashValue,
    /// The calculated R point has an odd Y coordinate (`ErrSigRYIsOdd`).
    SigRYIsOdd,
    /// The calculated R point is the point at infinity
    /// (`ErrSigRNotOnCurve`).
    SigRNotOnCurve,
    /// The calculated R.x does not match the signature's r
    /// (`ErrUnequalRValues`).
    UnequalRValues,
    /// The signature is shorter than 64 bytes (`ErrSigTooShort`).
    SigTooShort,
    /// The signature is longer than 64 bytes (`ErrSigTooLong`).
    SigTooLong,
    /// The r component is >= the field prime (`ErrSigRTooBig`).
    SigRTooBig,
    /// The s component is >= the group order (`ErrSigSTooBig`).
    SigSTooBig,
}

impl Error {
    /// The dcrd error kind name, used for differential comparison.
    pub fn kind_name(self) -> &'static str {
        match self {
            Error::InvalidHashLen => "ErrInvalidHashLen",
            Error::SchnorrHashValue => "ErrSchnorrHashValue",
            Error::SigRYIsOdd => "ErrSigRYIsOdd",
            Error::SigRNotOnCurve => "ErrSigRNotOnCurve",
            Error::UnequalRValues => "ErrUnequalRValues",
            Error::SigTooShort => "ErrSigTooShort",
            Error::SigTooLong => "ErrSigTooLong",
            Error::SigRTooBig => "ErrSigRTooBig",
            Error::SigSTooBig => "ErrSigSTooBig",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kind_name())
    }
}

impl core::error::Error for Error {}

/// An EC-Schnorr-DCRv0 signature: `r` is the X coordinate of the commitment
/// point (a field element in `[0, P-1]`), `s` a scalar in `[0, N-1]`, both
/// as 32 big-endian bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    r: [u8; 32],
    s: [u8; 32],
}

impl Signature {
    /// Construct from raw component bytes; `None` if `r` >= the field prime
    /// or `s` >= the group order.
    pub fn new(r: [u8; 32], s: [u8; 32]) -> Option<Signature> {
        if r >= FIELD_PRIME_BYTES || s >= GROUP_ORDER_BYTES {
            return None;
        }
        Some(Signature { r, s })
    }

    /// The r component as 32 big-endian bytes.
    pub fn r_bytes(&self) -> &[u8; 32] {
        &self.r
    }

    /// The s component as 32 big-endian bytes.
    pub fn s_bytes(&self) -> &[u8; 32] {
        &self.s
    }

    /// The 64-byte `r || s` serialization (dcrd `Signature.Serialize`).
    pub fn serialize(&self) -> [u8; SIGNATURE_SIZE] {
        let mut out = [0u8; SIGNATURE_SIZE];
        out[..32].copy_from_slice(&self.r);
        out[32..].copy_from_slice(&self.s);
        out
    }

    /// Whether the signature is valid for the hash and public key (dcrd
    /// `Signature.Verify`). Returns `false` for any hash that is not
    /// exactly 32 bytes, matching dcrd.
    pub fn verify(&self, hash: &[u8], pub_key: &PublicKey) -> bool {
        self.verify_detailed(hash, pub_key).is_ok()
    }

    /// Verification with the specific dcrd failure reason (mirrors dcrd's
    /// internal `schnorrVerify`; dcrd only exports the boolean form).
    pub fn verify_detailed(&self, hash: &[u8], pub_key: &PublicKey) -> Result<(), Error> {
        // Step 1: the message hash must be 32 bytes. Steps 2-4 (pubkey on
        // curve, r < p, s < n) hold by construction of our types.
        if hash.len() != 32 {
            return Err(Error::InvalidHashLen);
        }

        // Step 5-6: e = BLAKE-256(r || m), rejected if >= n.
        let e = challenge(&self.r, hash).ok_or(Error::SchnorrHashValue)?;

        // Step 7: R = s*G + e*Q.
        let s = Scalar::from_repr(self.s.into()).expect("s < n by construction");
        let q = pub_key.as_k256_point();
        let big_r = ProjectivePoint::GENERATOR * s + q * e;

        // Step 8: fail if R is the point at infinity.
        if bool::from(big_r.is_identity()) {
            return Err(Error::SigRNotOnCurve);
        }

        // Step 9: fail if R.y is odd.
        let affine = big_r.to_affine();
        let encoded = affine.to_encoded_point(false);
        let y = encoded.y().expect("non-identity affine point has y");
        if y[31] & 1 == 1 {
            return Err(Error::SigRYIsOdd);
        }

        // Step 10: verified iff R.x == r.
        let x = encoded.x().expect("non-identity affine point has x");
        if x[..] != self.r {
            return Err(Error::UnequalRValues);
        }
        Ok(())
    }
}

/// `BLAKE-256(r || m)` as a scalar; `None` if the digest is >= the group
/// order (the EC-Schnorr-DCRv0 rejection case).
fn challenge(r: &[u8; 32], hash: &[u8]) -> Option<Scalar> {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(r);
    input[32..].copy_from_slice(hash);
    let commitment = dcroxide_crypto::blake256::sum256(&input);
    // from_repr rejects values >= n, which is exactly dcrd's overflow check.
    Option::from(Scalar::from_repr(commitment.into()))
}

/// Parse a 64-byte `r || s` signature with dcrd's exact rules
/// (`schnorr.ParseSignature`): r must be a canonical field element and s a
/// canonical scalar (zero allowed for both; verification rejects what it
/// must).
pub fn parse_signature(sig: &[u8]) -> Result<Signature, Error> {
    if sig.len() < SIGNATURE_SIZE {
        return Err(Error::SigTooShort);
    }
    if sig.len() > SIGNATURE_SIZE {
        return Err(Error::SigTooLong);
    }
    let r: [u8; 32] = sig[..32].try_into().expect("32 bytes");
    let s: [u8; 32] = sig[32..].try_into().expect("32 bytes");
    if r >= FIELD_PRIME_BYTES {
        return Err(Error::SigRTooBig);
    }
    if s >= GROUP_ORDER_BYTES {
        return Err(Error::SigSTooBig);
    }
    Ok(Signature { r, s })
}

/// Sign `hash` with the given nonce scalar bytes (dcrd's internal
/// `schnorrSign`); fails with [`Error::SchnorrHashValue`] when the challenge
/// overflows, which the public [`sign`] retries with the next nonce.
fn sign_with_nonce(
    priv_scalar: &Scalar,
    nonce: &[u8; 32],
    hash: &[u8; 32],
) -> Result<Signature, Error> {
    // Step 4: R = kG.
    let mut k = Scalar::from_repr((*nonce).into()).expect("nonce is a valid scalar");
    let big_r = (ProjectivePoint::GENERATOR * k).to_affine();
    let encoded = big_r.to_encoded_point(false);

    // Step 5: negate k if R.y is odd.
    let y = encoded.y().expect("kG is never the identity for k != 0");
    if y[31] & 1 == 1 {
        k = -k;
    }

    // Step 6: r = R.x.
    let x = encoded.x().expect("affine point has x");
    let mut r = [0u8; 32];
    r.copy_from_slice(x);

    // Steps 7-8: e = BLAKE-256(r || m), retry on overflow.
    let e = challenge(&r, hash).ok_or(Error::SchnorrHashValue)?;

    // Step 9: s = k - e*d mod n.
    let s = k - e * priv_scalar;

    Ok(Signature {
        r,
        s: s.to_bytes().into(),
    })
}

/// Produce a deterministic EC-Schnorr-DCRv0 signature (dcrd `schnorr.Sign`),
/// byte-compatible with dcrd (verified differentially). The only reachable
/// error is [`Error::InvalidHashLen`] for a hash that is not 32 bytes; the
/// astronomically rare challenge-overflow case retries with the next
/// RFC6979 nonce exactly as dcrd does.
pub fn sign(priv_key: &PrivateKey, hash: &[u8]) -> Result<Signature, Error> {
    // Step 1: the hash must be 32 bytes. Step 2 (d != 0) holds by
    // construction of PrivateKey.
    let hash: &[u8; 32] = hash.try_into().map_err(|_| Error::InvalidHashLen)?;

    let priv_bytes = priv_key.inner().secret_bytes();
    let priv_scalar = Scalar::from_repr(priv_bytes.into()).expect("private key is a valid scalar");

    // Step 3 + retry loop: RFC6979 nonces domain-separated for this scheme.
    let mut iteration = 0u32;
    loop {
        let nonce = nonce_rfc6979(
            &priv_bytes,
            hash,
            Some(&RFC6979_EXTRA_DATA_V0),
            None,
            iteration,
        );
        match sign_with_nonce(&priv_scalar, &nonce, hash) {
            Ok(sig) => return Ok(sig),
            Err(_) => iteration = iteration.wrapping_add(1),
        }
    }
}

/// Errors from [`parse_pub_key`], mirroring dcrd `schnorr.ParsePubKey`
/// (which uses plain errors rather than kinds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PubKeyError {
    /// The serialization is not exactly 33 bytes.
    InvalidLen(usize),
    /// The format byte is not a compressed-key format (0x02/0x03).
    NotCompressed(u8),
    /// The key failed standard secp256k1 parsing.
    Invalid(super::Error),
}

impl fmt::Display for PubKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PubKeyError::InvalidLen(len) => {
                write!(f, "bad pubkey byte string size (want 33, have {len})")
            }
            PubKeyError::NotCompressed(_) => f.write_str("wrong pubkey type (not compressed)"),
            PubKeyError::Invalid(err) => err.fmt(f),
        }
    }
}

impl core::error::Error for PubKeyError {}

/// Parse a public key for EC-Schnorr-DCRv0 use: the scheme accepts only the
/// 33-byte compressed format (dcrd `schnorr.ParsePubKey`).
pub fn parse_pub_key(serialized: &[u8]) -> Result<PublicKey, PubKeyError> {
    if serialized.len() != 33 {
        return Err(PubKeyError::InvalidLen(serialized.len()));
    }
    let format = serialized[0];
    if format & !1u8 != 0x02 {
        return Err(PubKeyError::NotCompressed(format));
    }
    PublicKey::parse(serialized).map_err(PubKeyError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcroxide_testutil::unhex;

    fn key(hex: &str) -> PrivateKey {
        let bytes: [u8; 32] = unhex(hex).try_into().expect("32 bytes");
        PrivateKey::from_bytes(&bytes).expect("valid key")
    }

    fn arr32(hex: &str) -> [u8; 32] {
        unhex(hex).try_into().expect("32 bytes")
    }

    /// Ported from dcrd's TestSchnorrSignAndVerify: RFC6979-nonce rows
    /// exercise the full public sign path (and pin our nonce generation via
    /// the expected signatures); each signature must also verify.
    #[test]
    fn sign_and_verify_vectors_rfc6979() {
        // (name, key, hash, expected nonce, expected sig)
        let cases = [
            (
                "key 0x1, blake256(0x01020304)",
                "0000000000000000000000000000000000000000000000000000000000000001",
                "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
                "d4e18f08eb87073cb2a6707def02007315f7349c3c132590a0088fefece557ef",
                "4c68976afe187ff0167919ad181cb30f187e2af1c8233b2cbebbbe0fc97fff61e9ae2d0e306497236d4e328dc1a34244045745e87da69d806859348bc2a74525",
            ),
            (
                "key 0x2, blake256(0x01020304)",
                "0000000000000000000000000000000000000000000000000000000000000002",
                "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
                "341682d3064ec802646be9c4a0fd97f8480807fcac3179e97098b8597de909dc",
                "c6deb3a26c08842612bfd4411a91c90f64cfea2206c758cd1352ff2b93cc3611c9ffe5dd240f52d3ee199e29373030a5d795b674cd4da991fd07f5edefc3817d",
            ),
            (
                "key 0x1, blake256(0x0102030405)",
                "0000000000000000000000000000000000000000000000000000000000000001",
                "dc063eba3c8d52a159e725c1a161506f6cb6b53478ad5ef3f08d534efa871d9f",
                "cfbabebb15824ff3cfa5f4080a8608aaa9db891541851b27275c61db9d6d7e1c",
                "461646005002d673c2e903f3c9ff2c2455e60810445ee486b9c36152287bc41a1b54733190ed128e466c5263a404f17344b73426d7faf00325c7a0af04be6cfe",
            ),
            (
                "key 0x2, blake256(0x0102030405)",
                "0000000000000000000000000000000000000000000000000000000000000002",
                "dc063eba3c8d52a159e725c1a161506f6cb6b53478ad5ef3f08d534efa871d9f",
                "f7a8f640df67ba21b619eb742a73cbfc58739153b8772d5b2f8781f33d45e554",
                "f3632492a72eb8e175b93e1eb31ef382e49f3f3fe385892523beaef9171aa15d441e1a94ab9b1dafa93e0d48d08c26513d53449197e761c74bebb2fae97525c3",
            ),
            (
                "random key 1, blake256(0x01)",
                "a1becef2069444a9dc6331c3247e113c3ee142edda683db8643f9cb0af7cbe33",
                "4a6c419a1e25c85327115c4ace586decddfe2990ed8f3d4d801871158338501d",
                "c23097718bd90c10ba2e99abff92f21c0eec71796712a772f0ce10f2b1bc6f5f",
                "0b89d1fb10635e4a5da463c7339fd0f8d2e7d205a8288d4f973635beb8b59f7fe7c69c94ac665d14c105c2b4ba3b4c59a7819f8ecfe0d9f5f0c93a9f6d7ef447",
            ),
            (
                "random key 2, blake256(0x02)",
                "59930b76d4b15767ec0e8c8e5812aa2e57db30c6af7963e2a6295ba02af5416b",
                "49af37ab5270015fe25276ea5a3bb159d852943df23919522a202205fb7d175c",
                "342d8326464a0b5866091126e2aa29a960eba8e47dba7bef355b18b3f9011793",
                "533e99ee9c838af4cc0280b0223ab0560e7e2083694bd5b0cab3c0cb80bc2e1ecf4f777f046a18b7f8eb2c29325945025e6d5a145176b1a1de9aca7d882ca5d2",
            ),
            (
                "random key 3, blake256(0x03)",
                "c5b205c36bb7497d242e96ec19a2a4f086d8daa919135cf490d2b7c0230f0e91",
                "b706d561742ad3671703c247eb927ee8a386369c79644131cdeb2c5c26bf6c5d",
                "710a4f1a3bee3567b53bd4dd0c9c0e55d76981a5ed488223ca0583bf8a563951",
                "95c966fd6435d505a492548370b29a3c40efc3fefa3e1d997b3e2788cc33836e84a19d1d32c98f266f57f12c4363c0d9d432ca76985c6b7cb21c9970e14c75d8",
            ),
            (
                "random key 4, blake256(0x04)",
                "65b46d4eb001c649a86309286aaf94b18386effe62c2e1586d9b1898ccf0099b",
                "4c6eb9e38415034f4c93d3304d10bef38bf0ad420eefd0f72f940f11c5857786",
                "cb4727000027551b8c2c3b717696dcff46f9ad088050571cb8634038003fc136",
                "327f4e1dc74948df95dba34f26b63317568325316742fc8276be8cd2544a105cecd401dcd37834c2c007bb3402130fcac0cca549326b81727097d4420e73268c",
            ),
        ];

        for (name, key_hex, hash_hex, nonce_hex, want_sig) in cases {
            let priv_key = key(key_hex);
            let hash = arr32(hash_hex);

            // Direct pin of the RFC6979 nonce dcrd computed for this case.
            let nonce = nonce_rfc6979(
                &unhex(key_hex),
                &hash,
                Some(&RFC6979_EXTRA_DATA_V0),
                None,
                0,
            );
            assert_eq!(nonce, arr32(nonce_hex), "{name}: nonce");

            let sig = sign(&priv_key, &hash).expect("sign");
            assert_eq!(
                dcroxide_testutil::hex(&sig.serialize()),
                want_sig,
                "{name}: signature"
            );
            assert!(sig.verify(&hash, &priv_key.public_key()), "{name}: verify");
        }
    }

    /// Ported random-nonce rows from TestSchnorrSignAndVerify, driven
    /// through the internal signing path like dcrd's own test does.
    #[test]
    fn sign_with_explicit_nonce_vectors() {
        let cases = [
            (
                "key 0x1, blake256(0x01020304), random nonce",
                "0000000000000000000000000000000000000000000000000000000000000001",
                "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
                "a6df66500afeb7711d4c8e2220960855d940a5ed57260d2c98fbf6066cca283e",
                "b073759a96a835b09b79e7b93c37fdbe48fb82b000c4a0e1404ba5d1fbc15d0a299d614b02dec30f8261ae43d09a224b233f3221405c9ffd3d2b00a3d2188fd4",
            ),
            (
                "key 0x2, blake256(0x01020304), random nonce",
                "0000000000000000000000000000000000000000000000000000000000000002",
                "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
                "679a6d36e7fe6c02d7668af86d78186e8f9ccc04371ac1c8c37939d1f5cae07a",
                "4a090d82f48ca12d9e7aa24b5dcc187ee0db2920496f671d63e86036aaa7997e16d33ae10eade4db33dda17873948b4803d6eb9b10781616880a6f66ba2d1b78",
            ),
            (
                "key 0x2, blake256(0x0102030405), random nonce",
                "0000000000000000000000000000000000000000000000000000000000000002",
                "dc063eba3c8d52a159e725c1a161506f6cb6b53478ad5ef3f08d534efa871d9f",
                "026ece4cfb704733dd5eef7898e44c33bd5a0d749eb043f48705e40fa9e9afa0",
                "3c4c5a2f217ea758113fd4e89eb756314dfad101a300f48e5bd764d3b6e0f8bfc29f43beed7d84348386152f1c43fc606d0887fa5b6f5c0b7875687f53b344f0",
            ),
        ];

        for (name, key_hex, hash_hex, nonce_hex, want_sig) in cases {
            let priv_key = key(key_hex);
            let hash = arr32(hash_hex);
            let priv_scalar = Scalar::from_repr(arr32(key_hex).into()).expect("valid scalar");

            let sig = sign_with_nonce(&priv_scalar, &arr32(nonce_hex), &hash).expect("sign");
            assert_eq!(
                dcroxide_testutil::hex(&sig.serialize()),
                want_sig,
                "{name}: signature"
            );
            assert!(sig.verify(&hash, &priv_key.public_key()), "{name}: verify");
        }
    }

    #[test]
    fn parse_rejects_bad_lengths_and_ranges() {
        let good = [0u8; 64];
        assert!(
            parse_signature(&good).is_ok(),
            "zero r/s parses (like dcrd)"
        );
        assert_eq!(parse_signature(&good[..63]), Err(Error::SigTooShort));
        assert_eq!(parse_signature(&[0u8; 65]), Err(Error::SigTooLong));

        let mut r_too_big = [0u8; 64];
        r_too_big[..32].copy_from_slice(&FIELD_PRIME_BYTES);
        assert_eq!(parse_signature(&r_too_big), Err(Error::SigRTooBig));

        let mut s_too_big = [0u8; 64];
        s_too_big[32..].copy_from_slice(&GROUP_ORDER_BYTES);
        assert_eq!(parse_signature(&s_too_big), Err(Error::SigSTooBig));
    }

    #[test]
    fn tampered_signatures_do_not_verify() {
        let priv_key = key("0000000000000000000000000000000000000000000000000000000000000001");
        let hash = arr32("c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7");
        let pub_key = priv_key.public_key();
        let sig = sign(&priv_key, &hash).expect("sign");

        // Tampered r fails with unequal R values.
        let mut r = *sig.r_bytes();
        r[31] ^= 1;
        let bad = Signature::new(r, *sig.s_bytes()).expect("in range");
        assert!(!bad.verify(&hash, &pub_key));

        // Negated s does NOT verify: unlike ECDSA, DCRv0 has no s
        // malleability because R (not just its x) is fixed by the even-Y
        // rule.
        let neg_s = super::super::negate_mod_n(sig.s_bytes());
        let bad = Signature::new(*sig.r_bytes(), neg_s).expect("in range");
        assert!(!bad.verify(&hash, &pub_key));

        // Wrong hash length is rejected outright.
        assert!(!sig.verify(&hash[..31], &pub_key));
        assert_eq!(
            sig.verify_detailed(&hash[..31], &pub_key),
            Err(Error::InvalidHashLen)
        );
    }

    #[test]
    fn parse_pub_key_accepts_compressed_only() {
        let priv_key = key("0000000000000000000000000000000000000000000000000000000000000001");
        let pub_key = priv_key.public_key();

        let compressed = pub_key.serialize_compressed();
        assert_eq!(parse_pub_key(&compressed), Ok(pub_key));

        let uncompressed = pub_key.serialize_uncompressed();
        assert_eq!(
            parse_pub_key(&uncompressed),
            Err(PubKeyError::InvalidLen(65))
        );

        let mut wrong_format = compressed;
        wrong_format[0] = 0x04;
        assert_eq!(
            parse_pub_key(&wrong_format),
            Err(PubKeyError::NotCompressed(0x04))
        );
    }

    #[test]
    fn rfc6979_extra_data_constant_is_blake256_of_scheme_name() {
        assert_eq!(
            dcroxide_crypto::blake256::sum256(b"EC-Schnorr-DCRv0"),
            RFC6979_EXTRA_DATA_V0
        );
    }
}
