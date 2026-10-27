// SPDX-License-Identifier: ISC
//! The signature verification algorithms: the fourteen of ring's provider
//! (`rustls-0.23.46/src/crypto/ring/mod.rs:107-123`), each a rustls
//! `SignatureVerificationAlgorithm` under the name `webpki::ring` gives it
//! (`rustls-webpki-0.103.16/src/ring_algs.rs`) and with the two algorithm
//! identifiers ring's returns, since webpki picks an algorithm for a
//! certificate by comparing those bytes (`signed_data.rs:186-247`).
//!
//! * ECDSA on P-256 and P-384, each with SHA-256 and SHA-384, over the
//!   curve crates' `ecdsa` verifier.  The key is taken only as an
//!   uncompressed point, `0x04` and both coordinates at the field's
//!   length, as ring parses it (`ring-0.17.14/src/ec/suite_b/
//!   public_key.rs`), where `VerifyingKey::from_sec1_bytes` would also take
//!   the compressed form; the point must be on the curve, with coordinates
//!   below p.  The signature is strict DER, a SEQUENCE of two minimal
//!   positive INTEGERs and nothing after it, with r and s in [1, n)
//!   (`ecdsa-0.17.0/src/der.rs:90-114`, `lib.rs:237-246`), as ring's
//!   `split_rs_asn1` and Go's `ecdsa.VerifyASN1` read it.  The digest is
//!   cut to the order's length and reduced (`hazmat.rs:136-173`), which is
//!   ring's and Go's reading of a SHA-384 digest under P-256.
//! * Ed25519, as Go 1.26.2 verifies it
//!   (`crypto/internal/fips140/ed25519/ed25519.go:290-327`) and ring does
//!   (`ring-0.17.14/src/ec/curve25519/ed25519/verification.rs:36-74`),
//!   written here on `curve25519-dalek`: the key's 32 bytes decoded as Go's
//!   `Point.SetBytes` decodes them, a y at or above p and an x of zero with
//!   its sign bit set both taken; S below L; k = SHA-512(R || A || M) mod L
//!   over the bytes as received; and `R' = [S]B - [k]A` compared,
//!   encoded, with R.  So it is cofactorless, takes keys of small order, and
//!   refuses an R that is not canonically encoded, as Go and ring do.
//! * RSA, PKCS#1 v1.5 with SHA-256, SHA-384 and SHA-512, under both of the
//!   identifiers a certificate may name each by, and PSS with each, in this
//!   tree (`src/rsa.rs`, ADR-0015 T5).
//!
//! Verification touches only public values and runs in variable time.

use core::fmt;
use core::marker::PhantomData;

use curve25519_dalek::constants::ED25519_BASEPOINT_COMPRESSED;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use ecdsa::elliptic_curve::array::typenum::Unsigned;
use ecdsa::elliptic_curve::sec1::ToSec1Point;
use rustls::pki_types::{
    AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id,
};
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::rsa::{Hash, RsaVerify};

/// ECDSA signatures using the P-256 curve and SHA-256.
pub static ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm =
    &EcdsaVerify::<p256::NistP256, Sha256> {
        name: "ECDSA_P256_SHA256",
        public_key_alg_id: alg_id::ECDSA_P256,
        signature_alg_id: alg_id::ECDSA_SHA256,
        types: PhantomData,
    };

/// ECDSA signatures using the P-256 curve and SHA-384, its digest cut to
/// 256 bits.
pub static ECDSA_P256_SHA384: &dyn SignatureVerificationAlgorithm =
    &EcdsaVerify::<p256::NistP256, Sha384> {
        name: "ECDSA_P256_SHA384",
        public_key_alg_id: alg_id::ECDSA_P256,
        signature_alg_id: alg_id::ECDSA_SHA384,
        types: PhantomData,
    };

/// ECDSA signatures using the P-384 curve and SHA-256.
pub static ECDSA_P384_SHA256: &dyn SignatureVerificationAlgorithm =
    &EcdsaVerify::<p384::NistP384, Sha256> {
        name: "ECDSA_P384_SHA256",
        public_key_alg_id: alg_id::ECDSA_P384,
        signature_alg_id: alg_id::ECDSA_SHA256,
        types: PhantomData,
    };

/// ECDSA signatures using the P-384 curve and SHA-384.
pub static ECDSA_P384_SHA384: &dyn SignatureVerificationAlgorithm =
    &EcdsaVerify::<p384::NistP384, Sha384> {
        name: "ECDSA_P384_SHA384",
        public_key_alg_id: alg_id::ECDSA_P384,
        signature_alg_id: alg_id::ECDSA_SHA384,
        types: PhantomData,
    };

/// Ed25519 signatures (RFC 8410), verified as Go verifies them.
pub static ED25519: &dyn SignatureVerificationAlgorithm = &Ed25519Verify;

/// RSA PKCS#1 v1.5 signatures using SHA-256, for keys of 2041 to 8192
/// bits, as ring rounds the least.
pub static RSA_PKCS1_2048_8192_SHA256: &dyn SignatureVerificationAlgorithm = &RsaVerify::pkcs1(
    "RSA_PKCS1_2048_8192_SHA256",
    Hash::Sha256,
    alg_id::RSA_PKCS1_SHA256,
);

/// RSA PKCS#1 v1.5 signatures using SHA-384, for keys of 2041 to 8192
/// bits.
pub static RSA_PKCS1_2048_8192_SHA384: &dyn SignatureVerificationAlgorithm = &RsaVerify::pkcs1(
    "RSA_PKCS1_2048_8192_SHA384",
    Hash::Sha384,
    alg_id::RSA_PKCS1_SHA384,
);

/// RSA PKCS#1 v1.5 signatures using SHA-512, for keys of 2041 to 8192
/// bits.
pub static RSA_PKCS1_2048_8192_SHA512: &dyn SignatureVerificationAlgorithm = &RsaVerify::pkcs1(
    "RSA_PKCS1_2048_8192_SHA512",
    Hash::Sha512,
    alg_id::RSA_PKCS1_SHA512,
);

/// [`RSA_PKCS1_2048_8192_SHA256`] under the identifier without the NULL
/// parameters RFC 4055 requires and asks verifiers to accept missing; the
/// encoding signed still carries them.
pub static RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS: &dyn SignatureVerificationAlgorithm =
    &RsaVerify::pkcs1(
        "RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS",
        Hash::Sha256,
        RSA_PKCS1_SHA256_ABSENT_PARAMS,
    );

/// [`RSA_PKCS1_2048_8192_SHA384`] under the identifier without its NULL
/// parameters.
pub static RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS: &dyn SignatureVerificationAlgorithm =
    &RsaVerify::pkcs1(
        "RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS",
        Hash::Sha384,
        RSA_PKCS1_SHA384_ABSENT_PARAMS,
    );

/// [`RSA_PKCS1_2048_8192_SHA512`] under the identifier without its NULL
/// parameters.
pub static RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS: &dyn SignatureVerificationAlgorithm =
    &RsaVerify::pkcs1(
        "RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS",
        Hash::Sha512,
        RSA_PKCS1_SHA512_ABSENT_PARAMS,
    );

/// RSA PSS signatures using SHA-256, MGF1 and a 32-byte salt, for keys of
/// 2041 to 8192 bits of type `rsaEncryption` (RFC 4055 §1.2).
pub static RSA_PSS_2048_8192_SHA256_LEGACY_KEY: &dyn SignatureVerificationAlgorithm =
    &RsaVerify::pss(
        "RSA_PSS_2048_8192_SHA256_LEGACY_KEY",
        Hash::Sha256,
        alg_id::RSA_PSS_SHA256,
    );

/// RSA PSS signatures using SHA-384, MGF1 and a 48-byte salt, for keys of
/// 2041 to 8192 bits of type `rsaEncryption`.
pub static RSA_PSS_2048_8192_SHA384_LEGACY_KEY: &dyn SignatureVerificationAlgorithm =
    &RsaVerify::pss(
        "RSA_PSS_2048_8192_SHA384_LEGACY_KEY",
        Hash::Sha384,
        alg_id::RSA_PSS_SHA384,
    );

/// RSA PSS signatures using SHA-512, MGF1 and a 64-byte salt, for keys of
/// 2041 to 8192 bits of type `rsaEncryption`.
pub static RSA_PSS_2048_8192_SHA512_LEGACY_KEY: &dyn SignatureVerificationAlgorithm =
    &RsaVerify::pss(
        "RSA_PSS_2048_8192_SHA512_LEGACY_KEY",
        Hash::Sha512,
        alg_id::RSA_PSS_SHA512,
    );

/// `sha256WithRSAEncryption` with no parameters: webpki's data file's bytes
/// (`rustls-webpki-0.103.16/src/data/alg-rsa-pkcs1-sha256-absent-params.der`).
const RSA_PKCS1_SHA256_ABSENT_PARAMS: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
]);

/// `sha384WithRSAEncryption` with no parameters (`alg-rsa-pkcs1-sha384-absent-params.der`).
const RSA_PKCS1_SHA384_ABSENT_PARAMS: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c,
]);

/// `sha512WithRSAEncryption` with no parameters (`alg-rsa-pkcs1-sha512-absent-params.der`).
const RSA_PKCS1_SHA512_ABSENT_PARAMS: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d,
]);

/// A NIST curve as the ECDSA verifier takes it: its field's length and
/// the curve crate's verification.  The `verifying_curve!` macro writes it
/// for each curve, so the crates' trait bounds stay out of the algorithm,
/// as `sign.rs` and `kx.rs` keep them out of theirs.
trait VerifyingCurve: 'static + Send + Sync {
    /// The length of a field element: 32 or 48 bytes.
    const FIELD_LEN: usize;

    /// Whether `signature`, DER, is a signature of the digest `prehash`
    /// under `public_key`, a SEC 1 point.
    fn verifies_prehash(public_key: &[u8], prehash: &[u8], signature: &[u8]) -> bool;
}

/// [`VerifyingCurve`] for the curve type `$curve` of the crate `$krate`.
macro_rules! verifying_curve {
    ($krate:ident :: $curve:ident) => {
        impl VerifyingCurve for $krate::$curve {
            const FIELD_LEN: usize =
                <ecdsa::elliptic_curve::FieldBytesSize<$krate::$curve> as Unsigned>::USIZE;

            fn verifies_prehash(public_key: &[u8], prehash: &[u8], signature: &[u8]) -> bool {
                use ecdsa::signature::hazmat::PrehashVerifier;
                let Ok(key) = $krate::ecdsa::VerifyingKey::from_sec1_bytes(public_key) else {
                    return false;
                };
                let Ok(signature) = $krate::ecdsa::Signature::from_der(signature) else {
                    return false;
                };
                key.verify_prehash(prehash, &signature).is_ok()
            }
        }
    };
}

verifying_curve!(p256::NistP256);
verifying_curve!(p384::NistP384);

/// ECDSA on the curve `C` with the hash `D`.
struct EcdsaVerify<C: VerifyingCurve, D: Digest> {
    /// webpki's name for it, for `Debug`.
    name: &'static str,
    /// The SubjectPublicKeyInfo algorithm of its keys.
    public_key_alg_id: AlgorithmIdentifier,
    /// The certificate's signature algorithm identifier.
    signature_alg_id: AlgorithmIdentifier,
    /// The curve and the hash, which the value does not hold.
    types: PhantomData<fn() -> (C, D)>,
}

impl<C: VerifyingCurve, D: Digest> fmt::Debug for EcdsaVerify<C, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name)
    }
}

impl<C: VerifyingCurve, D: Digest + 'static> SignatureVerificationAlgorithm for EcdsaVerify<C, D> {
    /// The key must be an uncompressed point, which ring takes alone, and
    /// the digest is `D`'s of the message.
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let uncompressed = C::FIELD_LEN
            .checked_mul(2)
            .and_then(|len| len.checked_add(1))
            .is_some_and(|len| public_key.len() == len)
            && public_key.first() == Some(&0x04);
        if uncompressed && C::verifies_prehash(public_key, &D::digest(message), signature) {
            Ok(())
        } else {
            Err(InvalidSignature)
        }
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key_alg_id
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_alg_id
    }
}

/// The algorithm behind [`ED25519`].
struct Ed25519Verify;

impl fmt::Debug for Ed25519Verify {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ED25519")
    }
}

impl SignatureVerificationAlgorithm for Ed25519Verify {
    /// Go's `verify`: a 32-byte key and a 64-byte signature R || S, S
    /// canonical, the key on the curve, and `[S]B - [k]A` encoding to R.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the negation of a curve point, which cannot overflow"
    )]
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let key = <[u8; 32]>::try_from(public_key).map_err(|_| InvalidSignature)?;
        let (r, s) = <&[u8; 64]>::try_from(signature)
            .map_err(|_| InvalidSignature)?
            .split_at(32);
        let s = <[u8; 32]>::try_from(s).map_err(|_| InvalidSignature)?;
        let s = Scalar::from_canonical_bytes(s)
            .into_option()
            .ok_or(InvalidSignature)?;
        let a = CompressedEdwardsY(key)
            .decompress()
            .ok_or(InvalidSignature)?;
        let k = Scalar::from_bytes_mod_order_wide(
            &Sha512::new()
                .chain_update(r)
                .chain_update(key)
                .chain_update(message)
                .finalize()
                .into(),
        );
        let check = EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &-a, &s).compress();
        if check.as_bytes() == r {
            Ok(())
        } else {
            Err(InvalidSignature)
        }
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }
}

/// The body of the `tlscrypto_verify` fuzz target, not part of the API:
/// each of the fourteen algorithms on a key, a message and a signature cut
/// from `data`, none of which may panic, and the number that accept.
///
/// `data` is a byte that picks the key, the message's length in two bytes,
/// big-endian, and then, for a key taken from `data`, the key's length in
/// two more and the key; what follows is the message and then the
/// signature, each cut short where `data` ends.  The picking byte takes a
/// key from `data` but for 1 to 4, which put in a key the parsers take, so
/// that arbitrary signatures reach the arithmetic as well as the parsers:
/// 1, 2 and 3 the P-256 and P-384 generators, uncompressed, and Ed25519's
/// base point, each the public key of the secret scalar 1; and 4 an
/// `RSAPublicKey` of e = 65537 and a 2048-bit odd modulus, the next 256
/// bytes of `data` (`fuzz_rsa_key`), under which a signature of 256
/// bytes below the modulus is raised and both paddings are checked.
#[doc(hidden)]
pub fn fuzz_verify(data: &[u8]) -> usize {
    /// `len` bytes from the front of `data`, or all of it, and the rest.
    fn take(data: &[u8], len: usize) -> (&[u8], &[u8]) {
        data.split_at(len.min(data.len()))
    }
    /// A two-byte big-endian length from the front of `data`, and the rest.
    fn length(data: &[u8]) -> (usize, &[u8]) {
        match data.split_first_chunk::<2>() {
            Some((len, rest)) => (usize::from(u16::from_be_bytes(*len)), rest),
            None => (0, &[]),
        }
    }
    let Some((&pick, rest)) = data.split_first() else {
        return 0;
    };
    let (message_len, rest) = length(rest);
    let fixed;
    let (key, rest): (&[u8], &[u8]) = match pick {
        1 => {
            fixed = p256::PublicKey::from_affine(p256::AffinePoint::GENERATOR)
                .map(|key| key.to_sec1_point(false).as_bytes().to_vec())
                .unwrap_or_default();
            (&fixed, rest)
        }
        2 => {
            fixed = p384::PublicKey::from_affine(p384::AffinePoint::GENERATOR)
                .map(|key| key.to_sec1_point(false).as_bytes().to_vec())
                .unwrap_or_default();
            (&fixed, rest)
        }
        3 => (ED25519_BASEPOINT_COMPRESSED.as_bytes(), rest),
        4 => {
            let (modulus, rest) = take(rest, 256);
            fixed = fuzz_rsa_key(modulus);
            (&fixed, rest)
        }
        _ => {
            let (key_len, rest) = length(rest);
            take(rest, key_len)
        }
    };
    let (message, signature) = take(rest, message_len);
    crate::SUPPORTED_SIG_ALGS
        .all
        .iter()
        .filter(|algorithm| algorithm.verify_signature(key, message, signature).is_ok())
        .count()
}

/// The fuzz body's RSA key: the `RSAPublicKey` of e = 65537 and a 2048-bit
/// odd modulus, `bytes` zero-padded to 256 bytes with the top and bottom
/// bits set, which is within ring's limits whatever `bytes` is.
fn fuzz_rsa_key(bytes: &[u8]) -> Vec<u8> {
    let mut modulus = [0; 256];
    for (to, from) in modulus.iter_mut().zip(bytes) {
        *to = *from;
    }
    if let Some(top) = modulus.first_mut() {
        *top |= 0x80;
    }
    if let Some(bottom) = modulus.last_mut() {
        *bottom |= 0x01;
    }
    // A SEQUENCE of 266 bytes: the modulus, an INTEGER of 257 bytes with
    // its sign byte, and the exponent.
    [
        &[0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00][..],
        &modulus,
        &[0x02, 0x03, 0x01, 0x00, 0x01],
    ]
    .concat()
}

#[cfg(test)]
// Test-harness arithmetic over bounded lengths.
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use dcroxide_testutil::{SplitMix64, unhex};
    use ecdsa::signature::hazmat::PrehashSigner;

    use super::*;

    /// Each algorithm returns ring's two identifiers, webpki's for its name,
    /// the three without parameters being webpki's data files' bytes; no
    /// two of the fourteen share a pair, so webpki can tell them apart.
    #[test]
    fn each_algorithm_carries_its_identifiers() {
        let absent = |last: u8| {
            AlgorithmIdentifier::from_slice(
                [
                    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, last,
                ]
                .to_vec()
                .leak(),
            )
        };
        let expected = [
            (ECDSA_P256_SHA256, alg_id::ECDSA_P256, alg_id::ECDSA_SHA256),
            (ECDSA_P256_SHA384, alg_id::ECDSA_P256, alg_id::ECDSA_SHA384),
            (ECDSA_P384_SHA256, alg_id::ECDSA_P384, alg_id::ECDSA_SHA256),
            (ECDSA_P384_SHA384, alg_id::ECDSA_P384, alg_id::ECDSA_SHA384),
            (ED25519, alg_id::ED25519, alg_id::ED25519),
            (
                RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
                alg_id::RSA_ENCRYPTION,
                alg_id::RSA_PSS_SHA256,
            ),
            (
                RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
                alg_id::RSA_ENCRYPTION,
                alg_id::RSA_PSS_SHA384,
            ),
            (
                RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
                alg_id::RSA_ENCRYPTION,
                alg_id::RSA_PSS_SHA512,
            ),
            (
                RSA_PKCS1_2048_8192_SHA256,
                alg_id::RSA_ENCRYPTION,
                alg_id::RSA_PKCS1_SHA256,
            ),
            (
                RSA_PKCS1_2048_8192_SHA384,
                alg_id::RSA_ENCRYPTION,
                alg_id::RSA_PKCS1_SHA384,
            ),
            (
                RSA_PKCS1_2048_8192_SHA512,
                alg_id::RSA_ENCRYPTION,
                alg_id::RSA_PKCS1_SHA512,
            ),
            (
                RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS,
                alg_id::RSA_ENCRYPTION,
                absent(0x0b),
            ),
            (
                RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS,
                alg_id::RSA_ENCRYPTION,
                absent(0x0c),
            ),
            (
                RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS,
                alg_id::RSA_ENCRYPTION,
                absent(0x0d),
            ),
        ];
        assert_eq!(crate::SUPPORTED_SIG_ALGS.all.len(), expected.len());
        let mut pairs = std::collections::BTreeSet::new();
        for (listed, (algorithm, public_key, signature)) in
            crate::SUPPORTED_SIG_ALGS.all.iter().zip(expected)
        {
            assert_eq!(
                format!("{listed:?}"),
                format!("{algorithm:?}"),
                "in its place"
            );
            assert_eq!(listed.public_key_alg_id(), public_key, "{algorithm:?}");
            assert_eq!(listed.signature_alg_id(), signature, "{algorithm:?}");
            assert_eq!(algorithm.public_key_alg_id(), public_key, "{algorithm:?}");
            assert_eq!(algorithm.signature_alg_id(), signature, "{algorithm:?}");
            assert!(!algorithm.fips(), "{algorithm:?}");
            let pair = (public_key.as_ref().to_vec(), signature.as_ref().to_vec());
            assert!(pairs.insert(pair), "{algorithm:?}: a pair of its own");
        }
        assert_eq!(format!("{ECDSA_P384_SHA256:?}"), "ECDSA_P384_SHA256");
    }

    /// A P-256 or P-384 key's own signature verifies under each ECDSA
    /// algorithm of its curve with that algorithm's hash, a SHA-384 digest
    /// cut to P-256's 256 bits; and is refused as the other hash's, under
    /// the other curve's algorithms, with the key compressed, in the
    /// hybrid form or a byte long, and as anything but its DER alone.
    #[test]
    fn ecdsa_takes_the_uncompressed_key_and_the_der_signature() {
        let message = b"a TLS 1.2 ServerKeyExchange's parameters";
        let p256 = p256::ecdsa::SigningKey::from_slice(&[7; 32]).expect("a key");
        let p384 = p384::ecdsa::SigningKey::from_slice(&[7; 48]).expect("a key");
        let p256_public = p256
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        let p384_public = p384
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        let p256_compressed = p256.verifying_key().to_sec1_point(true).as_bytes().to_vec();
        let p384_compressed = p384.verifying_key().to_sec1_point(true).as_bytes().to_vec();
        // Each algorithm, its key uncompressed and compressed, and a
        // signature its own.
        type Case = (
            &'static dyn SignatureVerificationAlgorithm,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
        );
        let cases: [Case; 4] = [
            (
                ECDSA_P256_SHA256,
                p256_public.clone(),
                p256_compressed.clone(),
                PrehashSigner::<p256::ecdsa::Signature>::sign_prehash(
                    &p256,
                    &Sha256::digest(message),
                )
                .expect("signed")
                .to_der()
                .as_bytes()
                .to_vec(),
            ),
            (
                ECDSA_P256_SHA384,
                p256_public.clone(),
                p256_compressed,
                PrehashSigner::<p256::ecdsa::Signature>::sign_prehash(
                    &p256,
                    &Sha384::digest(message),
                )
                .expect("signed")
                .to_der()
                .as_bytes()
                .to_vec(),
            ),
            (
                ECDSA_P384_SHA256,
                p384_public.clone(),
                p384_compressed.clone(),
                PrehashSigner::<p384::ecdsa::Signature>::sign_prehash(
                    &p384,
                    &Sha256::digest(message),
                )
                .expect("signed")
                .to_der()
                .as_bytes()
                .to_vec(),
            ),
            (
                ECDSA_P384_SHA384,
                p384_public.clone(),
                p384_compressed,
                PrehashSigner::<p384::ecdsa::Signature>::sign_prehash(
                    &p384,
                    &Sha384::digest(message),
                )
                .expect("signed")
                .to_der()
                .as_bytes()
                .to_vec(),
            ),
        ];
        let ecdsa = [
            ECDSA_P256_SHA256,
            ECDSA_P256_SHA384,
            ECDSA_P384_SHA256,
            ECDSA_P384_SHA384,
        ];
        for (index, (algorithm, public, compressed, signature)) in cases.iter().enumerate() {
            for (other_index, other) in ecdsa.iter().enumerate() {
                assert_eq!(
                    other.verify_signature(public, message, signature).is_ok(),
                    other_index == index,
                    "{algorithm:?}'s signature under {other:?}"
                );
            }
            let mut hybrid = public.clone();
            hybrid[0] = 0x06 | (public[public.len() - 1] & 1);
            let long = [public.clone(), vec![0]].concat();
            for (what, key) in [
                ("compressed", compressed),
                ("hybrid", &hybrid),
                ("a byte long", &long),
            ] {
                assert!(
                    algorithm.verify_signature(key, message, signature).is_err(),
                    "{algorithm:?}, {what}"
                );
            }
            let trailing = [signature.clone(), vec![0]].concat();
            let mut long_form = vec![0x30, 0x81, signature[1]];
            long_form.extend_from_slice(&signature[2..]);
            for (what, wrong) in [
                ("a byte after it", &trailing),
                ("its length in the long form", &long_form),
            ] {
                assert!(
                    algorithm.verify_signature(public, message, wrong).is_err(),
                    "{algorithm:?}, {what}"
                );
            }
            assert!(
                algorithm
                    .verify_signature(public, b"another", signature)
                    .is_err()
            );
        }
    }

    /// Ed25519 as Go verifies it: RFC 8032's first three tests verify; S
    /// at or above L is refused; the identity as the key, in its canonical
    /// encoding, with the sign bit of its zero x set, and with y written as
    /// p + 1, takes [S]B as R for any message, cofactorless verification
    /// taking a key of small order; and R in a form that is not canonical
    /// is refused.
    #[test]
    fn ed25519_follows_gos_rules() {
        for (public, message, signature) in [
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
            (
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac\
                 18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
        ] {
            let (public, message, signature) = (unhex(public), unhex(message), unhex(signature));
            assert!(
                ED25519
                    .verify_signature(&public, &message, &signature)
                    .is_ok()
            );
            // S + L names the same point, and is refused.
            let s = Scalar::from_canonical_bytes(signature[32..].try_into().expect("32"))
                .into_option()
                .expect("canonical");
            let l = unhex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
            let mut s_plus_l = [0u8; 32];
            let mut carry = 0u16;
            for (i, byte) in s_plus_l.iter_mut().enumerate() {
                let sum = u16::from(s.as_bytes()[i]) + u16::from(l[i]) + carry;
                *byte = sum as u8;
                carry = sum >> 8;
            }
            let wrong = [&signature[..32], &s_plus_l].concat();
            assert!(ED25519.verify_signature(&public, &message, &wrong).is_err());
            assert!(
                ED25519
                    .verify_signature(&public, b"another", &signature)
                    .is_err()
            );
            assert!(
                ED25519
                    .verify_signature(&public[..31], &message, &signature)
                    .is_err()
            );
            assert!(
                ED25519
                    .verify_signature(&public, &message, &signature[..63])
                    .is_err()
            );
        }

        let s = Scalar::from_bytes_mod_order([9; 32]);
        let r = EdwardsPoint::mul_base(&s).compress().to_bytes();
        let identity_canonical = {
            let mut key = [0; 32];
            key[0] = 1;
            key
        };
        let mut identity_signed = identity_canonical;
        identity_signed[31] |= 0x80;
        let mut identity_p_plus_1 = [0xff; 32];
        identity_p_plus_1[0] = 0xee;
        identity_p_plus_1[31] = 0x7f;
        for key in [identity_canonical, identity_signed, identity_p_plus_1] {
            for message in [&b""[..], b"any message at all"] {
                let signature = [&r[..], s.as_bytes()].concat();
                assert!(
                    ED25519.verify_signature(&key, message, &signature).is_ok(),
                    "{key:02x?}"
                );
            }
            // S = 0 makes R' the identity, which only its canonical encoding
            // matches.
            let zero = [&identity_canonical[..], &[0; 32]].concat();
            assert!(
                ED25519.verify_signature(&key, b"m", &zero).is_ok(),
                "{key:02x?}"
            );
            let not_canonical = [&identity_p_plus_1[..], &[0; 32]].concat();
            assert!(
                ED25519
                    .verify_signature(&key, b"m", &not_canonical)
                    .is_err(),
                "{key:02x?}"
            );
        }

        // The challenge hashes the key as received.  The point of order 2,
        // y = -1, written with the sign bit of its zero x set, is not its
        // canonical encoding; under it [S]B, S verifies exactly when k is
        // even, k hashed over those bytes and not over the canonical ones.
        let mut order_2 = [0xff; 32];
        order_2[0] = 0xec;
        order_2[31] = 0x7f;
        let mut order_2_signed = order_2;
        order_2_signed[31] |= 0x80;
        let k_is_even = |key: &[u8; 32], message: &[u8]| {
            let k = Scalar::from_bytes_mod_order_wide(
                &Sha512::new()
                    .chain_update(&r[..])
                    .chain_update(key)
                    .chain_update(message)
                    .finalize()
                    .into(),
            );
            k.as_bytes()[0] & 1 == 0
        };
        let mut seen = [false; 2];
        for i in 0u8..64 {
            let message = [i];
            let as_received = k_is_even(&order_2_signed, &message);
            if as_received == k_is_even(&order_2, &message) {
                continue;
            }
            let signature = [&r[..], s.as_bytes()].concat();
            let verified = ED25519.verify_signature(&order_2_signed, &message, &signature);
            assert_eq!(verified.is_ok(), as_received, "message {i}");
            seen[usize::from(as_received)] = true;
        }
        assert_eq!(seen, [true, true], "messages each way");
    }

    /// The fuzz target's body counts the algorithms that accept: one for a
    /// signature by the secret scalar 1 under each curve key it picks,
    /// whose public key is the generator or the base point, two for a test
    /// key's PKCS#1 v1.5 signature under the RSA pick with the key's modulus
    /// as its bytes, the algorithm and its twin without NULL parameters,
    /// and none once the signature changes.  And over inputs from a fixed
    /// generator, nothing panics: six in seven cut as it cuts them, with a
    /// key from the data or each pick's, and signatures of any length and
    /// of each algorithm's shape, 64 bytes with S below L, a DER SEQUENCE
    /// of two INTEGERs at the curve's length and the RSA modulus's 256
    /// bytes, so that many reach the arithmetic; and the seventh of any
    /// shape, so that lengths run past the end of the data.
    #[test]
    fn the_fuzz_body_counts_what_accepts() {
        let message = b"fuzzed".to_vec();
        let input = |pick: u8, signature: &[u8]| {
            let len = u16::try_from(message.len()).expect("short").to_be_bytes();
            [&[pick][..], &len, &message, signature].concat()
        };
        let mut one = [0; 32];
        one[31] = 1;
        let p256 = p256::ecdsa::SigningKey::from_slice(&one).expect("1");
        let mut one48 = [0; 48];
        one48[47] = 1;
        let p384 = p384::ecdsa::SigningKey::from_slice(&one48).expect("1");
        let p256_signature =
            PrehashSigner::<p256::ecdsa::Signature>::sign_prehash(&p256, &Sha256::digest(&message))
                .expect("signed")
                .to_der()
                .as_bytes()
                .to_vec();
        let p384_signature =
            PrehashSigner::<p384::ecdsa::Signature>::sign_prehash(&p384, &Sha384::digest(&message))
                .expect("signed")
                .to_der()
                .as_bytes()
                .to_vec();
        let ed25519_signature = {
            let r = Scalar::from_bytes_mod_order([3; 32]);
            let big_r = EdwardsPoint::mul_base(&r).compress().to_bytes();
            let k = Scalar::from_bytes_mod_order_wide(
                &Sha512::new()
                    .chain_update(big_r)
                    .chain_update(ED25519_BASEPOINT_COMPRESSED.as_bytes())
                    .chain_update(&message)
                    .finalize()
                    .into(),
            );
            [&big_r[..], (r + k).as_bytes()].concat()
        };
        for (pick, signature) in [
            (1, &p256_signature),
            (2, &p384_signature),
            (3, &ed25519_signature),
        ] {
            assert_eq!(fuzz_verify(&input(pick, signature)), 1, "pick {pick}");
            let mut changed = signature.clone();
            let last = changed.len() - 1;
            changed[last] ^= 1;
            assert_eq!(fuzz_verify(&input(pick, &changed)), 0, "pick {pick}");
        }
        // The RSA pick, its 256 bytes a test key's modulus, which has its
        // top and bottom bits set and e = 65537 already.
        let rsa = dcroxide_testutil::rsa_test_key("rsa2048");
        assert_eq!((rsa.n.len(), &rsa.e[..]), (256, &[1, 0, 1][..]));
        assert_eq!(fuzz_rsa_key(&rsa.n), rsa.rsa_public_key());
        let rsa_input = |signature: &[u8]| {
            let len = u16::try_from(message.len()).expect("short").to_be_bytes();
            [&[4][..], &len, &rsa.n, &message, signature].concat()
        };
        let rsa_signature = crate::rsa::pkcs1_signature(&rsa, Hash::Sha256, &message);
        assert_eq!(fuzz_verify(&rsa_input(&rsa_signature)), 2);
        let mut changed = rsa_signature.clone();
        changed[255] ^= 1;
        assert_eq!(fuzz_verify(&rsa_input(&changed)), 0);
        // The same P-256 key and signature, the key cut from the input.
        let key = p256
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        let from_data = [
            &[0][..],
            &u16::try_from(message.len()).expect("short").to_be_bytes(),
            &u16::try_from(key.len()).expect("short").to_be_bytes(),
            &key,
            &message,
            &p256_signature,
        ]
        .concat();
        assert_eq!(fuzz_verify(&from_data), 1);

        let mut rng = SplitMix64(0x7f5a_2026_1027);
        let random = |rng: &mut SplitMix64, len: usize| {
            let mut bytes = vec![0; len];
            rng.fill(&mut bytes);
            bytes
        };
        // An input cut as the body cuts it, under `pick`.
        let shaped = |rng: &mut SplitMix64, pick: u8| {
            let message = rng.bytes(64);
            let mut data = vec![pick];
            data.extend_from_slice(&u16::try_from(message.len()).expect("short").to_be_bytes());
            match pick {
                1..=3 => {}
                4 => data.extend(random(rng, 256)),
                _ => {
                    let key = rng.bytes(600);
                    data.extend_from_slice(&u16::try_from(key.len()).expect("short").to_be_bytes());
                    data.extend(key);
                }
            }
            data.extend_from_slice(&message);
            let signature = match rng.below(4) {
                0 => rng.bytes(600),
                // R and an S below 2^252, so below L.
                1 => {
                    let mut signature = random(rng, 64);
                    signature[63] &= 0x0f;
                    signature
                }
                // r and s positive at P-384's length for its pick and
                // P-256's for the others, below either order.
                2 => {
                    let len = if pick == 2 { 48 } else { 32 };
                    let integer = |rng: &mut SplitMix64| {
                        let mut value = random(rng, len);
                        value[0] &= 0x7f;
                        [&[0x02, len as u8][..], &value].concat()
                    };
                    let content = [integer(rng), integer(rng)].concat();
                    [&[0x30, content.len() as u8][..], &content].concat()
                }
                _ => random(rng, 256),
            };
            data.extend_from_slice(&signature);
            data
        };
        for case in 0..1400u64 {
            // Every seventh input is bytes of any shape, whose lengths
            // mostly run past the bytes that follow them.
            let data = if case % 7 == 6 {
                rng.bytes(600)
            } else {
                shaped(&mut rng, (case % 6) as u8)
            };
            assert!(
                fuzz_verify(&data) <= crate::SUPPORTED_SIG_ALGS.all.len(),
                "case {case}"
            );
        }
        assert_eq!(fuzz_verify(&[]), 0);
        assert_eq!(fuzz_verify(&[1]), 0);
        assert_eq!(fuzz_verify(&[4]), 0);
    }
}
