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
//! * Ed25519, as Go 1.27.3 verifies it
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
//! Beside them, and in no set ring had, the rest of the ECDSA set Go
//! verifies (ADR-0015, T4): P-256 and P-384 with SHA-512, and P-521 with
//! each of SHA-256, SHA-384 and SHA-512, under the names and identifiers
//! `webpki::aws_lc_rs` gives them (`rustls-webpki-0.103.16/src/
//! aws_lc_rs_algs.rs:92-139`).  They are the same verifier on the same
//! rules: the key uncompressed alone, at P-521's 66-byte coordinates, each
//! below p and on the curve, as Go's `ecdsa.ParseUncompressedPublicKey`
//! reads one; the signature strict DER with r and s in [1, n), in a
//! SEQUENCE whose length is in the short form below 128 content bytes and
//! in the long form from 128 up, where an honestly made P-521 signature's
//! almost always falls (one whose r and s are both small enough, which no
//! honest signer makes in practice, is in the short form and verifies as
//! it does in Go); and the digest cut to the
//! order's length where it is longer, a SHA-512 digest under P-256 or
//! P-384, and taken whole where it is shorter, any digest under P-521,
//! whose order is 521 bits, which is Go's `hashToNat`
//! (`crypto/internal/fips140/ecdsa/ecdsa.go:407-422`).  Go's
//! `crypto/x509` takes ecdsa-with-SHA256, -SHA384 and -SHA512 from a key
//! on any of the three curves (`crypto/x509/x509.go:1099-1106`), and its
//! `crypto/tls` a TLS 1.2 ECDSA scheme from a key on any of them
//! (`crypto/tls/auth.go:210-220`), so all nine pairs are needed.
//! [`crate::RPC_SIG_ALGS`] lists them; [`crate::SUPPORTED_SIG_ALGS`], ring's
//! set, does not.
//!
//! Beside them, and in no set ring had, ML-DSA-44, -65 and -87 (FIPS 204),
//! which Go 1.27 verifies in a certificate and in a TLS 1.3
//! CertificateVerify, on the `ml-dsa` crate, under the names and
//! identifiers `webpki::aws_lc_rs` gives them.  Each algorithm's two
//! identifiers are its set's bare OID, so a certificate whose key or
//! signature algorithm carries parameters, or names another set, finds no
//! algorithm, as Go refuses the one (`crypto/x509/parser.go:366-374`) and
//! makes the other an unknown algorithm or a set mismatch
//! (`crypto/x509/x509.go:433-444`, `:1115-1134`).  The key and the
//! signature must be exactly the set's lengths; the signature is decoded
//! as FIPS 204's `sigDecode` with its hint and norm checks before the key
//! is expanded, and verified over the message with an empty context, as Go
//! calls `mldsa.Verify` (`crypto/x509/x509.go:1135`,
//! `crypto/tls/auth.go:49-56`).  [`crate::RPC_SIG_ALGS`] lists them.
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

use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsaParams, Signature, VerifyingKey};

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

/// ECDSA signatures using the P-256 curve and SHA-512, its digest cut to
/// 256 bits.  Not in ring's set; Go verifies it.
pub static ECDSA_P256_SHA512: &dyn SignatureVerificationAlgorithm =
    &EcdsaVerify::<p256::NistP256, Sha512> {
        name: "ECDSA_P256_SHA512",
        public_key_alg_id: alg_id::ECDSA_P256,
        signature_alg_id: alg_id::ECDSA_SHA512,
        types: PhantomData,
    };

/// ECDSA signatures using the P-384 curve and SHA-512, its digest cut to
/// 384 bits.  Not in ring's set; Go verifies it.
pub static ECDSA_P384_SHA512: &dyn SignatureVerificationAlgorithm =
    &EcdsaVerify::<p384::NistP384, Sha512> {
        name: "ECDSA_P384_SHA512",
        public_key_alg_id: alg_id::ECDSA_P384,
        signature_alg_id: alg_id::ECDSA_SHA512,
        types: PhantomData,
    };

/// ECDSA signatures using the P-521 curve and SHA-256, the digest taken
/// whole.  Not in ring's set; Go verifies it.
pub static ECDSA_P521_SHA256: &dyn SignatureVerificationAlgorithm =
    &EcdsaVerify::<p521::NistP521, Sha256> {
        name: "ECDSA_P521_SHA256",
        public_key_alg_id: alg_id::ECDSA_P521,
        signature_alg_id: alg_id::ECDSA_SHA256,
        types: PhantomData,
    };

/// ECDSA signatures using the P-521 curve and SHA-384, the digest taken
/// whole.  Not in ring's set; Go verifies it.
pub static ECDSA_P521_SHA384: &dyn SignatureVerificationAlgorithm =
    &EcdsaVerify::<p521::NistP521, Sha384> {
        name: "ECDSA_P521_SHA384",
        public_key_alg_id: alg_id::ECDSA_P521,
        signature_alg_id: alg_id::ECDSA_SHA384,
        types: PhantomData,
    };

/// ECDSA signatures using the P-521 curve and SHA-512, the digest taken
/// whole: what a P-521 key signs with in TLS 1.3
/// (`ecdsa_secp521r1_sha512`), and what Go's `crypto/x509` signs with by
/// default for a P-521 authority, dcrwallet's under `--tlscurve=P-521`
/// among them.  Not in ring's set; Go verifies it.
pub static ECDSA_P521_SHA512: &dyn SignatureVerificationAlgorithm =
    &EcdsaVerify::<p521::NistP521, Sha512> {
        name: "ECDSA_P521_SHA512",
        public_key_alg_id: alg_id::ECDSA_P521,
        signature_alg_id: alg_id::ECDSA_SHA512,
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

/// ML-DSA-44 signatures (FIPS 204), pure, with an empty context.
pub static ML_DSA_44: &dyn SignatureVerificationAlgorithm = &MlDsaVerify::<ml_dsa::MlDsa44> {
    name: "ML_DSA_44",
    alg_id: alg_id::ML_DSA_44,
    set: PhantomData,
};

/// ML-DSA-65 signatures, pure, with an empty context.
pub static ML_DSA_65: &dyn SignatureVerificationAlgorithm = &MlDsaVerify::<ml_dsa::MlDsa65> {
    name: "ML_DSA_65",
    alg_id: alg_id::ML_DSA_65,
    set: PhantomData,
};

/// ML-DSA-87 signatures, pure, with an empty context.
pub static ML_DSA_87: &dyn SignatureVerificationAlgorithm = &MlDsaVerify::<ml_dsa::MlDsa87> {
    name: "ML_DSA_87",
    alg_id: alg_id::ML_DSA_87,
    set: PhantomData,
};

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
    /// The length of a field element: 32, 48 or 66 bytes.
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
verifying_curve!(p521::NistP521);

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

/// ML-DSA on the parameter set `P`.
pub(crate) struct MlDsaVerify<P: MlDsaParams> {
    /// `webpki::aws_lc_rs`'s name for it, for `Debug`.
    name: &'static str,
    /// The set's identifier, the bare OID, for its keys and its signatures
    /// alike.
    alg_id: AlgorithmIdentifier,
    /// The set, which the value does not hold.
    set: PhantomData<fn() -> P>,
}

impl<P: MlDsaParams> fmt::Debug for MlDsaVerify<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name)
    }
}

impl<P: MlDsaParams> MlDsaVerify<P> {
    /// Whether `signature` is `P`'s signature of `message` under
    /// `public_key` with `context`: each exactly `P`'s length, the
    /// signature's hints and the norm of its z as FIPS 204's `sigDecode`
    /// requires (`ml-dsa-0.1.2/src/lib.rs:115-128`, `src/hint.rs:128-161`),
    /// checked before the key is expanded, and a context of at most 255
    /// bytes.  The algorithm passes an empty context; the Wycheproof tests
    /// pass a case's own.
    pub(crate) fn verifies(
        public_key: &[u8],
        message: &[u8],
        context: &[u8],
        signature: &[u8],
    ) -> bool {
        let (Ok(public_key), Ok(signature)) = (
            <&EncodedVerifyingKey<P>>::try_from(public_key),
            <&EncodedSignature<P>>::try_from(signature),
        ) else {
            return false;
        };
        let Some(signature) = Signature::<P>::decode(signature) else {
            return false;
        };
        VerifyingKey::<P>::decode(public_key).verify_with_context(message, context, &signature)
    }
}

impl<P: MlDsaParams> SignatureVerificationAlgorithm for MlDsaVerify<P> {
    /// Go's `mldsa.Verify` with no context.
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        if Self::verifies(public_key, message, b"", signature) {
            Ok(())
        } else {
            Err(InvalidSignature)
        }
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.alg_id
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.alg_id
    }
}

/// The body of the `tlscrypto_verify` fuzz target, not part of the API:
/// each of the twenty-two algorithms of [`crate::RPC_SIG_ALGS`], ring's
/// fourteen, ML-DSA's three and the five ECDSA pairs ring lacked, on a key,
/// a message and a signature cut from `data`, none of which may panic, and
/// the number that accept.
///
/// `data` is a byte that picks the key, the message's length in two bytes,
/// big-endian, and then, for a key taken from `data`, the key's length in
/// two more and the key; what follows is the message and then the
/// signature, each cut short where `data` ends.  The picking byte takes a
/// key from `data` but for 1 to 8, which put in a key the parsers take, so
/// that arbitrary signatures reach the arithmetic as well as the parsers:
/// 1, 2, 8 and 3 the P-256, P-384 and P-521 generators, uncompressed, and
/// Ed25519's base point, each the public key of the secret scalar 1; 4 an
/// `RSAPublicKey` of e = 65537 and a 2048-bit odd modulus, the next 256
/// bytes of `data` (`fuzz_rsa_key`), under which a signature of 256
/// bytes below the modulus is raised and both paddings are checked; and 5,
/// 6 and 7 an ML-DSA-44, -65 or -87 key of zero bytes, which is a key
/// (its t1 zero), under which the signature is laid over one of the set's
/// length whose z is zero and whose hints are empty
/// (`fuzz_ml_dsa_signature`), so that whatever `data` holds is decoded
/// whole, its hints and z checked, and a signature that passes them
/// reaches the arithmetic.
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
    // The ML-DSA set's place in `FUZZ_ML_DSA` that picks 5 to 7 name.
    let ml_dsa = match pick {
        5 => Some(0),
        6 => Some(1),
        7 => Some(2),
        _ => None,
    };
    let fixed;
    let (key, rest): (&[u8], &[u8]) = match (pick, ml_dsa) {
        (_, Some(set)) => {
            fixed = vec![0; FUZZ_ML_DSA.get(set).map_or(0, |lengths| lengths.0)];
            (&fixed, rest)
        }
        (1, _) => {
            fixed = p256::PublicKey::from_affine(p256::AffinePoint::GENERATOR)
                .map(|key| key.to_sec1_point(false).as_bytes().to_vec())
                .unwrap_or_default();
            (&fixed, rest)
        }
        (2, _) => {
            fixed = p384::PublicKey::from_affine(p384::AffinePoint::GENERATOR)
                .map(|key| key.to_sec1_point(false).as_bytes().to_vec())
                .unwrap_or_default();
            (&fixed, rest)
        }
        (8, _) => {
            fixed = p521::PublicKey::from_affine(p521::AffinePoint::GENERATOR)
                .map(|key| key.to_sec1_point(false).as_bytes().to_vec())
                .unwrap_or_default();
            (&fixed, rest)
        }
        (3, _) => (ED25519_BASEPOINT_COMPRESSED.as_bytes(), rest),
        (4, _) => {
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
    let laid;
    let signature = match ml_dsa {
        Some(set) => {
            laid = fuzz_ml_dsa_signature(set, signature);
            &laid[..]
        }
        None => signature,
    };
    crate::RPC_SIG_ALGS
        .all
        .iter()
        .filter(|algorithm| algorithm.verify_signature(key, message, signature).is_ok())
        .count()
}

/// ML-DSA-44's, -65's and -87's lengths, as the fuzz body lays them out:
/// the public key, the signature, its challenge c̃, the bits of each of
/// z's coefficients and z's number of polynomials (FIPS 204, table 2).
const FUZZ_ML_DSA: [(usize, usize, usize, usize, usize); 3] = [
    (1312, 2420, 32, 18, 4),
    (1952, 3309, 48, 20, 5),
    (2592, 4627, 64, 20, 7),
];

/// The fuzz body's ML-DSA signature for the set at `set` in
/// [`FUZZ_ML_DSA`]: `bytes` laid over a signature of the set's length
/// whose c̃ is zero, every coefficient of z zero, which `BitPack` writes
/// as γ1 with only the top bit of its field set, and its hints empty, all
/// zero bytes; `bytes` beyond that length are dropped.  Set 0 is
/// ML-DSA-44, 1 ML-DSA-65 and 2 ML-DSA-87.  Not part of the API: the RPC
/// listener's client-certificate fuzz body lays its input the same way.
#[doc(hidden)]
pub fn fuzz_ml_dsa_signature(set: usize, bytes: &[u8]) -> Vec<u8> {
    let Some(&(_, len, c_tilde, bits, polys)) = FUZZ_ML_DSA.get(set) else {
        return Vec::new();
    };
    let mut signature = vec![0u8; len];
    let coefficients = polys.saturating_mul(256);
    for index in 0..coefficients {
        let top = index
            .checked_mul(bits)
            .and_then(|bit| bit.checked_add(bits))
            .and_then(|bit| bit.checked_sub(1))
            .and_then(|bit| Some((c_tilde.checked_add(bit / 8)?, bit % 8)));
        if let Some((byte, shift)) = top
            && let Some(byte) = signature.get_mut(byte)
        {
            *byte |= 1 << shift;
        }
    }
    for (to, from) in signature.iter_mut().zip(bytes) {
        *to = *from;
    }
    signature
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

    /// The RPC set is ring's fourteen algorithms, ML-DSA's three and the
    /// five ECDSA pairs ring lacked, the mapping in Go 1.27.3's order of
    /// preference less SHA-1 (`crypto/tls/defaults.go:49-67`), each of
    /// ring's schemes mapped to the algorithms ring's mapping gives it and,
    /// for the two ECDSA schemes, P-521's after them, and P-521's scheme to
    /// its hash on P-521 first and then on P-256 and P-384; each new ECDSA
    /// algorithm carries webpki's identifiers for its name; and each ML-DSA
    /// algorithm carries its set's bare OID as both identifiers, with no
    /// parameters, a pair of its own.
    #[test]
    fn the_rpc_set_is_rings_ml_dsa_and_p521_in_gos_order() {
        use rustls::SignatureScheme as S;
        let name = |algorithm: &&dyn SignatureVerificationAlgorithm| format!("{algorithm:?}");
        let ml_dsa = [ML_DSA_44, ML_DSA_65, ML_DSA_87];
        let added = [
            (ECDSA_P256_SHA512, alg_id::ECDSA_P256, alg_id::ECDSA_SHA512),
            (ECDSA_P384_SHA512, alg_id::ECDSA_P384, alg_id::ECDSA_SHA512),
            (ECDSA_P521_SHA256, alg_id::ECDSA_P521, alg_id::ECDSA_SHA256),
            (ECDSA_P521_SHA384, alg_id::ECDSA_P521, alg_id::ECDSA_SHA384),
            (ECDSA_P521_SHA512, alg_id::ECDSA_P521, alg_id::ECDSA_SHA512),
        ];
        let all: Vec<String> = crate::RPC_SIG_ALGS.all.iter().map(name).collect();
        let expected: Vec<String> = ml_dsa
            .iter()
            .chain(crate::SUPPORTED_SIG_ALGS.all)
            .chain(added.iter().map(|(algorithm, ..)| algorithm))
            .map(name)
            .collect();
        assert_eq!(all, expected);
        for (algorithm, public_key, signature) in added {
            assert_eq!(algorithm.public_key_alg_id(), public_key, "{algorithm:?}");
            assert_eq!(algorithm.signature_alg_id(), signature, "{algorithm:?}");
        }
        assert_eq!(format!("{ECDSA_P521_SHA512:?}"), "ECDSA_P521_SHA512");
        let schemes: Vec<S> = crate::RPC_SIG_ALGS
            .mapping
            .iter()
            .map(|(scheme, _)| *scheme)
            .collect();
        assert_eq!(
            schemes,
            [
                S::ML_DSA_44,
                S::ML_DSA_65,
                S::ML_DSA_87,
                S::RSA_PSS_SHA256,
                S::ECDSA_NISTP256_SHA256,
                S::ED25519,
                S::RSA_PSS_SHA384,
                S::RSA_PSS_SHA512,
                S::RSA_PKCS1_SHA256,
                S::RSA_PKCS1_SHA384,
                S::RSA_PKCS1_SHA512,
                S::ECDSA_NISTP384_SHA384,
                S::ECDSA_NISTP521_SHA512,
            ]
        );
        for (scheme, algorithms) in crate::RPC_SIG_ALGS.mapping {
            let ours: Vec<String> = algorithms.iter().map(name).collect();
            let expected: Vec<String> = match crate::SUPPORTED_SIG_ALGS
                .mapping
                .iter()
                .find(|(ring, _)| ring == scheme)
            {
                Some((_, ring)) => {
                    let mut ring: Vec<String> = ring.iter().map(name).collect();
                    match *scheme {
                        S::ECDSA_NISTP256_SHA256 => ring.push(name(&ECDSA_P521_SHA256)),
                        S::ECDSA_NISTP384_SHA384 => ring.push(name(&ECDSA_P521_SHA384)),
                        _ => {}
                    }
                    ring
                }
                None if *scheme == S::ECDSA_NISTP521_SHA512 => {
                    [ECDSA_P521_SHA512, ECDSA_P256_SHA512, ECDSA_P384_SHA512]
                        .iter()
                        .map(name)
                        .collect()
                }
                // An ML-DSA scheme, to its algorithm of the same name.
                None => vec![format!("{scheme:?}")],
            };
            assert_eq!(ours, expected, "{scheme:?}");
        }
        let mut pairs = std::collections::BTreeSet::new();
        for algorithm in crate::RPC_SIG_ALGS.all {
            let pair = (
                algorithm.public_key_alg_id().as_ref().to_vec(),
                algorithm.signature_alg_id().as_ref().to_vec(),
            );
            assert!(pairs.insert(pair), "{algorithm:?}: a pair of its own");
            assert!(!algorithm.fips(), "{algorithm:?}");
        }
        for (algorithm, last) in ml_dsa.iter().zip([0x11, 0x12, 0x13]) {
            let oid = [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, last,
            ];
            assert_eq!(algorithm.public_key_alg_id().as_ref(), oid, "{algorithm:?}");
            assert_eq!(algorithm.signature_alg_id().as_ref(), oid, "{algorithm:?}");
        }
    }

    /// An ML-DSA key from a seed of `seed` bytes, its public key and its
    /// signature of `message` with `context`, made with the crate's
    /// deterministic signer.
    fn ml_dsa_signed<P: MlDsaParams>(
        seed: u8,
        message: &[u8],
        context: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        let key = ml_dsa::ExpandedSigningKey::<P>::from_seed(&[seed; 32].into());
        let signature = key.sign_deterministic(message, context).expect("signed");
        (
            key.verifying_key().encode().to_vec(),
            signature.encode().to_vec(),
        )
    }

    /// Each ML-DSA set verifies its own signature with an empty context,
    /// and refuses it under the other two sets, with the key or the
    /// signature a byte long or short, with a bit of c̃ changed, with z's
    /// first coefficient at the bound FIPS 204's `sigDecode` sets, γ1 − β,
    /// where just under it decodes and fails, for another message, and
    /// when it was made over a context, which TLS and x509 never give.
    #[test]
    fn ml_dsa_takes_its_own_set_at_its_lengths() {
        // Each set: its algorithm, its key and signature, γ1's bits and β.
        let message = b"a TLS 1.3 CertificateVerify's content";
        let sets = [
            (
                ML_DSA_44,
                ml_dsa_signed::<ml_dsa::MlDsa44>(1, message, b""),
                17,
                78,
                32,
            ),
            (
                ML_DSA_65,
                ml_dsa_signed::<ml_dsa::MlDsa65>(2, message, b""),
                19,
                196,
                48,
            ),
            (
                ML_DSA_87,
                ml_dsa_signed::<ml_dsa::MlDsa87>(3, message, b""),
                19,
                120,
                64,
            ),
        ];
        let lengths = [(1312, 2420), (1952, 3309), (2592, 4627)];
        for (index, (algorithm, (key, signature), gamma1_bits, beta, c_tilde)) in
            sets.iter().enumerate()
        {
            assert_eq!(
                (key.len(), signature.len()),
                lengths[index],
                "{algorithm:?}"
            );
            for (other_index, (other, ..)) in sets.iter().enumerate() {
                assert_eq!(
                    other.verify_signature(key, message, signature).is_ok(),
                    other_index == index,
                    "{algorithm:?}'s signature under {other:?}"
                );
            }
            let long = |bytes: &[u8]| [bytes, &[0]].concat();
            let short = |bytes: &[u8]| bytes[..bytes.len() - 1].to_vec();
            for (what, key, signature) in [
                ("a key a byte long", long(key), signature.clone()),
                ("a key a byte short", short(key), signature.clone()),
                ("a signature a byte long", key.clone(), long(signature)),
                ("a signature a byte short", key.clone(), short(signature)),
            ] {
                assert!(
                    algorithm
                        .verify_signature(&key, message, &signature)
                        .is_err(),
                    "{algorithm:?}, {what}"
                );
            }
            let mut flipped = signature.clone();
            flipped[0] ^= 1;
            assert!(algorithm.verify_signature(key, message, &flipped).is_err());
            assert!(
                algorithm
                    .verify_signature(key, b"another", signature)
                    .is_err()
            );
            // z's first coefficient, written as γ1 − z in the low bits of
            // the bytes after c̃: γ1 − β is refused as it is decoded, and
            // γ1 − β − 1 decodes and fails the challenge.
            let bits = gamma1_bits + 1;
            for (encoded, decodes) in [(*beta, false), (beta + 1, true)] {
                let mut at = signature.clone();
                for bit in 0..bits {
                    let (byte, shift) = (c_tilde + bit / 8, bit % 8);
                    at[byte] =
                        (at[byte] & !(1 << shift)) | ((((encoded >> bit) & 1) as u8) << shift);
                }
                assert!(algorithm.verify_signature(key, message, &at).is_err());
                let decoded = match index {
                    0 => ml_dsa::Signature::<ml_dsa::MlDsa44>::try_from(&at[..]).is_ok(),
                    1 => ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(&at[..]).is_ok(),
                    _ => ml_dsa::Signature::<ml_dsa::MlDsa87>::try_from(&at[..]).is_ok(),
                };
                assert_eq!(decoded, decodes, "{algorithm:?}, z0 written as {encoded}");
            }
        }
        let (key, signature) = ml_dsa_signed::<ml_dsa::MlDsa44>(1, message, b"a context");
        assert!(
            ML_DSA_44
                .verify_signature(&key, message, &signature)
                .is_err()
        );
        assert!(MlDsaVerify::<ml_dsa::MlDsa44>::verifies(
            &key,
            message,
            b"a context",
            &signature
        ));
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

    /// The nine ECDSA pairs of the RPC set, each curve's key with each
    /// hash: a key's signature of a message's digest verifies under the
    /// algorithm of its curve and that hash alone.  The digest is read as
    /// Go's `hashToNat` reads it: a SHA-512 digest cut to P-256's and
    /// P-384's lengths, so a signature of its first 32 or 48 bytes is one
    /// of the digest, and a shorter digest taken whole under P-521, so a
    /// signature of the digest padded with zeros on the left to 66 bytes is
    /// one of the digest.  A P-521 key is refused compressed, in the hybrid
    /// form, a byte long or short, and with a coordinate at or above p
    /// (bits set above the field's 521); a P-521 signature, whose SEQUENCE
    /// length is in the long form for an honestly made one, is refused with
    /// that length in two bytes, with a byte after it, with r or s at n or
    /// zero, with a leading zero r does not need, and for another message.
    /// A P-521 signature with r = 1 and s = 5, made by solving for the key
    /// ([`P521_SHORT_FORM`]), whose SEQUENCE length is in the short form,
    /// verifies under each hash, as Go 1.27.3's `ecdsa.VerifyASN1` verifies
    /// it, and is refused with that length in the long form, which DER does
    /// not allow below 128.
    #[test]
    fn ecdsa_takes_each_curve_with_each_hash() {
        let message = b"a TLS 1.3 CertificateVerify's content";
        let digests = [
            Sha256::digest(message).to_vec(),
            Sha384::digest(message).to_vec(),
            Sha512::digest(message).to_vec(),
        ];
        let p256 = p256::ecdsa::SigningKey::from_slice(&[7; 32]).expect("a key");
        let p384 = p384::ecdsa::SigningKey::from_slice(&[7; 48]).expect("a key");
        let mut scalar = [7; 66];
        scalar[0] = 1;
        let p521 = p521::ecdsa::SigningKey::from_slice(&scalar).expect("a key");
        // Each curve: its key, its field's length, and its signature of a
        // prehash.
        type Signer = Box<dyn Fn(&[u8]) -> Vec<u8>>;
        let curves: [(Vec<u8>, usize, Signer); 3] = [
            (
                p256.verifying_key()
                    .to_sec1_point(false)
                    .as_bytes()
                    .to_vec(),
                32,
                Box::new(move |prehash: &[u8]| {
                    PrehashSigner::<p256::ecdsa::Signature>::sign_prehash(&p256, prehash)
                        .expect("signed")
                        .to_der()
                        .as_bytes()
                        .to_vec()
                }),
            ),
            (
                p384.verifying_key()
                    .to_sec1_point(false)
                    .as_bytes()
                    .to_vec(),
                48,
                Box::new(move |prehash: &[u8]| {
                    PrehashSigner::<p384::ecdsa::Signature>::sign_prehash(&p384, prehash)
                        .expect("signed")
                        .to_der()
                        .as_bytes()
                        .to_vec()
                }),
            ),
            (
                p521.verifying_key()
                    .to_sec1_point(false)
                    .as_bytes()
                    .to_vec(),
                66,
                Box::new(move |prehash: &[u8]| {
                    PrehashSigner::<p521::ecdsa::Signature>::sign_prehash(&p521, prehash)
                        .expect("signed")
                        .to_der()
                        .as_bytes()
                        .to_vec()
                }),
            ),
        ];
        // The nine, by curve and then by hash.
        let algorithms = [
            [ECDSA_P256_SHA256, ECDSA_P256_SHA384, ECDSA_P256_SHA512],
            [ECDSA_P384_SHA256, ECDSA_P384_SHA384, ECDSA_P384_SHA512],
            [ECDSA_P521_SHA256, ECDSA_P521_SHA384, ECDSA_P521_SHA512],
        ];
        for (curve, (key, field, sign)) in curves.iter().enumerate() {
            assert_eq!(key.len(), 1 + 2 * field);
            for (hash, digest) in digests.iter().enumerate() {
                // The prehash `hashToNat` reads the digest as.
                let read = if digest.len() >= *field {
                    digest[..*field].to_vec()
                } else {
                    [vec![0; field - digest.len()], digest.clone()].concat()
                };
                for (what, signature) in [
                    ("the digest", sign(digest)),
                    ("the digest as Go reads it", sign(&read)),
                ] {
                    for (other_curve, row) in algorithms.iter().enumerate() {
                        for (other_hash, other) in row.iter().enumerate() {
                            assert_eq!(
                                other.verify_signature(key, message, &signature).is_ok(),
                                (other_curve, other_hash) == (curve, hash),
                                "{:?}'s signature of {what} under {other:?}",
                                algorithms[curve][hash]
                            );
                        }
                    }
                }
            }
        }
        // P-521's key and its SHA-512 signature, mutated.
        let (key, _, sign) = &curves[2];
        let algorithm = ECDSA_P521_SHA512;
        let signature = sign(&digests[2]);
        assert!(algorithm.verify_signature(key, message, &signature).is_ok());
        assert_eq!(&signature[..2], [0x30, 0x81], "the long form");
        let mut compressed = vec![0x02 | (key[132] & 1)];
        compressed.extend_from_slice(&key[1..67]);
        let mut hybrid = key.clone();
        hybrid[0] = 0x06 | (key[132] & 1);
        let long = [key.clone(), vec![0]].concat();
        let short = key[..132].to_vec();
        // x with a bit above the field's 521 set, which is at or above p.
        let mut x_high = key.clone();
        x_high[1] |= 0x02;
        let mut y_high = key.clone();
        y_high[67] |= 0x80;
        for (what, wrong) in [
            ("compressed", &compressed),
            ("hybrid", &hybrid),
            ("a byte long", &long),
            ("a byte short", &short),
            ("x at or above p", &x_high),
            ("y at or above p", &y_high),
        ] {
            assert!(
                algorithm
                    .verify_signature(wrong, message, &signature)
                    .is_err(),
                "{what}"
            );
        }
        // r and s, read back from the DER.
        let content = &signature[3..];
        let r_len = usize::from(content[1]);
        let r = &content[2..2 + r_len];
        let s = &content[2 + r_len + 2..];
        let integer = |value: &[u8]| {
            let mut tlv = vec![0x02, value.len() as u8];
            tlv.extend_from_slice(value);
            tlv
        };
        let der = |r: &[u8], s: &[u8]| {
            let content = [integer(r), integer(s)].concat();
            let mut out = if content.len() > 127 {
                vec![0x30, 0x81, content.len() as u8]
            } else {
                vec![0x30, content.len() as u8]
            };
            out.extend_from_slice(&content);
            out
        };
        assert_eq!(der(r, s), signature, "the DER rebuilt");
        // P-521's order, 521 bits, as a minimal positive INTEGER's bytes.
        let n = unhex(
            "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             fa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
        );
        let two_byte_length = [&[0x30, 0x82, 0x00, signature[2]][..], &signature[3..]].concat();
        let trailing = [signature.clone(), vec![0]].concat();
        let padded_r = [vec![0], r.to_vec()].concat();
        for (what, wrong) in [
            ("its length in two bytes", two_byte_length),
            ("a byte after it", trailing),
            ("r at n", der(&n, s)),
            ("s at n", der(r, &n)),
            ("r zero", der(&[0], s)),
            ("s zero", der(r, &[0])),
            ("r with a needless leading zero", der(&padded_r, s)),
        ] {
            assert!(
                algorithm.verify_signature(key, message, &wrong).is_err(),
                "{what}"
            );
        }
        assert!(
            algorithm
                .verify_signature(key, b"another", &signature)
                .is_err()
        );
        // A short-form P-521 signature under each hash, and the same with
        // its length in the long form.
        let short_form = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x05];
        let long_form = [0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x05];
        for (algorithm, key) in [ECDSA_P521_SHA256, ECDSA_P521_SHA384, ECDSA_P521_SHA512]
            .into_iter()
            .zip(P521_SHORT_FORM.keys)
        {
            let key = unhex(key);
            assert!(
                algorithm
                    .verify_signature(&key, P521_SHORT_FORM.message, &short_form)
                    .is_ok(),
                "{algorithm:?}, the short form"
            );
            assert!(
                algorithm
                    .verify_signature(&key, P521_SHORT_FORM.message, &long_form)
                    .is_err(),
                "{algorithm:?}, the short form's length in the long form"
            );
        }
    }

    /// A P-521 signature whose SEQUENCE length is in DER's short form:
    /// r = 1 and s = 5 over [`ShortFormVectors::message`], with the key
    /// solved for under each hash, Q = (R - u1 G) / u2 for a point R whose
    /// x is 1 modulo n, by a generator kept outside the repository during
    /// the review of ADR-0015's T4.  Go 1.27.3's `ecdsa.VerifyASN1`, with
    /// each key read by `ecdsa.ParseUncompressedPublicKey`, verified each
    /// under its hash.
    struct ShortFormVectors {
        /// The message signed.
        message: &'static [u8],
        /// The uncompressed keys, in hex, under SHA-256, SHA-384 and SHA-512.
        keys: [&'static str; 3],
    }

    /// The vectors [`ShortFormVectors`] describes.
    const P521_SHORT_FORM: ShortFormVectors = ShortFormVectors {
        message: b"edge-case message",
        keys: [
            "040146624a297c110c4a16dce982bd099f92da8ca5ff50da2c6305c3e4e7a493f64901d81697049\
             37b62eae4a56ea818e34b688f15e9fa486f62342851888d98d49e730028586efc2cf7fcb7555f7cd8\
             d79e08ecff42932f69d14d61468adae63944c9b1bd61bde27f1402a3689a9322f667872363c86115\
             8fe830b7f19459b933bd85208d",
            "0401866cc9b970f153f97e95d8170867000b66ef2a5d9c36f8219b82222a8c0716ca73da1b03a2e\
             7595850b230cf33a0b493e6943c6980fb54e3105d720610e8fc925700b8128bf1d3af0a3c8882b511\
             ea20d7b65b7aeeb86d716c439616614d02681d3a45e197c4404b0acd2baf7fb93ad2306e5b39864dd\
             40617b833204b552c82dfacd0",
            "0400f3b2159f4cd51b6e549391a7df9b8ce6f7afb05ce1770106fbb27061f61b8fd346740a98c07\
             448d19f157becc09df1c7ac643d8be17fbb7fa7bde1a70b78c469d400d9aa4908ec8ed4609d064d6a\
             69ff8042ff49d2bdf33bcb1b4596fba30262c4d5c794d989bb6f4f08896cb30cdeb5bcaabf65734d1\
             76c779ad7af6e4b4eeebee3fb",
        ],
    };

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
    /// one for an ML-DSA key's signature with the key cut from the data,
    /// and none once the signature changes.  The ML-DSA picks lay what
    /// follows the message over a signature that decodes, so that z and the
    /// hints are checked and the arithmetic reached whatever the data's
    /// length.  And over inputs from a fixed generator, nothing panics:
    /// nine in ten cut as it cuts them, with a key from the data or each
    /// pick's, and signatures of any length and of each algorithm's shape,
    /// 64 bytes with S below L, a DER SEQUENCE of two INTEGERs at the
    /// curve's length, the RSA modulus's 256 bytes and ML-DSA bytes up to
    /// the set's length, so that many reach the arithmetic; and the tenth
    /// of any shape, so that lengths run past the end of the data.
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
        let mut one66 = [0; 66];
        one66[65] = 1;
        let p521 = p521::ecdsa::SigningKey::from_slice(&one66).expect("1");
        let p521_signature =
            PrehashSigner::<p521::ecdsa::Signature>::sign_prehash(&p521, &Sha512::digest(&message))
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
            (8, &p521_signature),
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
        // An ML-DSA key and signature of each set, the key cut from the
        // input; and the laid signature of each ML-DSA pick, which decodes
        // under its set, refused under the zero key.
        let ml_dsa = [
            ml_dsa_signed::<ml_dsa::MlDsa44>(4, &message, b""),
            ml_dsa_signed::<ml_dsa::MlDsa65>(5, &message, b""),
            ml_dsa_signed::<ml_dsa::MlDsa87>(6, &message, b""),
        ];
        for (key, signature) in &ml_dsa {
            let with_key = |signature: &[u8]| {
                [
                    &[0][..],
                    &u16::try_from(message.len()).expect("short").to_be_bytes(),
                    &u16::try_from(key.len()).expect("short").to_be_bytes(),
                    key,
                    &message,
                    signature,
                ]
                .concat()
            };
            assert_eq!(fuzz_verify(&with_key(signature)), 1);
            let mut changed = signature.clone();
            changed[0] ^= 1;
            assert_eq!(fuzz_verify(&with_key(&changed)), 0);
        }
        for (set, pick) in (5..=7u8).enumerate() {
            let laid = fuzz_ml_dsa_signature(set, &[]);
            assert_eq!(laid.len(), FUZZ_ML_DSA[set].1);
            let decodes = match set {
                0 => ml_dsa::Signature::<ml_dsa::MlDsa44>::try_from(&laid[..]).is_ok(),
                1 => ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(&laid[..]).is_ok(),
                _ => ml_dsa::Signature::<ml_dsa::MlDsa87>::try_from(&laid[..]).is_ok(),
            };
            assert!(decodes, "pick {pick}");
            let longer = [&laid[..], &[0xff; 5]].concat();
            assert_eq!(fuzz_ml_dsa_signature(set, &longer), laid, "pick {pick}");
            assert_eq!(fuzz_verify(&input(pick, &[])), 0, "pick {pick}");
            assert_eq!(fuzz_verify(&input(pick, &laid)), 0, "pick {pick}");
        }
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
                1..=3 | 5..=8 => {}
                4 => data.extend(random(rng, 256)),
                _ => {
                    let key = rng.bytes(600);
                    data.extend_from_slice(&u16::try_from(key.len()).expect("short").to_be_bytes());
                    data.extend(key);
                }
            }
            data.extend_from_slice(&message);
            let signature = match rng.below(4) {
                _ if (5..=7).contains(&pick) => {
                    let len = FUZZ_ML_DSA[usize::from(pick - 5)].1;
                    let len = rng.below(len as u64 + 1) as usize;
                    random(rng, len)
                }
                0 => rng.bytes(600),
                // R and an S below 2^252, so below L.
                1 => {
                    let mut signature = random(rng, 64);
                    signature[63] &= 0x0f;
                    signature
                }
                // r and s positive at P-384's length for its pick, at
                // P-521's, its top byte below 2, for its own, and at
                // P-256's for the others, below each order, P-521's in a
                // SEQUENCE whose length takes the long form.
                2 => {
                    let len = match pick {
                        2 => 48,
                        8 => 66,
                        _ => 32,
                    };
                    let integer = |rng: &mut SplitMix64| {
                        let mut value = random(rng, len);
                        value[0] &= if len == 66 { 0x01 } else { 0x7f };
                        [&[0x02, len as u8][..], &value].concat()
                    };
                    let content = [integer(rng), integer(rng)].concat();
                    let header = if content.len() > 127 {
                        vec![0x30, 0x81, content.len() as u8]
                    } else {
                        vec![0x30, content.len() as u8]
                    };
                    [&header[..], &content].concat()
                }
                _ => random(rng, 256),
            };
            data.extend_from_slice(&signature);
            data
        };
        for case in 0..2000u64 {
            // Every tenth input is bytes of any shape, whose lengths
            // mostly run past the bytes that follow them.
            let data = if case % 10 == 9 {
                rng.bytes(600)
            } else {
                shaped(&mut rng, (case % 10) as u8)
            };
            assert!(
                fuzz_verify(&data) <= crate::RPC_SIG_ALGS.all.len(),
                "case {case}"
            );
        }
        assert_eq!(fuzz_verify(&[]), 0);
        assert_eq!(fuzz_verify(&[1]), 0);
        assert_eq!(fuzz_verify(&[4]), 0);
        assert_eq!(fuzz_verify(&[8]), 0);
    }
}
