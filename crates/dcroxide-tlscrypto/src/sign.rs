// SPDX-License-Identifier: ISC
//! Signing keys, and the key loader that makes them from an `rpc.key`.
//!
//! The keys are ECDSA on P-256, P-384 and P-521 and Ed25519, each a
//! rustls `SigningKey` under the shape of rustls's ring provider
//! (`rustls-0.23.46/src/crypto/ring/sign.rs`): one signature scheme per
//! key, offered in both TLS versions when the peer lists it.  For P-256
//! and P-384 that is ring's choice (`:284-294`).  For P-521, which ring
//! cannot sign with, it is `ECDSA_NISTP521_SHA512`, the scheme Go offers
//! by default (`crypto/tls/defaults.go:52`) and the one its TLS 1.3 picks
//! for a P-521 key (`crypto/tls/auth.go:208-209`); in TLS 1.2 Go signs
//! with the first ECDSA scheme the peer lists (`:193-201`, `:263-267`),
//! which PARITY.md records.  RSA keys are read and refused (ADR-0015, T6).
//!
//! * ECDSA signs with the curve's own hash, SHA-256, SHA-384 or SHA-512,
//!   and RFC 6979's nonce with the field's length of additional data from
//!   the process generator (`rand::ProcessRng`) mixed in
//!   (`ecdsa-0.17.0/src/hazmat.rs:102-123`): the computation `ecdsa`'s
//!   own hedged signer makes (`signing.rs:220-232`), with the draw made
//!   here.  The nonce is safe should the draw be weak, and two signatures
//!   of the same transcript still differ, as Go's and ring's do.  The
//!   signature is DER, as TLS carries it.
//! * Ed25519 is RFC 8032's, on `curve25519-dalek` with `sha2`'s SHA-512:
//!   deterministic, so a signature is ring's and Go's `ed25519.Sign`'s
//!   byte for byte for the same seed and message.
//!
//! [`KEY_PROVIDER`] and [`load_der`] read a key as Go's `tls.X509KeyPair`
//! does (`crate::keys`), with Go's texts for a key Go refuses and this
//! provider's own for the RSA and P-224 keys Go loads and this provider
//! does not sign with.  The secrets are wiped when the last handshake
//! holding them drops them.

use core::fmt;
use std::sync::Arc;

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::{Scalar, clamp_integer};
use ecdsa::elliptic_curve::array::typenum::Unsigned;
use rustls::crypto::KeyProvider;
use rustls::pki_types::{AlgorithmIdentifier, PrivateKeyDer, SubjectPublicKeyInfoDer, alg_id};
use rustls::sign::{Signer, SigningKey, public_key_to_spki};
use rustls::{Error, SignatureAlgorithm, SignatureScheme};
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, Zeroizing};

use crate::keys::{self, KeyError, ParsedKey};
use crate::rand::ProcessRng;

/// Go's `tls.X509KeyPair` key parsing, less RSA: the key provider whose
/// `load_private_key` ignores the `PrivateKeyDer` variant, which a PEM
/// label chose, and reads `secret_der()` as [`load_der`] does.
pub static KEY_PROVIDER: &dyn KeyProvider = &KeyLoader;

/// [`KEY_PROVIDER`]'s and [`load_der`]'s text for an RSA key.
pub const RSA_KEY_REFUSED: &str = "RSA private keys are not supported: this provider signs with \
                                   ECDSA (P-256, P-384, P-521) and Ed25519 keys";

/// Go's text for a key none of its parsers reads (`crypto/tls/tls.go:382`).
const UNPARSABLE: &str = "tls: failed to parse private key";

/// Go's text for a PKCS#8 key of a type `crypto/tls` does not take, an
/// X25519 key (`crypto/tls/tls.go:375`).
const UNKNOWN_PKCS8_TYPE: &str = "tls: found unknown private key type in PKCS#8 wrapping";

/// The text for a P-224 key, which Go loads and serves over TLS 1.2 only,
/// and ring refused, as this provider does.
const P224_REFUSED: &str = "unsupported private key: ECDSA P-224";

/// What Go's `parsePrivateKey` reads a key as, when it is one of these.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAlgorithm {
    /// ECDSA on P-256.
    EcdsaP256,
    /// ECDSA on P-384.
    EcdsaP384,
    /// ECDSA on P-521.
    EcdsaP521,
    /// Ed25519.
    Ed25519,
    /// RSA, which [`load_der`] refuses.
    Rsa,
}

/// What Go's `parsePrivateKey` reads `der` as, whatever PEM label it came
/// under: `None` for a key it does not read, and for a key of another
/// type (P-224, X25519).
pub fn key_algorithm(der: &[u8]) -> Option<KeyAlgorithm> {
    Some(match keys::parse(der).ok()? {
        ParsedKey::EcdsaP256(_) => KeyAlgorithm::EcdsaP256,
        ParsedKey::EcdsaP384(_) => KeyAlgorithm::EcdsaP384,
        ParsedKey::EcdsaP521(_) => KeyAlgorithm::EcdsaP521,
        ParsedKey::Ed25519(_) => KeyAlgorithm::Ed25519,
        ParsedKey::Rsa => KeyAlgorithm::Rsa,
    })
}

/// Go's `parsePrivateKey` on raw DER, whatever PEM label it came under:
/// the signing key, or the `Error::General` [`KEY_PROVIDER`] would give.
pub fn load_der(der: &[u8]) -> Result<Arc<dyn SigningKey>, Error> {
    let refused = |text: &str| Err(Error::General(text.to_owned()));
    match keys::parse(der) {
        Ok(ParsedKey::EcdsaP256(key)) => Ok(Arc::new(EcdsaSigningKey::<p256::NistP256>::new(key))),
        Ok(ParsedKey::EcdsaP384(key)) => Ok(Arc::new(EcdsaSigningKey::<p384::NistP384>::new(key))),
        Ok(ParsedKey::EcdsaP521(key)) => Ok(Arc::new(EcdsaSigningKey::<p521::NistP521>::new(key))),
        Ok(ParsedKey::Ed25519(seed)) => Ok(Arc::new(Ed25519SigningKey::from_seed(&seed))),
        Ok(ParsedKey::Rsa) => refused(RSA_KEY_REFUSED),
        Err(KeyError::UnknownPkcs8Type) => refused(UNKNOWN_PKCS8_TYPE),
        Err(KeyError::P224) => refused(P224_REFUSED),
        Err(KeyError::Unparsable) => refused(UNPARSABLE),
    }
}

/// The [`KeyProvider`] behind [`KEY_PROVIDER`].
#[derive(Debug)]
struct KeyLoader;

impl KeyProvider for KeyLoader {
    /// [`load_der`] on the key's DER, which is wiped when the load is done,
    /// as ring's loader wipes it (`rustls-0.23.46/src/crypto/ring/mod.rs:57-62`).
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, Error> {
        let key_der = Zeroizing::new(key_der);
        load_der(key_der.secret_der())
    }
}

/// A NIST curve as the signer takes it: the scheme and SubjectPublicKeyInfo
/// algorithm of its keys, its field's length, and the operations on the
/// curve crate's key.  The `signing_curve!` macro writes it for each
/// curve, so the crates' trait bounds stay out of the TLS logic, as
/// `kx.rs` keeps them out of the key exchange.
trait SigningCurve: 'static + Send + Sync {
    /// The one signature scheme a key on the curve signs with.
    const SCHEME: SignatureScheme;
    /// The SubjectPublicKeyInfo algorithm of a key on the curve.
    const ALG_ID: AlgorithmIdentifier;
    /// The length of a field element: 32, 48 or 66 bytes, and of the
    /// hedge each signature draws.
    const FIELD_LEN: usize;
    /// The curve crate's signing key, which wipes its scalar on drop.
    type Key: Send + Sync;

    /// The uncompressed SEC 1 encoding of the key's public point.
    fn public(key: &Self::Key) -> Vec<u8>;

    /// The DER signature of `message`: the curve's hash, then RFC 6979's
    /// nonce with `hedge` as additional data.
    fn sign(key: &Self::Key, message: &[u8], hedge: &[u8]) -> Vec<u8>;

    /// The DER signature of `message` with `nonce`, big-endian at the
    /// field's length, as the nonce, or `None` when it is not in `[1, n)`
    /// or gives a signature of zero.
    #[cfg(test)]
    fn sign_with_nonce(key: &Self::Key, nonce: &[u8], message: &[u8]) -> Option<Vec<u8>>;

    /// The key whose scalar `scalar` encodes, big-endian at the field's
    /// length, or `None` when it is not in `[1, n)` or of another length.
    #[cfg(test)]
    fn key_from_scalar(scalar: &[u8]) -> Option<Self::Key>;
}

/// [`SigningCurve`] for the curve type `$curve` of the crate `$krate`.
macro_rules! signing_curve {
    ($krate:ident :: $curve:ident, $scheme:ident, $alg_id:ident) => {
        impl SigningCurve for $krate::$curve {
            const SCHEME: SignatureScheme = SignatureScheme::$scheme;
            const ALG_ID: AlgorithmIdentifier = alg_id::$alg_id;
            const FIELD_LEN: usize =
                <ecdsa::elliptic_curve::FieldBytesSize<$krate::$curve> as Unsigned>::USIZE;
            type Key = $krate::ecdsa::SigningKey;

            fn public(key: &Self::Key) -> Vec<u8> {
                key.verifying_key().to_sec1_point(false).as_bytes().to_vec()
            }

            fn sign(key: &Self::Key, message: &[u8], hedge: &[u8]) -> Vec<u8> {
                type Hash = <$krate::$curve as ecdsa::DigestAlgorithm>::Digest;
                let digest = Hash::digest(message);
                let (signature, _) = ecdsa::hazmat::sign_prehashed_rfc6979::<Self, Hash>(
                    key.as_nonzero_scalar(),
                    &digest,
                    hedge,
                );
                signature.to_der().as_bytes().to_vec()
            }

            #[cfg(test)]
            fn sign_with_nonce(key: &Self::Key, nonce: &[u8], message: &[u8]) -> Option<Vec<u8>> {
                type Hash = <$krate::$curve as ecdsa::DigestAlgorithm>::Digest;
                let nonce = $krate::FieldBytes::try_from(nonce).ok()?;
                let nonce = $krate::NonZeroScalar::from_repr(nonce).into_option()?;
                let (signature, _) = ecdsa::hazmat::sign_prehashed::<Self>(
                    key.as_nonzero_scalar(),
                    &nonce,
                    &Hash::digest(message),
                )
                .ok()?;
                Some(signature.to_der().as_bytes().to_vec())
            }

            #[cfg(test)]
            fn key_from_scalar(scalar: &[u8]) -> Option<Self::Key> {
                let scalar = $krate::FieldBytes::try_from(scalar).ok()?;
                $krate::ecdsa::SigningKey::from_bytes(&scalar).ok()
            }
        }
    };
}

signing_curve!(p256::NistP256, ECDSA_NISTP256_SHA256, ECDSA_P256);
signing_curve!(p384::NistP384, ECDSA_NISTP384_SHA384, ECDSA_P384);
signing_curve!(p521::NistP521, ECDSA_NISTP521_SHA512, ECDSA_P521);

/// The longest hedge: P-521's 66 bytes.
const MAX_FIELD_LEN: usize = 66;

/// An ECDSA key on the curve `C`, with its SubjectPublicKeyInfo, which
/// `CertifiedKey::keys_match` compares with the certificate's.
struct EcdsaSigningKey<C: SigningCurve> {
    /// The key, shared with each handshake's signer.
    key: Arc<C::Key>,
    /// The public key, as a certificate carries it.
    spki: SubjectPublicKeyInfoDer<'static>,
}

impl<C: SigningCurve> EcdsaSigningKey<C> {
    /// The signing key for `key`.
    fn new(key: C::Key) -> EcdsaSigningKey<C> {
        let spki = public_key_to_spki(&C::ALG_ID, C::public(&key));
        EcdsaSigningKey {
            key: Arc::new(key),
            spki,
        }
    }

    /// For the RFC 6979 vectors: the signature with no hedge, which is
    /// RFC 6979's deterministic one.
    #[cfg(test)]
    fn sign_deterministic(&self, message: &[u8]) -> Vec<u8> {
        C::sign(&self.key, message, &[])
    }

    /// For the RFC 6979 vectors and the timing check (ADR-0015, T10): the
    /// signature with `nonce` as the nonce, which RFC 6979 never gives at
    /// an extreme value of its own.
    #[cfg(test)]
    fn sign_with_nonce(&self, nonce: &[u8], message: &[u8]) -> Option<Vec<u8>> {
        C::sign_with_nonce(&self.key, nonce, message)
    }
}

impl<C: SigningCurve> fmt::Debug for EcdsaSigningKey<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaSigningKey")
            .field("scheme", &C::SCHEME)
            .finish()
    }
}

impl<C: SigningCurve> SigningKey for EcdsaSigningKey<C> {
    /// The curve's one scheme, in either TLS version, when the peer
    /// offers it.
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered.contains(&C::SCHEME).then(|| {
            Box::new(EcdsaSigner::<C> {
                key: Arc::clone(&self.key),
            }) as Box<dyn Signer>
        })
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(self.spki.clone())
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

/// One handshake's signer for an [`EcdsaSigningKey`].
struct EcdsaSigner<C: SigningCurve> {
    /// The key.
    key: Arc<C::Key>,
}

impl<C: SigningCurve> EcdsaSigner<C> {
    /// The signature of `message` with a hedge of the field's length that
    /// `draw` fills, from a zeroed buffer.  `draw` is [`ProcessRng`] but in
    /// the tests, which stand in for it to see the draw.
    fn sign_drawing(&self, message: &[u8], draw: impl FnOnce(&mut [u8])) -> Vec<u8> {
        const { assert!(C::FIELD_LEN <= MAX_FIELD_LEN) };
        let mut hedge = [0; MAX_FIELD_LEN];
        let hedge = &mut hedge[..C::FIELD_LEN];
        draw(hedge);
        C::sign(&self.key, message, hedge)
    }
}

impl<C: SigningCurve> fmt::Debug for EcdsaSigner<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaSigner")
            .field("scheme", &C::SCHEME)
            .finish()
    }
}

impl<C: SigningCurve> Signer for EcdsaSigner<C> {
    /// The hedged RFC 6979 signature, the hedge drawn from the process
    /// generator, which cannot fail.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.sign_drawing(message, |hedge| ProcessRng.fill(hedge)))
    }

    fn scheme(&self) -> SignatureScheme {
        C::SCHEME
    }
}

/// An Ed25519 key, expanded from its seed as RFC 8032 §5.1.5 expands it.
struct Ed25519Key {
    /// The secret scalar: the low half of SHA-512 of the seed, clamped,
    /// reduced mod L; wiped on drop.
    scalar: Zeroizing<Scalar>,
    /// The high half, which each nonce is hashed from; wiped on drop.
    prefix: Zeroizing<[u8; 32]>,
    /// The public key: the scalar times the base point, compressed.
    public: [u8; 32],
}

impl Ed25519Key {
    /// The key for `seed`.
    fn from_seed(seed: &[u8; 32]) -> Ed25519Key {
        let hash = Zeroizing::new(<[u8; 64]>::from(Sha512::digest(seed)));
        let (low, high) = hash.split_at(32);
        let mut scalar = [0; 32];
        scalar.copy_from_slice(low);
        let mut prefix = Zeroizing::new([0; 32]);
        prefix.copy_from_slice(high);
        let key = Ed25519Key::from_expanded(clamp_integer(scalar), prefix);
        scalar.zeroize();
        key
    }

    /// The key for an expanded scalar, which is reduced mod L, and its
    /// prefix.
    fn from_expanded(scalar: [u8; 32], prefix: Zeroizing<[u8; 32]>) -> Ed25519Key {
        let scalar = Zeroizing::new(Scalar::from_bytes_mod_order(scalar));
        let public = EdwardsPoint::mul_base(&scalar).compress().to_bytes();
        Ed25519Key {
            scalar,
            prefix,
            public,
        }
    }

    /// RFC 8032's signature of `message`: the nonce r = SHA-512(prefix ||
    /// message) mod L, then [`Ed25519Key::sign_with`].
    fn sign(&self, message: &[u8]) -> [u8; 64] {
        let hash = Zeroizing::new(<[u8; 64]>::from(
            Sha512::new()
                .chain_update(&self.prefix[..])
                .chain_update(message)
                .finalize(),
        ));
        let r = Zeroizing::new(Scalar::from_bytes_mod_order_wide(&hash));
        self.sign_with(&r, message)
    }

    /// The signature of `message` with the nonce `r`: R = rB, then
    /// S = r + SHA-512(R || A || message) * s mod L.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "arithmetic of scalars mod L, which cannot overflow"
    )]
    fn sign_with(&self, r: &Scalar, message: &[u8]) -> [u8; 64] {
        let big_r = EdwardsPoint::mul_base(r).compress().to_bytes();
        let k = <[u8; 64]>::from(
            Sha512::new()
                .chain_update(big_r)
                .chain_update(self.public)
                .chain_update(message)
                .finalize(),
        );
        let s = Scalar::from_bytes_mod_order_wide(&k) * *self.scalar + r;
        let mut signature = [0; 64];
        signature[..32].copy_from_slice(&big_r);
        signature[32..].copy_from_slice(s.as_bytes());
        signature
    }
}

/// An Ed25519 key as a rustls `SigningKey`.
struct Ed25519SigningKey {
    /// The key, shared with each handshake's signer.
    key: Arc<Ed25519Key>,
}

impl Ed25519SigningKey {
    /// The signing key for `seed`.
    fn from_seed(seed: &[u8; 32]) -> Ed25519SigningKey {
        Ed25519SigningKey {
            key: Arc::new(Ed25519Key::from_seed(seed)),
        }
    }

    /// For the timing check (ADR-0015, T10): the key for an expanded
    /// scalar and prefix chosen directly, since an extreme seed is not an
    /// extreme scalar once hashed.
    #[cfg(test)]
    fn from_expanded(scalar: [u8; 32], prefix: [u8; 32]) -> Ed25519SigningKey {
        Ed25519SigningKey {
            key: Arc::new(Ed25519Key::from_expanded(scalar, Zeroizing::new(prefix))),
        }
    }
}

impl fmt::Debug for Ed25519SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519SigningKey")
            .field("scheme", &SignatureScheme::ED25519)
            .finish()
    }
}

impl SigningKey for Ed25519SigningKey {
    /// `ED25519`, in either TLS version, when the peer offers it.
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered.contains(&SignatureScheme::ED25519).then(|| {
            Box::new(Ed25519Signer {
                key: Arc::clone(&self.key),
            }) as Box<dyn Signer>
        })
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(public_key_to_spki(&alg_id::ED25519, self.key.public))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}

/// One handshake's signer for an [`Ed25519SigningKey`].
struct Ed25519Signer {
    /// The key.
    key: Arc<Ed25519Key>,
}

impl fmt::Debug for Ed25519Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519Signer")
            .field("scheme", &SignatureScheme::ED25519)
            .finish()
    }
}

impl Signer for Ed25519Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.key.sign(message).to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

/// The body of the `tlscrypto_key_parse` fuzz target, not part of the API:
/// [`load_der`] on `der`, which must not panic and must agree with
/// [`key_algorithm`].  A key it loads is of the type that names, signs
/// `der` with that type's scheme, and, for the types this provider
/// verifies, P-256, P-384 and Ed25519, gives a signature the provider's
/// own verifier takes under the key's public key; a key it refuses as RSA
/// is RSA, and any other it refuses has no type.  Returns whether the key
/// loaded.
#[doc(hidden)]
pub fn fuzz_key_parse(der: &[u8]) -> bool {
    use rustls::pki_types::SignatureVerificationAlgorithm;
    let algorithm = key_algorithm(der);
    let key = match load_der(der) {
        Ok(key) => key,
        Err(Error::General(text)) => {
            let rsa = text == RSA_KEY_REFUSED;
            assert_eq!(rsa, algorithm == Some(KeyAlgorithm::Rsa), "{text}");
            assert!(rsa || algorithm.is_none(), "{text}, yet {algorithm:?}");
            return false;
        }
        Err(other) => panic!("load_der refused with {other:?}"),
    };
    let (scheme, verify, public_len): (_, Option<&dyn SignatureVerificationAlgorithm>, _) =
        match algorithm {
            Some(KeyAlgorithm::EcdsaP256) => (
                SignatureScheme::ECDSA_NISTP256_SHA256,
                Some(crate::verify::ECDSA_P256_SHA256),
                65,
            ),
            Some(KeyAlgorithm::EcdsaP384) => (
                SignatureScheme::ECDSA_NISTP384_SHA384,
                Some(crate::verify::ECDSA_P384_SHA384),
                97,
            ),
            Some(KeyAlgorithm::EcdsaP521) => (SignatureScheme::ECDSA_NISTP521_SHA512, None, 133),
            Some(KeyAlgorithm::Ed25519) => {
                (SignatureScheme::ED25519, Some(crate::verify::ED25519), 32)
            }
            other => panic!("load_der loaded a key key_algorithm reads as {other:?}"),
        };
    let signature = key
        .choose_scheme(&[scheme])
        .expect("the key's own scheme")
        .sign(der)
        .expect("signed");
    let spki = key.public_key().expect("a loaded key's public key");
    let spki = spki.as_ref();
    // The SubjectPublicKeyInfo ends with the key, the content of its BIT
    // STRING after the unused-bits byte.
    let public = spki
        .len()
        .checked_sub(public_len)
        .and_then(|start| spki.get(start..))
        .expect("a SubjectPublicKeyInfo longer than its key");
    if let Some(verify) = verify {
        assert!(
            verify.verify_signature(public, der, &signature).is_ok(),
            "{scheme:?}: the key's own signature"
        );
    }
    true
}

/// The timing check's hold on the signing keys (`crate::ct_check`,
/// ADR-0015 T10), which must choose the secret each signature is made
/// with: a key made from a secret the check picks, signing through this
/// module's own code with the hedge or the nonce fixed.  The curves' trait
/// and the key types stay private to this module; these two types hold
/// them for the check.
#[cfg(test)]
pub(crate) mod timing {
    use std::sync::Arc;

    use curve25519_dalek::scalar::Scalar;
    use rustls::SignatureScheme;

    use super::{EcdsaSigner, EcdsaSigningKey, Ed25519SigningKey, SigningCurve};

    /// An ECDSA key on P-256, P-384 or P-521.
    pub(crate) struct Ecdsa(Box<dyn EcdsaKey>);

    impl Ecdsa {
        /// The key on the curve of `scheme`, one of the three ECDSA schemes
        /// the keys sign with, whose scalar `scalar` encodes, big-endian at
        /// the field's length; `None` for another scheme, or for a scalar
        /// not in `[1, n)` or of another length.
        pub(crate) fn new(scheme: SignatureScheme, scalar: &[u8]) -> Option<Ecdsa> {
            fn on<C: SigningCurve>(scalar: &[u8]) -> Option<Ecdsa> {
                let key = EcdsaSigningKey::<C>::new(C::key_from_scalar(scalar)?);
                Some(Ecdsa(Box::new(key)))
            }
            match scheme {
                SignatureScheme::ECDSA_NISTP256_SHA256 => on::<p256::NistP256>(scalar),
                SignatureScheme::ECDSA_NISTP384_SHA384 => on::<p384::NistP384>(scalar),
                SignatureScheme::ECDSA_NISTP521_SHA512 => on::<p521::NistP521>(scalar),
                _ => None,
            }
        }

        /// The handshake signer's signature of `message`, with `hedge`, at
        /// the field's length, in place of its draw from the process
        /// generator.
        pub(crate) fn sign_hedged(&self, message: &[u8], hedge: &[u8]) -> Vec<u8> {
            self.0.sign_hedged(message, hedge)
        }

        /// The signature of `message` with `nonce`, big-endian at the
        /// field's length, as the nonce, or `None` when it is not in
        /// `[1, n)` or gives a signature of zero.
        pub(crate) fn sign_with_nonce(&self, nonce: &[u8], message: &[u8]) -> Option<Vec<u8>> {
            self.0.sign_with_nonce(nonce, message)
        }

        /// The uncompressed SEC 1 encoding of the public point.
        pub(crate) fn public(&self) -> Vec<u8> {
            self.0.public()
        }
    }

    /// [`Ecdsa`]'s operations on a key of one curve.
    trait EcdsaKey {
        fn sign_hedged(&self, message: &[u8], hedge: &[u8]) -> Vec<u8>;
        fn sign_with_nonce(&self, nonce: &[u8], message: &[u8]) -> Option<Vec<u8>>;
        fn public(&self) -> Vec<u8>;
    }

    impl<C: SigningCurve> EcdsaKey for EcdsaSigningKey<C> {
        fn sign_hedged(&self, message: &[u8], hedge: &[u8]) -> Vec<u8> {
            let signer = EcdsaSigner::<C> {
                key: Arc::clone(&self.key),
            };
            signer.sign_drawing(message, |drawn| drawn.copy_from_slice(hedge))
        }

        fn sign_with_nonce(&self, nonce: &[u8], message: &[u8]) -> Option<Vec<u8>> {
            EcdsaSigningKey::<C>::sign_with_nonce(self, nonce, message)
        }

        fn public(&self) -> Vec<u8> {
            C::public(&self.key)
        }
    }

    /// An Ed25519 key made from an expanded scalar and prefix.
    pub(crate) struct Ed25519(Ed25519SigningKey);

    impl Ed25519 {
        /// The key for `scalar`, which is reduced mod L as a seed's
        /// expanded scalar is, and `prefix`.
        pub(crate) fn new(scalar: [u8; 32], prefix: [u8; 32]) -> Ed25519 {
            Ed25519(Ed25519SigningKey::from_expanded(scalar, prefix))
        }

        /// The handshake signer's signature of `message`, its nonce hashed
        /// from the prefix and the message.
        pub(crate) fn sign(&self, message: &[u8]) -> [u8; 64] {
            self.0.key.sign(message)
        }

        /// The signature of `message` with `r` as the nonce, in place of
        /// SHA-512(prefix || message) mod L: the signer's own code from
        /// there, with nothing reduced first.
        pub(crate) fn sign_with_nonce(&self, r: &Scalar, message: &[u8]) -> [u8; 64] {
            self.0.key.sign_with(r, message)
        }

        /// The public key, compressed.
        pub(crate) fn public(&self) -> [u8; 32] {
            self.0.key.public
        }
    }
}

#[cfg(test)]
// Test-harness arithmetic over bounded lengths.
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use dcroxide_testutil::unhex;
    use ecdsa::signature::Verifier;

    use super::*;

    /// An RFC 6979 known answer: the key, its public point, and the
    /// message, nonce and signature of each case on the curve's own hash.
    struct Rfc6979 {
        key: &'static str,
        public: &'static str,
        cases: &'static [(&'static str, &'static str, &'static str, &'static str)],
    }

    /// RFC 6979 §A.2.5, NIST P-256 with SHA-256.
    const P256_VECTORS: Rfc6979 = Rfc6979 {
        key: "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        public: "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6\
                 7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
        cases: &[
            (
                "sample",
                "a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60",
                "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
                "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
            ),
            (
                "test",
                "d16b6ae827f17175e040871a1c7ec3500192c4c92677336ec2537acaee0008e0",
                "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367",
                "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083",
            ),
        ],
    };

    /// RFC 6979 §A.2.6, NIST P-384 with SHA-384.
    const P384_VECTORS: Rfc6979 = Rfc6979 {
        key: "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d8\
              96d5724e4c70a825f872c9ea60d2edf5",
        public: "04ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64\
                 def8f0ea9055866064a254515480bc138015d9b72d7d57244ea8ef9ac0c62189\
                 6708a59367f9dfb9f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720",
        cases: &[
            (
                "sample",
                "94ed910d1a099dad3254e9242ae85abde4ba15168eaf0ca87a555fd56d10fbca\
                 2907e3e83ba95368623b8c4686915cf9",
                "94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c\
                 81a648152e44acf96e36dd1e80fabe46",
                "99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94f\
                 a329c145786e679e7b82c71a38628ac8",
            ),
            (
                "test",
                "015ee46a5bf88773ed9123a5ab0807962d193719503c527b031b4c2d225092ad\
                 a71f4a459bc0da98adb95837db8312ea",
                "8203b63d3c853e8d77227fb377bcf7b7b772e97892a80f36ab775d509d7a5feb\
                 0542a7f0812998da8f1dd3ca3cf023db",
                "ddd0760448d42d8a43af45af836fce4de8be06b485e9b61b827c2f13173923e0\
                 6a739f040649a667bf3b828246baa5a5",
            ),
        ],
    };

    /// RFC 6979 §A.2.7, NIST P-521 with SHA-512.
    const P521_VECTORS: Rfc6979 = Rfc6979 {
        key: "00fad06daa62ba3b25d2fb40133da757205de67f5bb0018fee8c86e1b68c7e75ca\
              a896eb32f1f47c70855836a6d16fcc1466f6d8fbec67db89ec0c08b0e996b83538",
        public: "0401894550d0785932e00eaa23b694f213f8c3121f86dc97a04e5a7167db4e5bcd\
                 371123d46e45db6b5d5370a7f20fb633155d38ffa16d2bd761dcac474b9a2f5023\
                 a400493101c962cd4d2fddf782285e64584139c2f91b47f87ff82354d6630f746a\
                 28a0db25741b5b34a828008b22acc23f924faafbd4d33f81ea66956dfeaa2bfdfcf5",
        cases: &[(
            "sample",
            "01dae2ea071f8110dc26882d4d5eae0621a3256fc8847fb9022e2b7d28e6f10198\
             b1574fdd03a9053c08a1854a168aa5a57470ec97dd5ce090124ef52a2f7ecbffd3",
            "00c328fafcbd79dd77850370c46325d987cb525569fb63c5d3bc53950e6d4c5f17\
             4e25a1ee9017b5d450606add152b534931d7d4e8455cc91f9b15bf05ec36e377fa",
            "00617cce7cf5064806c467f678d3b4080d6f1cc50af26ca209417308281b68af28\
             2623eaa63e5b5c0723d8b8c37ff0777b1a20f8ccb1dccc43997f1ee0e44da4a67a",
        )],
    };

    /// The RFC's public point is the key's, and with no hedge each
    /// signature is RFC 6979's deterministic one, the one its nonce gives.
    fn check_rfc6979<C: SigningCurve>(
        vectors: &Rfc6979,
        key: C::Key,
        der: impl Fn(&str, &str) -> Vec<u8>,
    ) {
        let key = EcdsaSigningKey::<C>::new(key);
        let public = unhex(vectors.public);
        assert_eq!(
            key.spki.as_ref(),
            public_key_to_spki(&C::ALG_ID, &public).as_ref(),
            "{:?}: the public key",
            C::SCHEME
        );
        for (message, nonce, r, s) in vectors.cases {
            let want = der(r, s);
            assert_eq!(
                key.sign_deterministic(message.as_bytes()),
                want,
                "{:?}, {message:?}",
                C::SCHEME
            );
            assert_eq!(
                key.sign_with_nonce(&unhex(nonce), message.as_bytes()),
                Some(want),
                "{:?}, {message:?}, with the RFC's nonce",
                C::SCHEME
            );
        }
    }

    /// RFC 6979's known answers for each curve on the hash its TLS scheme
    /// names, through the signer with an empty hedge.
    #[test]
    fn ecdsa_answers_rfc_6979() {
        check_rfc6979::<p256::NistP256>(
            &P256_VECTORS,
            p256::ecdsa::SigningKey::from_slice(&unhex(P256_VECTORS.key)).expect("the key"),
            |r, s| {
                p256::ecdsa::Signature::from_slice(&[unhex(r), unhex(s)].concat())
                    .expect("r and s")
                    .to_der()
                    .as_bytes()
                    .to_vec()
            },
        );
        check_rfc6979::<p384::NistP384>(
            &P384_VECTORS,
            p384::ecdsa::SigningKey::from_slice(&unhex(P384_VECTORS.key)).expect("the key"),
            |r, s| {
                p384::ecdsa::Signature::from_slice(&[unhex(r), unhex(s)].concat())
                    .expect("r and s")
                    .to_der()
                    .as_bytes()
                    .to_vec()
            },
        );
        check_rfc6979::<p521::NistP521>(
            &P521_VECTORS,
            p521::ecdsa::SigningKey::from_slice(&unhex(P521_VECTORS.key)).expect("the key"),
            |r, s| {
                p521::ecdsa::Signature::from_slice(&[unhex(r), unhex(s)].concat())
                    .expect("r and s")
                    .to_der()
                    .as_bytes()
                    .to_vec()
            },
        );
    }

    /// The handshake signer draws a hedge of the field's length, 32, 48 or
    /// 66 bytes, from a zeroed buffer, and signs with it as the RFC 6979
    /// additional data; from the process generator two signatures of one
    /// message differ, neither is the deterministic one, and both verify.
    #[test]
    fn ecdsa_signatures_are_hedged() {
        fn check<C: SigningCurve>(
            key: C::Key,
            field_len: usize,
            verifies: impl Fn(&[u8], &[u8]) -> bool,
        ) {
            let key = EcdsaSigningKey::<C>::new(key);
            let signer = EcdsaSigner::<C> {
                key: Arc::clone(&key.key),
            };
            let message = b"a TLS 1.3 CertificateVerify's content";
            let mut drawn = None;
            let hedged = signer.sign_drawing(message, |hedge| {
                drawn = Some(hedge.to_vec());
                hedge.fill(0x5a);
            });
            assert_eq!(drawn, Some(vec![0; field_len]), "{:?}", C::SCHEME);
            assert_eq!(hedged, C::sign(&key.key, message, &vec![0x5a; field_len]));
            let deterministic = key.sign_deterministic(message);
            assert_ne!(hedged, deterministic, "{:?}", C::SCHEME);
            let first = signer.sign(message).expect("signed");
            let second = signer.sign(message).expect("signed");
            assert_ne!(first, second, "{:?}", C::SCHEME);
            assert_ne!(first, deterministic, "{:?}", C::SCHEME);
            for signature in [&first, &second, &hedged, &deterministic] {
                assert!(verifies(message, signature), "{:?}", C::SCHEME);
            }
        }
        let p256 = p256::ecdsa::SigningKey::from_slice(&[7; 32]).expect("a key");
        let p256_public = *p256.verifying_key();
        check::<p256::NistP256>(p256, 32, |message, signature| {
            p256::ecdsa::DerSignature::from_bytes(signature)
                .is_ok_and(|signature| p256_public.verify(message, &signature).is_ok())
        });
        let p384 = p384::ecdsa::SigningKey::from_slice(&[7; 48]).expect("a key");
        let p384_public = *p384.verifying_key();
        check::<p384::NistP384>(p384, 48, |message, signature| {
            p384::ecdsa::DerSignature::from_bytes(signature)
                .is_ok_and(|signature| p384_public.verify(message, &signature).is_ok())
        });
        let mut scalar = [7; 66];
        scalar[0] = 1;
        let p521 = p521::ecdsa::SigningKey::from_slice(&scalar).expect("a key");
        let p521_public = *p521.verifying_key();
        check::<p521::NistP521>(p521, 66, |message, signature| {
            p521::ecdsa::DerSignature::from_bytes(signature)
                .is_ok_and(|signature| p521_public.verify(message, &signature).is_ok())
        });
    }

    /// Each key offers its one scheme wherever the peer lists it, and
    /// nothing when the peer does not; its signer names that scheme.
    #[test]
    fn each_key_offers_its_one_scheme() {
        let p256 = |byte| sec1_key(P256_OID, &[byte; 32]);
        let mut p521 = [7; 66];
        p521[0] = 1;
        let keys = [
            (
                p256(7),
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureAlgorithm::ECDSA,
            ),
            (
                sec1_key(P384_OID, &[7; 48]),
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureAlgorithm::ECDSA,
            ),
            (
                sec1_key(P521_OID, &p521),
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureAlgorithm::ECDSA,
            ),
            (
                ed25519_key(&[7; 32]),
                SignatureScheme::ED25519,
                SignatureAlgorithm::ED25519,
            ),
        ];
        let all = [
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
        ];
        for (der, scheme, algorithm) in keys {
            let key = load_der(&der).expect("a key");
            assert_eq!(key.algorithm(), algorithm, "{scheme:?}");
            let signer = key.choose_scheme(&all).expect("its scheme offered");
            assert_eq!(signer.scheme(), scheme);
            assert!(!signer.sign(b"message").expect("signed").is_empty());
            let others: Vec<_> = all.iter().copied().filter(|s| *s != scheme).collect();
            assert!(key.choose_scheme(&others).is_none(), "{scheme:?}");
            assert!(key.choose_scheme(&[]).is_none(), "{scheme:?}");
            assert!(key.choose_scheme(&[scheme]).is_some(), "{scheme:?}");
        }
    }

    /// `prime256v1`, `secp384r1` and `secp521r1`.
    const P256_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    const P384_OID: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
    const P521_OID: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x23];

    /// A DER element: `tag`, a short-form length and `content`.
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag, u8::try_from(content.len()).expect("short")];
        out.extend_from_slice(content);
        out
    }

    /// A SEC 1 key on `curve` with `scalar` and no public key.
    fn sec1_key(curve: &[u8], scalar: &[u8]) -> Vec<u8> {
        tlv(
            0x30,
            &[
                tlv(0x02, &[1]),
                tlv(0x04, scalar),
                tlv(0xa0, &tlv(0x06, curve)),
            ]
            .concat(),
        )
    }

    /// A PKCS#8 Ed25519 key with `seed`.
    fn ed25519_key(seed: &[u8; 32]) -> Vec<u8> {
        tlv(
            0x30,
            &[
                tlv(0x02, &[0]),
                tlv(0x30, &tlv(0x06, &[0x2b, 0x65, 0x70])),
                tlv(0x04, &tlv(0x04, seed)),
            ]
            .concat(),
        )
    }

    /// RFC 8032 §7.1's first three Ed25519 tests: the public key and the
    /// signature from the seed, and from the expanded key, made through the
    /// timing check's constructor, with the nonce the RFC derives given to
    /// the signer's `sign_with`.
    #[test]
    fn ed25519_answers_rfc_8032() {
        for (seed, public, message, signature) in [
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
                 5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
                 085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
            (
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac\
                 18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
        ] {
            let seed = <[u8; 32]>::try_from(unhex(seed)).expect("32 bytes");
            let (public, message, signature) = (unhex(public), unhex(message), unhex(signature));
            let key = load_der(&ed25519_key(&seed)).expect("the key");
            assert_eq!(
                key.public_key().expect("its public key").as_ref(),
                public_key_to_spki(&alg_id::ED25519, &public).as_ref()
            );
            let signer = key
                .choose_scheme(&[SignatureScheme::ED25519])
                .expect("ED25519");
            assert_eq!(signer.sign(&message).expect("signed"), signature);

            let hash = Sha512::digest(seed);
            let scalar = clamp_integer(hash[..32].try_into().expect("32 bytes"));
            let prefix: [u8; 32] = hash[32..].try_into().expect("32 bytes");
            let expanded = Ed25519SigningKey::from_expanded(scalar, prefix);
            assert_eq!(expanded.key.public.to_vec(), public);
            let nonce = Scalar::from_bytes_mod_order_wide(
                &Sha512::new()
                    .chain_update(prefix)
                    .chain_update(&message)
                    .finalize()
                    .into(),
            );
            assert_eq!(expanded.key.sign_with(&nonce, &message).to_vec(), signature);
        }
    }

    /// Each refusal has its text: Go's for what Go refuses, this
    /// provider's for the RSA and P-224 keys Go loads; and the type each
    /// key reads as.
    #[test]
    fn each_refusal_has_its_text() {
        let text = |der: &[u8]| match load_der(der) {
            Err(Error::General(text)) => text,
            other => panic!("{der:02x?}: {other:?}"),
        };
        let int = |content: &[u8]| tlv(0x02, content);
        let rsa = tlv(
            0x30,
            &[
                int(&[0]),
                int(&[0x00, 0xc5]),
                int(&[3]),
                int(&[5]),
                int(&[7]),
                int(&[11]),
            ]
            .concat(),
        );
        let p224 = sec1_key(&[0x2b, 0x81, 0x04, 0x00, 0x21], &[1]);
        let x25519 = tlv(
            0x30,
            &[
                tlv(0x02, &[0]),
                tlv(0x30, &tlv(0x06, &[0x2b, 0x65, 0x6e])),
                tlv(0x04, &tlv(0x04, &[7; 32])),
            ]
            .concat(),
        );
        assert_eq!(text(&rsa), RSA_KEY_REFUSED);
        assert_eq!(text(&p224), "unsupported private key: ECDSA P-224");
        assert_eq!(
            text(&x25519),
            "tls: found unknown private key type in PKCS#8 wrapping"
        );
        assert_eq!(text(b"not a key"), "tls: failed to parse private key");
        assert_eq!(text(&[]), "tls: failed to parse private key");

        assert_eq!(key_algorithm(&rsa), Some(KeyAlgorithm::Rsa));
        assert_eq!(
            key_algorithm(&sec1_key(P256_OID, &[7])),
            Some(KeyAlgorithm::EcdsaP256)
        );
        assert_eq!(
            key_algorithm(&sec1_key(P384_OID, &[7])),
            Some(KeyAlgorithm::EcdsaP384)
        );
        assert_eq!(
            key_algorithm(&sec1_key(P521_OID, &[7])),
            Some(KeyAlgorithm::EcdsaP521)
        );
        assert_eq!(
            key_algorithm(&ed25519_key(&[7; 32])),
            Some(KeyAlgorithm::Ed25519)
        );
        for other in [p224, x25519, b"not a key".to_vec()] {
            assert_eq!(key_algorithm(&other), None, "{other:02x?}");
        }
    }

    /// The fuzz target's body loads and signs with each key type, its
    /// signature verified by the provider's own verifier but for P-521's,
    /// refuses an RSA key as RSA, and over every truncation of each key, a
    /// bit flipped in every byte, and inputs from a fixed generator, never
    /// panics.
    #[test]
    fn the_fuzz_body_agrees_with_key_algorithm() {
        let mut p521 = [7; 66];
        p521[0] = 1;
        let keys = [
            sec1_key(P256_OID, &[7; 32]),
            sec1_key(P384_OID, &[7; 48]),
            sec1_key(P521_OID, &p521),
            ed25519_key(&[7; 32]),
        ];
        for key in &keys {
            assert!(fuzz_key_parse(key), "{key:02x?}");
        }
        let int = |content: &[u8]| tlv(0x02, content);
        let rsa = tlv(
            0x30,
            &[
                int(&[0]),
                int(&[0x00, 0xc5]),
                int(&[3]),
                int(&[5]),
                int(&[7]),
                int(&[11]),
            ]
            .concat(),
        );
        assert!(!fuzz_key_parse(&rsa));
        let mut loaded = 0;
        for key in keys.iter().chain([&rsa]) {
            for len in 0..key.len() {
                loaded += usize::from(fuzz_key_parse(&key[..len]));
            }
            for at in 0..key.len() {
                let mut flipped = key.clone();
                flipped[at] ^= 0x01;
                loaded += usize::from(fuzz_key_parse(&flipped));
            }
        }
        assert!(loaded > 4, "{loaded} mutated keys loaded");
        let mut rng = dcroxide_testutil::SplitMix64(0x4b65_7950_6172_7365);
        for _ in 0..2000 {
            assert!(!fuzz_key_parse(&rng.bytes(200)));
        }
    }

    /// The key provider reads the DER whatever variant a PEM label put it
    /// in, as Go ignores the label, and claims no FIPS validation.
    #[test]
    fn the_key_provider_ignores_the_variant() {
        use rustls::pki_types::{PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};
        let sec1 = sec1_key(P256_OID, &[7]);
        let want = load_der(&sec1)
            .expect("the key")
            .public_key()
            .map(|spki| spki.as_ref().to_vec());
        for der in [
            PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(sec1.clone())),
            PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(sec1.clone())),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(sec1.clone())),
        ] {
            let key = KEY_PROVIDER.load_private_key(der).expect("loaded");
            assert_eq!(key.public_key().map(|spki| spki.as_ref().to_vec()), want);
        }
        assert!(!KEY_PROVIDER.fips());
    }
}
