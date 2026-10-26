// SPDX-License-Identifier: ISC
//! The six TLS 1.2 cipher suites and their record protection, field for
//! field ring's (`rustls-0.23.46/src/crypto/ring/tls12.rs:19-117`).
//!
//! AES-GCM (RFC 5288) takes ring's nonce construction byte for byte
//! (`ring/tls12.rs:284-305`, `:390-406`): the key block gives a four-byte
//! salt and eight further bytes, the write IV is the two together, each
//! record's nonce is that IV XOR the sequence number, as in TLS 1.3, and
//! its last eight bytes go on the wire ahead of the ciphertext as the
//! explicit nonce, so they never repeat under one key.  The reader takes
//! the explicit nonce from the record.  ChaCha20-Poly1305 (RFC 7905 §2)
//! has a twelve-byte IV and no explicit nonce.  The additional data is
//! RFC 5246 §6.2.3.3's, from rustls's `make_tls12_aad`.

use core::marker::PhantomData;

use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, KeySizeUser};
use rustls::crypto::KeyExchangeAlgorithm;
use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, KeyBlockShape, MessageDecrypter,
    MessageEncrypter, NONCE_LEN, Nonce, OutboundOpaqueMessage, OutboundPlainMessage,
    PrefixedPayload, Tls12AeadAlgorithm, UnsupportedOperationError, make_tls12_aad,
};
use rustls::{
    CipherSuite, CipherSuiteCommon, ConnectionTrafficSecrets, Error, SignatureScheme,
    SupportedCipherSuite, Tls12CipherSuite,
};

use crate::aead::{self, AES_GCM_LIMIT, CHACHA20_POLY1305_LIMIT, RecordAead, TAG_LEN, UnusableKey};
use crate::hash::{SHA256, SHA384};
use crate::hmac::{PRF_SHA256, PRF_SHA384};

/// The TLS 1.2 suite TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.
pub static TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: AES_GCM_LIMIT,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_ECDSA_SCHEMES,
        aead_alg: &AES_128_GCM,
        prf_provider: &PRF_SHA256,
    });

/// The TLS 1.2 suite TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.
pub static TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            hash_provider: &SHA384,
            confidentiality_limit: AES_GCM_LIMIT,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_ECDSA_SCHEMES,
        aead_alg: &AES_256_GCM,
        prf_provider: &PRF_SHA384,
    });

/// The TLS 1.2 suite TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.
pub static TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: CHACHA20_POLY1305_LIMIT,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_ECDSA_SCHEMES,
        aead_alg: &CHACHA20_POLY1305,
        prf_provider: &PRF_SHA256,
    });

/// The TLS 1.2 suite TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.
pub static TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: AES_GCM_LIMIT,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_RSA_SCHEMES,
        aead_alg: &AES_128_GCM,
        prf_provider: &PRF_SHA256,
    });

/// The TLS 1.2 suite TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.
pub static TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            hash_provider: &SHA384,
            confidentiality_limit: AES_GCM_LIMIT,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_RSA_SCHEMES,
        aead_alg: &AES_256_GCM,
        prf_provider: &PRF_SHA384,
    });

/// The TLS 1.2 suite TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.
pub static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: CHACHA20_POLY1305_LIMIT,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_RSA_SCHEMES,
        aead_alg: &CHACHA20_POLY1305,
        prf_provider: &PRF_SHA256,
    });

/// The schemes an ECDHE-ECDSA suite signs its key exchange with, in
/// ring's order (`ring/tls12.rs:103-108`).
static TLS12_ECDSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ED25519,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP256_SHA256,
];

/// The schemes an ECDHE-RSA suite signs its key exchange with, in ring's
/// order (`ring/tls12.rs:110-117`).
static TLS12_RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

/// AES-128-GCM's record protection in TLS 1.2.
pub(crate) static AES_128_GCM: Tls12Gcm<Aes128Gcm> = Tls12Gcm(PhantomData);
/// AES-256-GCM's record protection in TLS 1.2.
pub(crate) static AES_256_GCM: Tls12Gcm<Aes256Gcm> = Tls12Gcm(PhantomData);
/// ChaCha20-Poly1305's record protection in TLS 1.2.
pub(crate) static CHACHA20_POLY1305: Tls12ChaCha = Tls12ChaCha;

/// The length of an AES-GCM record's salt, the fixed part of its nonce
/// that the key block gives (RFC 5288 §3).
const GCM_SALT_LEN: usize = 4;

/// The length of the explicit nonce an AES-GCM record carries ahead of
/// its ciphertext (RFC 5288 §3).
const GCM_EXPLICIT_NONCE_LEN: usize = 8;

/// What sealing adds to an AES-GCM record's plaintext: the explicit nonce
/// and the tag.
const GCM_OVERHEAD: usize = GCM_EXPLICIT_NONCE_LEN + TAG_LEN;

/// The longest plaintext a record may carry, 2^14 bytes (RFC 5246
/// §6.2.1).  rustls's own constant, `MAX_FRAGMENT_LEN`, is crate-private
/// (`rustls-0.23.46/src/msgs/fragmenter.rs:4`); ring's decrypters refuse a
/// longer plaintext once it authenticates (`ring/tls12.rs:275-277`,
/// `:356-358`), and so do these.
const MAX_FRAGMENT_LEN: usize = 16_384;

/// The TLS 1.2 record protection of the AES-GCM AEAD `A`.
pub(crate) struct Tls12Gcm<A>(PhantomData<fn() -> A>);

impl<A: RecordAead> Tls12Gcm<A> {
    /// The encrypter for `key`, the four-byte `salt` and the eight
    /// further key-block bytes `explicit`, or one that fails every record
    /// when a length is wrong.
    ///
    /// `Tls12AeadAlgorithm::encrypter` comes here, as do the tests, which
    /// cannot make an `AeadKey` shorter than 32 bytes outside rustls.
    pub(crate) fn encrypter_for(
        &self,
        key: &[u8],
        salt: &[u8],
        explicit: &[u8],
    ) -> Box<dyn MessageEncrypter> {
        match (A::new_from_slice(key), gcm_iv(salt, explicit)) {
            (Ok(aead), Some(iv)) => Box::new(GcmEncrypter { aead, iv }),
            _ => Box::new(UnusableKey),
        }
    }

    /// The decrypter for `key` and the four-byte `salt`, or one that
    /// fails every record when a length is wrong.
    pub(crate) fn decrypter_for(&self, key: &[u8], salt: &[u8]) -> Box<dyn MessageDecrypter> {
        match (A::new_from_slice(key), <[u8; GCM_SALT_LEN]>::try_from(salt)) {
            (Ok(aead), Ok(salt)) => Box::new(GcmDecrypter { aead, salt }),
            _ => Box::new(UnusableKey),
        }
    }
}

impl<A: RecordAead> Tls12AeadAlgorithm for Tls12Gcm<A> {
    fn encrypter(&self, key: AeadKey, iv: &[u8], extra: &[u8]) -> Box<dyn MessageEncrypter> {
        self.encrypter_for(key.as_ref(), iv, extra)
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        self.decrypter_for(key.as_ref(), iv)
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: A::key_size(),
            fixed_iv_len: GCM_SALT_LEN,
            explicit_nonce_len: GCM_EXPLICIT_NONCE_LEN,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        let iv = gcm_iv(iv, explicit).ok_or(UnsupportedOperationError)?;
        Ok(A::traffic_secrets(key, iv))
    }
}

/// The AES-GCM write IV: the salt and then the explicit-nonce bytes of the
/// key block, as ring builds it (`ring/tls12.rs:390-406`), or `None` when
/// either has the wrong length.
fn gcm_iv(salt: &[u8], explicit: &[u8]) -> Option<Iv> {
    let salt = <[u8; GCM_SALT_LEN]>::try_from(salt).ok()?;
    let explicit = <[u8; GCM_EXPLICIT_NONCE_LEN]>::try_from(explicit).ok()?;
    let mut iv = [0; NONCE_LEN];
    let (front, back) = iv.split_at_mut(GCM_SALT_LEN);
    front.copy_from_slice(&salt);
    back.copy_from_slice(&explicit);
    Some(Iv::from(iv))
}

/// Seals TLS 1.2 AES-GCM records under one key.
struct GcmEncrypter<A> {
    /// The keyed AEAD, wiped when dropped.
    aead: A,
    /// The write IV, salt first.
    iv: Iv,
}

impl<A: RecordAead> MessageEncrypter for GcmEncrypter<A> {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = msg
            .payload
            .len()
            .checked_add(GCM_OVERHEAD)
            .ok_or(Error::EncryptError)?;
        let nonce = Nonce::new(&self.iv, seq).0;
        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        let (_, explicit) = nonce.split_at(GCM_SALT_LEN);
        payload.extend_from_slice(explicit);
        payload.extend_from_chunks(&msg.payload);
        let (_, body) = payload.as_mut().split_at_mut(GCM_EXPLICIT_NONCE_LEN);
        let tag = aead::seal(&self.aead, nonce, &aad, body)?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len.saturating_add(GCM_OVERHEAD)
    }
}

/// Opens TLS 1.2 AES-GCM records under one key.
struct GcmDecrypter<A> {
    /// The keyed AEAD, wiped when dropped.
    aead: A,
    /// The fixed part of every nonce.
    salt: [u8; GCM_SALT_LEN],
}

impl<A: RecordAead> MessageDecrypter for GcmDecrypter<A> {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        let end = payload
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(Error::DecryptError)?;
        let plain_len = end
            .checked_sub(GCM_EXPLICIT_NONCE_LEN)
            .ok_or(Error::DecryptError)?;
        let (explicit, sealed) = payload.split_at_mut(GCM_EXPLICIT_NONCE_LEN);
        let mut nonce = [0; NONCE_LEN];
        let (front, back) = nonce.split_at_mut(GCM_SALT_LEN);
        front.copy_from_slice(&self.salt);
        back.copy_from_slice(explicit);
        let aad = make_tls12_aad(seq, msg.typ, msg.version, plain_len);
        aead::open(&self.aead, nonce, &aad, sealed)?;
        if plain_len > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }
        // The plaintext stays where it was decrypted, after the explicit
        // nonce, as rustls's aws-lc-rs provider leaves it
        // (`rustls-0.23.46/src/crypto/aws_lc_rs/tls12.rs:297-299`).
        Ok(msg.into_plain_message_range(GCM_EXPLICIT_NONCE_LEN..end))
    }
}

/// The TLS 1.2 record protection of ChaCha20-Poly1305.
pub(crate) struct Tls12ChaCha;

impl Tls12ChaCha {
    /// The encrypter for `key` and the twelve-byte `iv`, or one that fails
    /// every record when a length is wrong.
    pub(crate) fn encrypter_for(&self, key: &[u8], iv: &[u8]) -> Box<dyn MessageEncrypter> {
        match (
            ChaCha20Poly1305::new_from_slice(key),
            <[u8; NONCE_LEN]>::try_from(iv),
        ) {
            (Ok(aead), Ok(iv)) => Box::new(ChaChaEncrypter {
                aead,
                iv: Iv::from(iv),
            }),
            _ => Box::new(UnusableKey),
        }
    }

    /// The decrypter for `key` and the twelve-byte `iv`, or one that fails
    /// every record when a length is wrong.
    pub(crate) fn decrypter_for(&self, key: &[u8], iv: &[u8]) -> Box<dyn MessageDecrypter> {
        match (
            ChaCha20Poly1305::new_from_slice(key),
            <[u8; NONCE_LEN]>::try_from(iv),
        ) {
            (Ok(aead), Ok(iv)) => Box::new(ChaChaDecrypter {
                aead,
                iv: Iv::from(iv),
            }),
            _ => Box::new(UnusableKey),
        }
    }
}

impl Tls12AeadAlgorithm for Tls12ChaCha {
    fn encrypter(&self, key: AeadKey, iv: &[u8], _extra: &[u8]) -> Box<dyn MessageEncrypter> {
        self.encrypter_for(key.as_ref(), iv)
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        self.decrypter_for(key.as_ref(), iv)
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: ChaCha20Poly1305::key_size(),
            fixed_iv_len: NONCE_LEN,
            explicit_nonce_len: 0,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        _explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        let iv = <[u8; NONCE_LEN]>::try_from(iv).map_err(|_| UnsupportedOperationError)?;
        Ok(ChaCha20Poly1305::traffic_secrets(key, Iv::from(iv)))
    }
}

/// Seals TLS 1.2 ChaCha20-Poly1305 records under one key.
struct ChaChaEncrypter {
    /// The keyed AEAD, wiped when dropped.
    aead: ChaCha20Poly1305,
    /// The write IV.
    iv: Iv,
}

impl MessageEncrypter for ChaChaEncrypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = msg
            .payload
            .len()
            .checked_add(TAG_LEN)
            .ok_or(Error::EncryptError)?;
        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_chunks(&msg.payload);
        let tag = aead::seal(
            &self.aead,
            Nonce::new(&self.iv, seq).0,
            &aad,
            payload.as_mut(),
        )?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len.saturating_add(TAG_LEN)
    }
}

/// Opens TLS 1.2 ChaCha20-Poly1305 records under one key.
struct ChaChaDecrypter {
    /// The keyed AEAD, wiped when dropped.
    aead: ChaCha20Poly1305,
    /// The read IV.
    iv: Iv,
}

impl MessageDecrypter for ChaChaDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        let plain_len = payload
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(Error::DecryptError)?;
        let aad = make_tls12_aad(seq, msg.typ, msg.version, plain_len);
        aead::open(&self.aead, Nonce::new(&self.iv, seq).0, &aad, payload)?;
        if plain_len > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }
        payload.truncate(plain_len);
        Ok(msg.into_plain_message())
    }
}

#[cfg(test)]
// Test-harness arithmetic over record lengths and offsets.
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use aes_gcm::aead::array::Array;
    use rustls::crypto::cipher::OutboundChunks;
    use rustls::{ContentType, ProtocolVersion};

    use super::*;

    /// The sequence numbers each AEAD is checked at: the first two, the
    /// last before AES-GCM's confidentiality limit, and the last a
    /// connection can reach.
    const SEQS: [u64; 4] = [0, 1, (1 << 24) - 1, u64::MAX];

    /// A key of up to 32 bytes, no two alike.
    const KEY: [u8; 32] = [
        0x3c, 0xa7, 0x10, 0x5e, 0xd9, 0x82, 0x4b, 0xf6, 0x21, 0x6d, 0xb8, 0x07, 0xe4, 0x95, 0x3a,
        0xcf, 0x58, 0x13, 0xae, 0x7b, 0x02, 0xe6, 0x91, 0x4c, 0xbd, 0x68, 0x35, 0xf0, 0x8e, 0x29,
        0xd4, 0x77,
    ];

    /// Twelve bytes of key block after the key: an AES-GCM salt and
    /// explicit-nonce seed, or a ChaCha20-Poly1305 IV.
    const IV: [u8; 12] = [
        0x6e, 0xc1, 0x0a, 0x95, 0x47, 0xf2, 0x38, 0xdb, 0x84, 0x1f, 0xa6, 0x53,
    ];

    /// RFC 5246 §6.2.3.3's additional data for a record of `typ` carrying
    /// `len` bytes of plaintext at `seq`.
    fn aad(seq: u64, typ: u8, len: usize) -> Vec<u8> {
        let len = u16::try_from(len).expect("a record's length");
        [
            &seq.to_be_bytes()[..],
            &[typ, 0x03, 0x03],
            &len.to_be_bytes(),
        ]
        .concat()
    }

    /// The nonce at `seq`: the IV with the sequence number's eight
    /// big-endian bytes XORed into its last eight.
    fn nonce(seq: u64) -> [u8; 12] {
        let mut nonce = IV;
        for (n, s) in nonce[4..].iter_mut().zip(seq.to_be_bytes()) {
            *n ^= s;
        }
        nonce
    }

    /// `plaintext` sealed on the AEAD crate directly under `nonce` and
    /// `aad`, with its tag.
    fn sealed_by_hand<A: RecordAead>(
        key: &[u8],
        nonce: [u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Vec<u8> {
        let mut body = plaintext.to_vec();
        let tag = A::new_from_slice(key)
            .expect("the key")
            .encrypt_inout_detached(&Array::from(nonce), aad, body.as_mut_slice().into())
            .expect("sealed");
        body.extend_from_slice(&tag);
        body
    }

    /// The AES-GCM record body RFC 5288 gives `plaintext` of content type
    /// `typ` at `seq`: the explicit nonce, the ciphertext, the tag.
    fn gcm_by_hand<A: RecordAead>(key: &[u8], seq: u64, typ: u8, plaintext: &[u8]) -> Vec<u8> {
        let nonce = nonce(seq);
        let sealed = sealed_by_hand::<A>(key, nonce, &aad(seq, typ, plaintext.len()), plaintext);
        [&nonce[4..], &sealed].concat()
    }

    /// The ChaCha20-Poly1305 record body RFC 7905 gives `plaintext` of
    /// content type `typ` at `seq`: the ciphertext and the tag.
    fn chacha_by_hand(seq: u64, typ: u8, plaintext: &[u8]) -> Vec<u8> {
        sealed_by_hand::<ChaCha20Poly1305>(
            &KEY,
            nonce(seq),
            &aad(seq, typ, plaintext.len()),
            plaintext,
        )
    }

    /// Seal `plaintext` with `encrypter` at `seq` as a record of `typ`.
    fn seal(
        encrypter: &mut dyn MessageEncrypter,
        seq: u64,
        typ: ContentType,
        plaintext: &[u8],
    ) -> Result<OutboundOpaqueMessage, Error> {
        encrypter.encrypt(
            OutboundPlainMessage {
                typ,
                version: ProtocolVersion::TLSv1_2,
                payload: OutboundChunks::Single(plaintext),
            },
            seq,
        )
    }

    /// Open `body`, a record of `typ` and `version`, with `decrypter` at
    /// `seq`, returning its content type, version and plaintext.
    fn open(
        decrypter: &mut dyn MessageDecrypter,
        seq: u64,
        typ: ContentType,
        version: ProtocolVersion,
        body: &mut [u8],
    ) -> Result<(ContentType, ProtocolVersion, Vec<u8>), Error> {
        let plain = decrypter.decrypt(InboundOpaqueMessage::new(typ, version, body), seq)?;
        Ok((plain.typ, plain.version, plain.payload.to_vec()))
    }

    /// Open an application-data record of TLS 1.2.
    fn open_data(
        decrypter: &mut dyn MessageDecrypter,
        seq: u64,
        body: &mut [u8],
    ) -> Result<Vec<u8>, Error> {
        let (_, _, plaintext) = open(
            decrypter,
            seq,
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            body,
        )?;
        Ok(plaintext)
    }

    /// Each AES-GCM suite seals at each sequence number exactly what the
    /// AEAD crate gives for RFC 5288's nonce and additional data, puts the
    /// nonce's last eight bytes on the wire, and opens both its own records
    /// and those.
    fn gcm_seals_as_rfc_5288_says<A: RecordAead>(aead: &Tls12Gcm<A>, key_len: usize) {
        let key = &KEY[..key_len];
        let long = vec![0xa5; 16_384];
        for seq in SEQS {
            for plaintext in [&b""[..], b"hello", &long] {
                let mut encrypter = aead.encrypter_for(key, &IV[..4], &IV[4..]);
                let sealed = seal(encrypter.as_mut(), seq, ContentType::Handshake, plaintext)
                    .expect("sealed");
                assert_eq!(sealed.typ, ContentType::Handshake);
                assert_eq!(sealed.version, ProtocolVersion::TLSv1_2);
                let expected = gcm_by_hand::<A>(key, seq, 0x16, plaintext);
                assert_eq!(
                    sealed.payload.as_ref(),
                    expected,
                    "seq {seq}, {} bytes",
                    plaintext.len()
                );
                assert_eq!(
                    sealed.payload.as_ref()[..8],
                    nonce(seq)[4..],
                    "the explicit nonce"
                );
                assert_eq!(
                    encrypter.encrypted_payload_len(plaintext.len()),
                    expected.len()
                );

                let mut decrypter = aead.decrypter_for(key, &IV[..4]);
                let mut body = sealed.payload.as_ref().to_vec();
                assert_eq!(
                    open(
                        decrypter.as_mut(),
                        seq,
                        ContentType::Handshake,
                        ProtocolVersion::TLSv1_2,
                        &mut body
                    ),
                    Ok((
                        ContentType::Handshake,
                        ProtocolVersion::TLSv1_2,
                        plaintext.to_vec()
                    )),
                    "seq {seq}"
                );
                // The reader takes the explicit nonce from the record, so
                // a record sealed under another one opens too.
                let mut body = gcm_by_hand::<A>(key, seq, 0x17, plaintext);
                body[..8].copy_from_slice(&[0xee; 8]);
                let mut other = IV;
                other[4..].copy_from_slice(&[0xee; 8]);
                let resealed =
                    sealed_by_hand::<A>(key, other, &aad(seq, 0x17, plaintext.len()), plaintext);
                body[8..].copy_from_slice(&resealed);
                assert_eq!(
                    open_data(decrypter.as_mut(), seq, &mut body),
                    Ok(plaintext.to_vec()),
                    "seq {seq}, another explicit nonce"
                );
            }
        }
    }

    #[test]
    fn aes_128_gcm_seals_as_rfc_5288_says() {
        gcm_seals_as_rfc_5288_says(&AES_128_GCM, 16);
    }

    #[test]
    fn aes_256_gcm_seals_as_rfc_5288_says() {
        gcm_seals_as_rfc_5288_says(&AES_256_GCM, 32);
    }

    /// ChaCha20-Poly1305 seals at each sequence number exactly what the
    /// AEAD crate gives for RFC 7905's nonce and additional data, and opens
    /// both its own records and those.
    #[test]
    fn chacha20_poly1305_seals_as_rfc_7905_says() {
        let long = vec![0xa5; 16_384];
        for seq in SEQS {
            for plaintext in [&b""[..], b"hello", &long] {
                let mut encrypter = CHACHA20_POLY1305.encrypter_for(&KEY, &IV);
                let sealed =
                    seal(encrypter.as_mut(), seq, ContentType::Alert, plaintext).expect("sealed");
                assert_eq!(sealed.typ, ContentType::Alert);
                let expected = chacha_by_hand(seq, 0x15, plaintext);
                assert_eq!(
                    sealed.payload.as_ref(),
                    expected,
                    "seq {seq}, {} bytes",
                    plaintext.len()
                );
                assert_eq!(
                    encrypter.encrypted_payload_len(plaintext.len()),
                    expected.len()
                );

                let mut decrypter = CHACHA20_POLY1305.decrypter_for(&KEY, &IV);
                let mut body = sealed.payload.as_ref().to_vec();
                assert_eq!(
                    open(
                        decrypter.as_mut(),
                        seq,
                        ContentType::Alert,
                        ProtocolVersion::TLSv1_2,
                        &mut body
                    ),
                    Ok((
                        ContentType::Alert,
                        ProtocolVersion::TLSv1_2,
                        plaintext.to_vec()
                    )),
                    "seq {seq}"
                );
                let mut body = chacha_by_hand(seq, 0x17, plaintext);
                assert_eq!(
                    open_data(decrypter.as_mut(), seq, &mut body),
                    Ok(plaintext.to_vec())
                );
            }
        }
    }

    /// A record whose tag, ciphertext, explicit nonce or length was
    /// changed, whose header names another content type or version, or
    /// that is opened at another sequence number, fails as ring's does.
    fn refuses_tampering(
        decrypter: &mut dyn MessageDecrypter,
        by_hand: &dyn Fn(u64) -> Vec<u8>,
        explicit_nonce: bool,
        overhead: usize,
    ) {
        for seq in SEQS {
            let sealed = by_hand(seq);
            let last = sealed.len() - 1;
            let mut changes = vec![("the tag", last), ("the ciphertext", overhead - TAG_LEN)];
            if explicit_nonce {
                changes.push(("the explicit nonce", 0));
                changes.push(("the explicit nonce", 7));
            }
            for (what, at) in changes {
                let mut body = sealed.clone();
                body[at] ^= 0x80;
                assert_eq!(
                    open_data(decrypter, seq, &mut body),
                    Err(Error::DecryptError),
                    "seq {seq}: {what} changed"
                );
            }
            for (typ, version) in [
                (ContentType::Handshake, ProtocolVersion::TLSv1_2),
                (ContentType::ApplicationData, ProtocolVersion::TLSv1_1),
            ] {
                let mut body = sealed.clone();
                assert_eq!(
                    open(decrypter, seq, typ, version, &mut body),
                    Err(Error::DecryptError),
                    "seq {seq}: a header of {typ:?} {version:?}"
                );
            }
            let mut longer = [&sealed[..], &[0]].concat();
            assert_eq!(
                open_data(decrypter, seq, &mut longer),
                Err(Error::DecryptError)
            );
            let mut shorter = sealed[..last].to_vec();
            assert_eq!(
                open_data(decrypter, seq, &mut shorter),
                Err(Error::DecryptError)
            );
            let mut body = sealed.clone();
            assert_eq!(
                open_data(decrypter, seq.wrapping_add(1), &mut body),
                Err(Error::DecryptError),
                "seq {seq} opened as the next"
            );
            let mut body = sealed.clone();
            assert_eq!(
                open_data(decrypter, seq, &mut body),
                Ok(b"a record".to_vec())
            );
        }
        for len in [0, 1, overhead - 1] {
            let mut body = vec![0; len];
            assert_eq!(
                open_data(decrypter, 0, &mut body),
                Err(Error::DecryptError),
                "{len} bytes, shorter than the overhead"
            );
        }
    }

    #[test]
    fn aes_128_gcm_refuses_tampering() {
        let mut decrypter = AES_128_GCM.decrypter_for(&KEY[..16], &IV[..4]);
        let by_hand = |seq| gcm_by_hand::<Aes128Gcm>(&KEY[..16], seq, 0x17, b"a record");
        refuses_tampering(decrypter.as_mut(), &by_hand, true, GCM_OVERHEAD);
    }

    #[test]
    fn aes_256_gcm_refuses_tampering() {
        let mut decrypter = AES_256_GCM.decrypter_for(&KEY, &IV[..4]);
        let by_hand = |seq| gcm_by_hand::<Aes256Gcm>(&KEY, seq, 0x17, b"a record");
        refuses_tampering(decrypter.as_mut(), &by_hand, true, GCM_OVERHEAD);
    }

    #[test]
    fn chacha20_poly1305_refuses_tampering() {
        let mut decrypter = CHACHA20_POLY1305.decrypter_for(&KEY, &IV);
        let by_hand = |seq| chacha_by_hand(seq, 0x17, b"a record");
        refuses_tampering(decrypter.as_mut(), &by_hand, false, TAG_LEN);
    }

    /// An authentic record carrying more than 2^14 bytes of plaintext is
    /// `PeerSentOversizedRecord`, as ring's decrypters make it; one of
    /// exactly 2^14 bytes opens.
    #[test]
    fn an_authentic_oversized_record_is_refused() {
        for (len, expected) in [
            (16_384, Ok(vec![0x5a; 16_384])),
            (16_385, Err(Error::PeerSentOversizedRecord)),
        ] {
            let plaintext = vec![0x5a; len];
            let mut decrypter = AES_256_GCM.decrypter_for(&KEY, &IV[..4]);
            let mut body = gcm_by_hand::<Aes256Gcm>(&KEY, 9, 0x17, &plaintext);
            assert_eq!(
                open_data(decrypter.as_mut(), 9, &mut body),
                expected,
                "AES-GCM, {len} bytes"
            );
            let mut decrypter = CHACHA20_POLY1305.decrypter_for(&KEY, &IV);
            let mut body = chacha_by_hand(9, 0x17, &plaintext);
            assert_eq!(
                open_data(decrypter.as_mut(), 9, &mut body),
                expected,
                "ChaCha20-Poly1305, {len} bytes"
            );
        }
    }

    /// A key, salt, explicit nonce or IV of the wrong length makes an
    /// encrypter and a decrypter that return an error for every record,
    /// where ring's provider panics as it builds them, and secrets that
    /// cannot be extracted.  `UnusableKey` says what rustls then does with
    /// the errors.
    #[test]
    fn a_key_block_of_the_wrong_shape_fails_every_record() {
        let data = || (ContentType::ApplicationData, b"data".as_slice());
        let good_gcm = gcm_by_hand::<Aes128Gcm>(&KEY[..16], 0, 0x17, b"data");
        let gcm = [
            ("a 15-byte key", &KEY[..15], &IV[..4], &IV[4..]),
            ("a 32-byte key", &KEY[..], &IV[..4], &IV[4..]),
            ("a 3-byte salt", &KEY[..16], &IV[..3], &IV[4..]),
            ("a 5-byte salt", &KEY[..16], &IV[..5], &IV[4..]),
            ("a 7-byte explicit nonce", &KEY[..16], &IV[..4], &IV[5..]),
        ];
        for (what, key, salt, explicit) in gcm {
            let (typ, plaintext) = data();
            let mut encrypter = AES_128_GCM.encrypter_for(key, salt, explicit);
            assert_eq!(
                seal(encrypter.as_mut(), 0, typ, plaintext).err(),
                Some(Error::EncryptError),
                "{what}"
            );
            if explicit.len() == 8 {
                let mut decrypter = AES_128_GCM.decrypter_for(key, salt);
                let mut body = good_gcm.clone();
                assert_eq!(
                    open_data(decrypter.as_mut(), 0, &mut body),
                    Err(Error::DecryptError),
                    "{what}"
                );
            }
            if key.len() == 16 {
                assert!(
                    AES_128_GCM
                        .extract_keys(AeadKey::from(KEY), salt, explicit)
                        .is_err(),
                    "{what}"
                );
            }
        }
        // Through the trait, with the one key length rustls lets a caller
        // build, 32 bytes, which AES-128-GCM does not take.
        let mut encrypter = AES_128_GCM.encrypter(AeadKey::from(KEY), &IV[..4], &IV[4..]);
        let (typ, plaintext) = data();
        assert_eq!(
            seal(encrypter.as_mut(), 0, typ, plaintext).err(),
            Some(Error::EncryptError)
        );

        let good_chacha = chacha_by_hand(0, 0x17, b"data");
        let chacha: [(&str, &[u8], &[u8]); 4] = [
            ("a 16-byte key", &KEY[..16], &IV),
            ("a 31-byte key", &KEY[..31], &IV),
            ("an 11-byte IV", &KEY, &IV[..11]),
            ("a 4-byte IV", &KEY, &IV[..4]),
        ];
        for (what, key, iv) in chacha {
            let (typ, plaintext) = data();
            let mut encrypter = CHACHA20_POLY1305.encrypter_for(key, iv);
            assert_eq!(
                seal(encrypter.as_mut(), 0, typ, plaintext).err(),
                Some(Error::EncryptError),
                "{what}"
            );
            let mut decrypter = CHACHA20_POLY1305.decrypter_for(key, iv);
            let mut body = good_chacha.clone();
            assert_eq!(
                open_data(decrypter.as_mut(), 0, &mut body),
                Err(Error::DecryptError),
                "{what}"
            );
            if key.len() == 32 {
                assert!(
                    CHACHA20_POLY1305
                        .extract_keys(AeadKey::from(KEY), iv, &[])
                        .is_err(),
                    "{what}"
                );
            }
        }
    }

    /// The key block each AEAD asks rustls for: ring's shapes
    /// (`ring/tls12.rs:151-157`, `:201-207`).
    #[test]
    fn the_key_blocks_are_rings() {
        let shapes: [(&dyn Tls12AeadAlgorithm, usize, usize, usize); 3] = [
            (&AES_128_GCM, 16, 4, 8),
            (&AES_256_GCM, 32, 4, 8),
            (&CHACHA20_POLY1305, 32, 12, 0),
        ];
        for (aead, key, fixed_iv, explicit) in shapes {
            let shape = aead.key_block_shape();
            assert_eq!(
                (
                    shape.enc_key_len,
                    shape.fixed_iv_len,
                    shape.explicit_nonce_len
                ),
                (key, fixed_iv, explicit)
            );
        }
    }

    /// The AEAD a set of extracted secrets names, with its key and IV.
    fn named(secrets: &ConnectionTrafficSecrets) -> (&'static str, Vec<u8>, Vec<u8>) {
        match secrets {
            ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
                ("AES-128-GCM", key.as_ref().to_vec(), iv.as_ref().to_vec())
            }
            ConnectionTrafficSecrets::Aes256Gcm { key, iv } => {
                ("AES-256-GCM", key.as_ref().to_vec(), iv.as_ref().to_vec())
            }
            ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => (
                "ChaCha20-Poly1305",
                key.as_ref().to_vec(),
                iv.as_ref().to_vec(),
            ),
            _ => ("another AEAD", Vec::new(), Vec::new()),
        }
    }

    /// The secrets each AEAD hands out name it and carry the key and the
    /// IV the record layer uses: for AES-GCM the salt and the explicit
    /// nonce's seed together, as ring hands them out.
    #[test]
    fn extracted_secrets_name_the_aead() {
        let gcm = |aead: &dyn Tls12AeadAlgorithm| {
            aead.extract_keys(AeadKey::from(KEY), &IV[..4], &IV[4..])
                .expect("extracted")
        };
        assert_eq!(
            named(&gcm(&AES_128_GCM)),
            ("AES-128-GCM", KEY.to_vec(), IV.to_vec())
        );
        assert_eq!(
            named(&gcm(&AES_256_GCM)),
            ("AES-256-GCM", KEY.to_vec(), IV.to_vec())
        );
        let chacha = CHACHA20_POLY1305
            .extract_keys(AeadKey::from(KEY), &IV, &[])
            .expect("extracted");
        assert_eq!(
            named(&chacha),
            ("ChaCha20-Poly1305", KEY.to_vec(), IV.to_vec())
        );
    }

    /// Each suite carries its hash, the PRF over the same hash, ECDHE,
    /// ring's signature schemes for its key type, the AEAD its name gives
    /// with that AEAD's key block, and ring's confidentiality limit.  Two
    /// of the AEADs take 32-byte keys, so the AEAD is told apart by the
    /// secrets it hands out, which name it.
    #[test]
    fn each_suite_is_assembled_as_its_name_says() {
        let gcm128 = ("AES-128-GCM", (16, 4, 8), 1 << 24);
        let gcm256 = ("AES-256-GCM", (32, 4, 8), 1 << 24);
        let chacha = ("ChaCha20-Poly1305", (32, 12, 0), u64::MAX);
        let suites = [
            (
                TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                32,
                TLS12_ECDSA_SCHEMES,
                gcm128,
            ),
            (
                TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                48,
                TLS12_ECDSA_SCHEMES,
                gcm256,
            ),
            (
                TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                32,
                TLS12_ECDSA_SCHEMES,
                chacha,
            ),
            (
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                32,
                TLS12_RSA_SCHEMES,
                gcm128,
            ),
            (
                TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                48,
                TLS12_RSA_SCHEMES,
                gcm256,
            ),
            (
                TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                32,
                TLS12_RSA_SCHEMES,
                chacha,
            ),
        ];
        for (suite, hash_len, sign, (aead, shape, limit)) in suites {
            let SupportedCipherSuite::Tls12(tls12) = suite else {
                panic!("{suite:?} is a TLS 1.2 suite");
            };
            assert_eq!(
                tls12.common.hash_provider.output_len(),
                hash_len,
                "{suite:?}"
            );
            let mut prf = [0; 64];
            tls12
                .prf_provider
                .for_secret(&mut prf, b"secret", b"label", b"seed");
            let mut other = [0; 64];
            let hmac = if hash_len == 32 {
                &PRF_SHA256
            } else {
                &PRF_SHA384
            };
            rustls::crypto::tls12::Prf::for_secret(hmac, &mut other, b"secret", b"label", b"seed");
            assert_eq!(prf, other, "{suite:?}: the PRF over its hash");
            assert_eq!(tls12.kx, KeyExchangeAlgorithm::ECDHE, "{suite:?}");
            assert_eq!(tls12.sign, sign, "{suite:?}");
            let block = tls12.aead_alg.key_block_shape();
            assert_eq!(
                (
                    block.enc_key_len,
                    block.fixed_iv_len,
                    block.explicit_nonce_len
                ),
                shape,
                "{suite:?}"
            );
            let (iv, explicit) = IV.split_at(block.fixed_iv_len);
            let secrets = tls12
                .aead_alg
                .extract_keys(
                    AeadKey::from(KEY),
                    iv,
                    &explicit[..block.explicit_nonce_len],
                )
                .expect("extracted");
            assert_eq!(named(&secrets).0, aead, "{suite:?}");
            assert_eq!(tls12.common.confidentiality_limit, limit, "{suite:?}");
            assert!(!suite.fips(), "{suite:?}");
        }
    }
}
