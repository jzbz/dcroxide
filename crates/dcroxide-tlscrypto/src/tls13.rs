// SPDX-License-Identifier: ISC
//! The three TLS 1.3 cipher suites and their record protection
//! (RFC 8446 §5.2), field for field ring's
//! (`rustls-0.23.46/src/crypto/ring/tls13.rs:19-82`) but for QUIC, which the
//! node does not speak and whose key builders ring's suites carry.
//!
//! A record's nonce is the write IV XOR the sequence number and its
//! additional data the record header, both made by rustls's own helpers
//! (`Nonce::new`, `make_tls13_aad`); the body is the plaintext and its
//! content type, sealed in place with the tag appended.  Opening it leaves
//! the inner plaintext to rustls's `into_tls13_unpadded_message`, which
//! strips the padding and applies the length and content-type checks, as it
//! does for ring's.

use core::marker::PhantomData;

use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter, MessageEncrypter,
    Nonce, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload, Tls13AeadAlgorithm,
    UnsupportedOperationError, make_tls13_aad,
};
use rustls::{
    CipherSuite, CipherSuiteCommon, ConnectionTrafficSecrets, ContentType, Error, ProtocolVersion,
    SupportedCipherSuite, Tls13CipherSuite,
};

use crate::aead::{self, AES_GCM_LIMIT, CHACHA20_POLY1305_LIMIT, RecordAead, TAG_LEN, UnusableKey};
use crate::hash::{SHA256, SHA384};
use crate::hmac::{HKDF_SHA256, HKDF_SHA384};

/// The TLS 1.3 suite TLS_AES_128_GCM_SHA256.
pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: AES_GCM_LIMIT,
        },
        hkdf_provider: &HKDF_SHA256,
        aead_alg: &AES_128_GCM,
        quic: None,
    });

/// The TLS 1.3 suite TLS_AES_256_GCM_SHA384.
pub static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: &SHA384,
            confidentiality_limit: AES_GCM_LIMIT,
        },
        hkdf_provider: &HKDF_SHA384,
        aead_alg: &AES_256_GCM,
        quic: None,
    });

/// The TLS 1.3 suite TLS_CHACHA20_POLY1305_SHA256.
pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: CHACHA20_POLY1305_LIMIT,
        },
        hkdf_provider: &HKDF_SHA256,
        aead_alg: &CHACHA20_POLY1305,
        quic: None,
    });

/// AES-128-GCM's record protection in TLS 1.3.
pub(crate) static AES_128_GCM: Tls13Aead<Aes128Gcm> = Tls13Aead(PhantomData);
/// AES-256-GCM's record protection in TLS 1.3.
pub(crate) static AES_256_GCM: Tls13Aead<Aes256Gcm> = Tls13Aead(PhantomData);
/// ChaCha20-Poly1305's record protection in TLS 1.3.
pub(crate) static CHACHA20_POLY1305: Tls13Aead<ChaCha20Poly1305> = Tls13Aead(PhantomData);

/// What sealing adds to a record's plaintext: the content type byte and
/// the tag (RFC 8446 §5.2, with no padding).
const OVERHEAD: usize = 1 + TAG_LEN;

/// The TLS 1.3 record protection of the AEAD `A`.
pub(crate) struct Tls13Aead<A>(PhantomData<fn() -> A>);

impl<A: RecordAead> Tls13Aead<A> {
    /// The encrypter for `key` and `iv`, or one that fails every record
    /// when `key` is not a key of `A`'s length.
    ///
    /// `Tls13AeadAlgorithm::encrypter` comes here, as do the tests, which
    /// cannot make an `AeadKey` shorter than 32 bytes outside rustls
    /// (`AeadKey::new` is crate-private, `rustls-0.23.46/src/crypto/
    /// cipher.rs:293-301`).
    pub(crate) fn encrypter_for(&self, key: &[u8], iv: Iv) -> Box<dyn MessageEncrypter> {
        match A::new_from_slice(key) {
            Ok(aead) => Box::new(Tls13Encrypter { aead, iv }),
            Err(_) => Box::new(UnusableKey),
        }
    }

    /// The decrypter for `key` and `iv`, or one that fails every record
    /// when `key` is not a key of `A`'s length.
    pub(crate) fn decrypter_for(&self, key: &[u8], iv: Iv) -> Box<dyn MessageDecrypter> {
        match A::new_from_slice(key) {
            Ok(aead) => Box::new(Tls13Decrypter { aead, iv }),
            Err(_) => Box::new(UnusableKey),
        }
    }
}

impl<A: RecordAead> Tls13AeadAlgorithm for Tls13Aead<A> {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        self.encrypter_for(key.as_ref(), iv)
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        self.decrypter_for(key.as_ref(), iv)
    }

    fn key_len(&self) -> usize {
        A::key_size()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(A::traffic_secrets(key, iv))
    }
}

/// Seals TLS 1.3 records under one traffic key.
struct Tls13Encrypter<A> {
    /// The keyed AEAD, wiped when dropped.
    aead: A,
    /// The write IV.
    iv: Iv,
}

impl<A: RecordAead> MessageEncrypter for Tls13Encrypter<A> {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = msg
            .payload
            .len()
            .checked_add(OVERHEAD)
            .ok_or(Error::EncryptError)?;
        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&[u8::from(msg.typ)]);
        let tag = aead::seal(
            &self.aead,
            Nonce::new(&self.iv, seq).0,
            &make_tls13_aad(total_len),
            payload.as_mut(),
        )?;
        payload.extend_from_slice(&tag);
        // Every protected record goes out as application data under the
        // legacy record version TLS 1.2 (RFC 8446 §5.2).
        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len.saturating_add(OVERHEAD)
    }
}

/// Opens TLS 1.3 records under one traffic key.
struct Tls13Decrypter<A> {
    /// The keyed AEAD, wiped when dropped.
    aead: A,
    /// The read IV.
    iv: Iv,
}

impl<A: RecordAead> MessageDecrypter for Tls13Decrypter<A> {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        let aad = make_tls13_aad(payload.len());
        let plain_len = aead::open(&self.aead, Nonce::new(&self.iv, seq).0, &aad, payload)?;
        payload.truncate(plain_len);
        msg.into_tls13_unpadded_message()
    }
}

#[cfg(test)]
// Test-harness arithmetic over record lengths and offsets.
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use aes_gcm::aead::array::Array;
    use rustls::PeerMisbehaved;
    use rustls::crypto::cipher::OutboundChunks;

    use super::*;

    /// The sequence numbers each AEAD is checked at: the first two, the
    /// last before AES-GCM's confidentiality limit, and the last a
    /// connection can reach.
    const SEQS: [u64; 4] = [0, 1, (1 << 24) - 1, u64::MAX];

    /// A key of up to 32 bytes, no two alike.
    const KEY: [u8; 32] = [
        0x8a, 0x13, 0x55, 0xe0, 0x2f, 0x71, 0xc4, 0x09, 0x3b, 0xd6, 0x62, 0x9e, 0x04, 0xf8, 0x27,
        0xa1, 0x5c, 0x90, 0x3e, 0xeb, 0x16, 0x7d, 0xb2, 0x48, 0xcf, 0x01, 0x6a, 0x95, 0x33, 0xde,
        0x7e, 0xb9,
    ];

    /// A write IV.
    const IV: [u8; 12] = [
        0xf1, 0x0e, 0x6b, 0x24, 0x97, 0x58, 0xa3, 0xcc, 0x12, 0x8d, 0x40, 0xe7,
    ];

    /// The record body RFC 8446 §5.2 gives `plaintext` of content type
    /// `typ` at `seq`, computed on the AEAD crate directly: the nonce is
    /// the IV with the sequence number's eight big-endian bytes XORed into
    /// its last eight, and the additional data the outer header.
    fn by_hand<A: RecordAead>(key: &[u8], seq: u64, typ: u8, plaintext: &[u8]) -> Vec<u8> {
        let mut nonce = IV;
        for (n, s) in nonce[4..].iter_mut().zip(seq.to_be_bytes()) {
            *n ^= s;
        }
        let len = u16::try_from(plaintext.len() + 1 + 16).expect("a record's length");
        let aad = [0x17, 0x03, 0x03, (len >> 8) as u8, len as u8];
        let mut body = [plaintext, &[typ]].concat();
        let tag = A::new_from_slice(key)
            .expect("the key")
            .encrypt_inout_detached(&Array::from(nonce), &aad, body.as_mut_slice().into())
            .expect("sealed");
        body.extend_from_slice(&tag);
        body
    }

    /// Seal `plaintext` with `encrypter` at `seq` as a handshake record.
    fn seal(
        encrypter: &mut dyn MessageEncrypter,
        seq: u64,
        plaintext: &[u8],
    ) -> Result<OutboundOpaqueMessage, Error> {
        encrypter.encrypt(
            OutboundPlainMessage {
                typ: ContentType::Handshake,
                version: ProtocolVersion::TLSv1_3,
                payload: OutboundChunks::Single(plaintext),
            },
            seq,
        )
    }

    /// Open `body` with `decrypter` at `seq`, returning its content type,
    /// version and plaintext.
    fn open(
        decrypter: &mut dyn MessageDecrypter,
        seq: u64,
        body: &mut [u8],
    ) -> Result<(ContentType, ProtocolVersion, Vec<u8>), Error> {
        let msg =
            InboundOpaqueMessage::new(ContentType::ApplicationData, ProtocolVersion::TLSv1_2, body);
        let plain = decrypter.decrypt(msg, seq)?;
        Ok((plain.typ, plain.version, plain.payload.to_vec()))
    }

    /// Each AEAD seals at each sequence number exactly what the AEAD crate
    /// gives for RFC 8446's nonce and additional data, and opens both its
    /// own records and those.
    fn seals_as_rfc_8446_says<A: RecordAead>(aead: &Tls13Aead<A>, key_len: usize) {
        let key = &KEY[..key_len];
        let long = vec![0x5a; 16_384];
        for seq in SEQS {
            for plaintext in [&b""[..], b"hello", &long] {
                let mut encrypter = aead.encrypter_for(key, Iv::from(IV));
                let sealed = seal(encrypter.as_mut(), seq, plaintext).expect("sealed");
                assert_eq!(sealed.typ, ContentType::ApplicationData);
                assert_eq!(sealed.version, ProtocolVersion::TLSv1_2);
                let expected = by_hand::<A>(key, seq, 0x16, plaintext);
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

                let mut decrypter = aead.decrypter_for(key, Iv::from(IV));
                let mut body = sealed.payload.as_ref().to_vec();
                assert_eq!(
                    open(decrypter.as_mut(), seq, &mut body),
                    Ok((
                        ContentType::Handshake,
                        ProtocolVersion::TLSv1_3,
                        plaintext.to_vec()
                    )),
                    "seq {seq}"
                );
                let mut body = by_hand::<A>(key, seq, 0x17, plaintext);
                assert_eq!(
                    open(decrypter.as_mut(), seq, &mut body),
                    Ok((
                        ContentType::ApplicationData,
                        ProtocolVersion::TLSv1_3,
                        plaintext.to_vec()
                    )),
                    "seq {seq}, sealed by hand"
                );
            }
        }
    }

    #[test]
    fn aes_128_gcm_seals_as_rfc_8446_says() {
        seals_as_rfc_8446_says(&AES_128_GCM, 16);
    }

    #[test]
    fn aes_256_gcm_seals_as_rfc_8446_says() {
        seals_as_rfc_8446_says(&AES_256_GCM, 32);
    }

    #[test]
    fn chacha20_poly1305_seals_as_rfc_8446_says() {
        seals_as_rfc_8446_says(&CHACHA20_POLY1305, 32);
    }

    /// A record whose tag, ciphertext, inner content type or length was
    /// changed, or that is opened at another sequence number, fails as
    /// ring's does, with `DecryptError`.
    fn refuses_tampering<A: RecordAead>(aead: &Tls13Aead<A>, key_len: usize) {
        let key = &KEY[..key_len];
        let mut decrypter = aead.decrypter_for(key, Iv::from(IV));
        for seq in SEQS {
            let sealed = by_hand::<A>(key, seq, 0x17, b"a record");
            let last = sealed.len() - 1;
            let typ = sealed.len() - TAG_LEN - 1;
            for (what, at) in [
                ("the tag", last),
                ("the ciphertext", 0),
                ("the content type", typ),
            ] {
                let mut body = sealed.clone();
                body[at] ^= 0x01;
                assert_eq!(
                    open(decrypter.as_mut(), seq, &mut body),
                    Err(Error::DecryptError),
                    "seq {seq}: {what} changed"
                );
            }
            let mut longer = [&sealed[..], &[0]].concat();
            assert_eq!(
                open(decrypter.as_mut(), seq, &mut longer),
                Err(Error::DecryptError),
                "seq {seq}: a byte added"
            );
            let mut shorter = sealed[..last].to_vec();
            assert_eq!(
                open(decrypter.as_mut(), seq, &mut shorter),
                Err(Error::DecryptError),
                "seq {seq}: a byte removed"
            );
            let mut body = sealed.clone();
            assert_eq!(
                open(decrypter.as_mut(), seq.wrapping_add(1), &mut body),
                Err(Error::DecryptError),
                "seq {seq} opened as the next"
            );
        }
        for len in [0, 1, TAG_LEN - 1] {
            let mut body = vec![0; len];
            assert_eq!(
                open(decrypter.as_mut(), 0, &mut body),
                Err(Error::DecryptError),
                "{len} bytes, shorter than a tag"
            );
        }
    }

    #[test]
    fn aes_128_gcm_refuses_tampering() {
        refuses_tampering(&AES_128_GCM, 16);
    }

    #[test]
    fn aes_256_gcm_refuses_tampering() {
        refuses_tampering(&AES_256_GCM, 32);
    }

    #[test]
    fn chacha20_poly1305_refuses_tampering() {
        refuses_tampering(&CHACHA20_POLY1305, 32);
    }

    /// An authentic record still meets rustls's checks on the inner
    /// plaintext, which the decrypter hands it to: a body of padding alone
    /// names no content type, and one over 2^14 + 1 bytes is too long
    /// (`rustls-0.23.46/src/msgs/message/inbound.rs:61-87`).
    #[test]
    fn an_authentic_record_still_meets_rustlss_inner_plaintext_checks() {
        let key = &KEY[..16];
        let mut decrypter = AES_128_GCM.decrypter_for(key, Iv::from(IV));
        let mut padding = by_hand::<Aes128Gcm>(key, 3, 0, &[0; 4]);
        assert_eq!(
            open(decrypter.as_mut(), 3, &mut padding),
            Err(PeerMisbehaved::IllegalTlsInnerPlaintext.into())
        );
        let mut oversized = by_hand::<Aes128Gcm>(key, 4, 0x17, &[0x5a; 16_385]);
        assert_eq!(
            open(decrypter.as_mut(), 4, &mut oversized),
            Err(Error::PeerSentOversizedRecord)
        );
    }

    /// The zeros after a record's content type are padding, stripped
    /// before the type is read, and a zero ahead of the type is content
    /// (RFC 8446 §5.4).  Neither rustls nor ring pads what it sends, so no
    /// handshake in these tests carries padding; these records are sealed
    /// by hand, each ending in the zero `by_hand` appends as its type.
    #[test]
    fn a_padded_record_opens_to_its_content() {
        let key = &KEY[..16];
        let mut decrypter = AES_128_GCM.decrypter_for(key, Iv::from(IV));
        let records: [(u64, &[u8], ContentType, &[u8]); 3] = [
            (
                5,
                b"data\x17\x00\x00",
                ContentType::ApplicationData,
                b"data",
            ),
            (6, b"data\x00\x16\x00", ContentType::Handshake, b"data\x00"),
            (7, b"\x17", ContentType::ApplicationData, b""),
        ];
        for (seq, inner, typ, content) in records {
            let mut body = by_hand::<Aes128Gcm>(key, seq, 0, inner);
            assert_eq!(
                open(decrypter.as_mut(), seq, &mut body),
                Ok((typ, ProtocolVersion::TLSv1_3, content.to_vec())),
                "seq {seq}"
            );
        }
    }

    /// A key of a length the AEAD does not take makes an encrypter and a
    /// decrypter that return an error for every record, where ring's
    /// provider panics as it builds them.  `UnusableKey` says what rustls
    /// then does with the errors.
    fn a_key_of_the_wrong_length_fails_every_record<A: RecordAead>(aead: &Tls13Aead<A>) {
        assert_eq!(
            aead.key_len(),
            A::key_size(),
            "the length rustls is told to derive"
        );
        let good = &KEY[..A::key_size()];
        for wrong in [0, 1, 15, 16, 17, 31, 32, 33, 64] {
            if wrong == A::key_size() {
                continue;
            }
            let key = vec![0x42; wrong];
            let mut encrypter = aead.encrypter_for(&key, Iv::from(IV));
            assert_eq!(
                seal(encrypter.as_mut(), 0, b"data").err(),
                Some(Error::EncryptError),
                "a {wrong}-byte key"
            );
            let mut decrypter = aead.decrypter_for(&key, Iv::from(IV));
            let mut body = by_hand::<A>(good, 0, 0x17, b"data");
            assert_eq!(
                open(decrypter.as_mut(), 0, &mut body),
                Err(Error::DecryptError),
                "a {wrong}-byte key"
            );
        }
    }

    #[test]
    fn a_key_of_the_wrong_length_fails_every_record_for_each_aead() {
        a_key_of_the_wrong_length_fails_every_record(&AES_128_GCM);
        a_key_of_the_wrong_length_fails_every_record(&AES_256_GCM);
        a_key_of_the_wrong_length_fails_every_record(&CHACHA20_POLY1305);
        // Through the trait as well, with the one length rustls lets a
        // caller build, 32 bytes, which AES-128-GCM does not take.
        let mut encrypter = AES_128_GCM.encrypter(AeadKey::from(KEY), Iv::from(IV));
        assert_eq!(
            seal(encrypter.as_mut(), 0, b"data").err(),
            Some(Error::EncryptError)
        );
        let mut decrypter = AES_128_GCM.decrypter(AeadKey::from(KEY), Iv::from(IV));
        let mut body = by_hand::<Aes128Gcm>(&KEY[..16], 0, 0x17, b"data");
        assert_eq!(
            open(decrypter.as_mut(), 0, &mut body),
            Err(Error::DecryptError)
        );
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

    /// The secrets each AEAD hands out name it and carry the key and IV.
    #[test]
    fn extracted_secrets_name_the_aead() {
        let aeads: [(&str, &dyn Tls13AeadAlgorithm); 3] = [
            ("AES-128-GCM", &AES_128_GCM),
            ("AES-256-GCM", &AES_256_GCM),
            ("ChaCha20-Poly1305", &CHACHA20_POLY1305),
        ];
        for (name, aead) in aeads {
            let secrets = aead
                .extract_keys(AeadKey::from(KEY), Iv::from(IV))
                .expect("extracted");
            assert_eq!(named(&secrets), (name, KEY.to_vec(), IV.to_vec()));
        }
    }

    /// Each suite carries its hash, an HKDF over the same hash, the AEAD
    /// its name gives at that AEAD's key length, ring's confidentiality
    /// limit and no QUIC keys.  Two of the AEADs take 32-byte keys, so the
    /// AEAD is told apart by the secrets it hands out, which name it.
    #[test]
    fn each_suite_is_assembled_as_its_name_says() {
        let suites = [
            (TLS13_AES_128_GCM_SHA256, 32, "AES-128-GCM", 16, 1 << 24),
            (TLS13_AES_256_GCM_SHA384, 48, "AES-256-GCM", 32, 1 << 24),
            (
                TLS13_CHACHA20_POLY1305_SHA256,
                32,
                "ChaCha20-Poly1305",
                32,
                u64::MAX,
            ),
        ];
        for (suite, hash_len, aead, key_len, limit) in suites {
            let SupportedCipherSuite::Tls13(tls13) = suite else {
                panic!("{suite:?} is a TLS 1.3 suite");
            };
            assert_eq!(
                tls13.common.hash_provider.output_len(),
                hash_len,
                "{suite:?}"
            );
            assert_eq!(
                tls13.hkdf_provider.extract_from_zero_ikm(None).hash_len(),
                hash_len,
                "{suite:?}"
            );
            let secrets = tls13
                .aead_alg
                .extract_keys(AeadKey::from(KEY), Iv::from(IV))
                .expect("extracted");
            assert_eq!(named(&secrets).0, aead, "{suite:?}");
            assert_eq!(tls13.aead_alg.key_len(), key_len, "{suite:?}");
            assert_eq!(tls13.common.confidentiality_limit, limit, "{suite:?}");
            assert!(tls13.quic.is_none(), "{suite:?}");
            assert!(!suite.fips(), "{suite:?}");
        }
    }
}
