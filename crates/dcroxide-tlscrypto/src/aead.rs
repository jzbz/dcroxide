// SPDX-License-Identifier: ISC
//! The AEAD calls the TLS 1.3 and TLS 1.2 record layers share: sealing a
//! record body in place with a detached tag, opening one, and the
//! encrypter and decrypter that stand in for a key of the wrong length.
//!
//! ring's provider makes these calls on ring's own AEAD API in each record
//! layer (`rustls-0.23.46/src/crypto/ring/tls13.rs`, `tls12.rs`); here
//! they are made once, over the `aead` traits `aes-gcm` and
//! `chacha20poly1305` implement, so the Wycheproof vectors run through the
//! same two functions the records do.

use aes_gcm::aead::array::Array;
use aes_gcm::aead::consts::{U12, U16};
use aes_gcm::aead::{AeadInOut, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter, MessageEncrypter,
    NONCE_LEN, OutboundOpaqueMessage, OutboundPlainMessage,
};
use rustls::{ConnectionTrafficSecrets, Error};

/// The length of each suite's authentication tag.
pub(crate) const TAG_LEN: usize = 16;

/// How many full-size records one AES-GCM key may seal, in either TLS
/// version: ring's figure for both key sizes (`rustls-0.23.46/src/crypto/
/// ring/tls13.rs:48`, `:70`; `tls12.rs:53`, `:67`, `:81`, `:95`), a one in
/// 2^60 advantage by rustls's account (`src/suites.rs:34-46`).  rustls
/// updates the key in TLS 1.3, and closes a TLS 1.2 connection, at the
/// limit.
pub(crate) const AES_GCM_LIMIT: u64 = 1 << 24;

/// ChaCha20-Poly1305's limit, ring's (`ring/tls13.rs:28`, `tls12.rs:25`,
/// `:39`): none a 64-bit sequence number can reach
/// (draft-irtf-cfrg-aead-limits-08, §5.2.1).
pub(crate) const CHACHA20_POLY1305_LIMIT: u64 = u64::MAX;

/// An AEAD a record layer runs: a 96-bit nonce and a 128-bit tag, the
/// shape all three of TLS's AEADs have here (RFC 8446 §5.3, RFC 5288 §3,
/// RFC 7905 §2), and the name rustls gives its keys.
pub(crate) trait RecordAead:
    KeyInit + AeadInOut<NonceSize = U12, TagSize = U16> + Send + Sync + 'static
{
    /// The secrets rustls hands out for a key and IV of this AEAD
    /// (`Tls13AeadAlgorithm::extract_keys`,
    /// `Tls12AeadAlgorithm::extract_keys`), in the variant naming it.
    fn traffic_secrets(key: AeadKey, iv: Iv) -> ConnectionTrafficSecrets;
}

impl RecordAead for Aes128Gcm {
    fn traffic_secrets(key: AeadKey, iv: Iv) -> ConnectionTrafficSecrets {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv }
    }
}

impl RecordAead for Aes256Gcm {
    fn traffic_secrets(key: AeadKey, iv: Iv) -> ConnectionTrafficSecrets {
        ConnectionTrafficSecrets::Aes256Gcm { key, iv }
    }
}

impl RecordAead for ChaCha20Poly1305 {
    fn traffic_secrets(key: AeadKey, iv: Iv) -> ConnectionTrafficSecrets {
        ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv }
    }
}

/// Encrypt `in_out` in place under `nonce`, authenticating `aad` with it,
/// and return the tag, which the caller appends.
///
/// A failure is `EncryptError`, as ring's is.  Neither crate fails for a
/// record's lengths: `aes-gcm` refuses only a plaintext over 2^36 - 32
/// bytes or additional data over 2^61 - 1, and `chacha20poly1305` only a
/// plaintext of 2^32 - 1 blocks or more
/// (`aes-gcm-0.11.1/src/lib.rs:267-269`,
/// `chacha20poly1305-0.11.0/src/cipher.rs:58-60`).
pub(crate) fn seal<A: RecordAead>(
    aead: &A,
    nonce: [u8; NONCE_LEN],
    aad: &[u8],
    in_out: &mut [u8],
) -> Result<[u8; TAG_LEN], Error> {
    let tag = aead
        .encrypt_inout_detached(&Array::from(nonce), aad, in_out.into())
        .map_err(|_| Error::EncryptError)?;
    Ok(tag.into())
}

/// Decrypt `sealed`, a ciphertext followed by its tag, in place under
/// `nonce`, authenticating `aad` with it, and return the length of the
/// plaintext, which is left at the front of `sealed`.
///
/// A body shorter than a tag, or a tag that does not verify, is
/// `DecryptError`, as ring's is.  Both crates compare the tag in constant
/// time and decrypt only once it verifies
/// (`aes-gcm-0.11.1/src/lib.rs:298-306`,
/// `chacha20poly1305-0.11.0/src/cipher.rs:90-97`), so `sealed` is
/// unchanged when this fails.
pub(crate) fn open<A: RecordAead>(
    aead: &A,
    nonce: [u8; NONCE_LEN],
    aad: &[u8],
    sealed: &mut [u8],
) -> Result<usize, Error> {
    let plain_len = sealed
        .len()
        .checked_sub(TAG_LEN)
        .ok_or(Error::DecryptError)?;
    let (ciphertext, tag) = sealed.split_at_mut(plain_len);
    let tag = Array::try_from(&*tag).map_err(|_| Error::DecryptError)?;
    aead.decrypt_inout_detached(&Array::from(nonce), aad, ciphertext.into(), &tag)
        .map_err(|_| Error::DecryptError)?;
    Ok(plain_len)
}

/// The encrypter and decrypter for a key or IV of a length the AEAD does
/// not take: every record fails, with `EncryptError` or `DecryptError`.
///
/// rustls always hands an AEAD a key of its `key_len` and the IV lengths of
/// its `KeyBlockShape`, and ring unwraps on that when it builds the key
/// (`rustls-0.23.46/src/crypto/ring/tls13.rs:173-184`, `tls12.rs:126-219`).
/// These panic nowhere themselves, but they do not keep a broken invariant
/// from aborting a release build (`panic = "abort"`): rustls answers the
/// decrypter's `DecryptError` with an alert (`src/conn.rs:1154-1159`) and
/// unwraps the encrypter's `EncryptError` (`src/record_layer.rs:107-118`),
/// so the first record written under such a key, an alert among them,
/// panics, where ring's provider would have when it built the key.
pub(crate) struct UnusableKey;

impl MessageEncrypter for UnusableKey {
    fn encrypt(
        &mut self,
        _msg: OutboundPlainMessage<'_>,
        _seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        Err(Error::EncryptError)
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len
    }
}

impl MessageDecrypter for UnusableKey {
    fn decrypt<'a>(
        &mut self,
        _msg: InboundOpaqueMessage<'a>,
        _seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        Err(Error::DecryptError)
    }
}
