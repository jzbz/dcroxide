// SPDX-License-Identifier: ISC
//! RSA signature verification written in this tree (ADR-0015, T5): the
//! public-key half of RSA alone, PKCS#1 v1.5 and PSS, over `num-bigint`.
//! Nothing here signs, and nothing here is secret.
//!
//! ring verified the node's RSA signatures before this, and the rules
//! below are ring's, so that the switch changes no verdict
//! (`ring-0.17.14/src/rsa/`):
//!
//! * The key is an `RSAPublicKey` as ring reads one (`rsa.rs:44-54`,
//!   `io/der.rs:75-111`, `:148-193`): one SEQUENCE of two INTEGERs and
//!   nothing before, between or after them; each INTEGER positive and
//!   minimally encoded; each length in the short form or in the long form
//!   of one or two bytes, itself minimal.  Go's `crypto/x509` reads the
//!   SEQUENCE more leniently, ignoring bytes after E and after the SEQUENCE
//!   (`crypto/x509/parser.go:261-271`), so such a key verifies in Go and is
//!   refused here, as ring refused it.
//! * The modulus is odd and at least 256 bytes long, so 2041- to 2047-bit
//!   moduli pass, as they do in ring, and at most 8192 bits
//!   (`public_modulus.rs:39-77`, `arithmetic/bigint/modulusvalue.rs:42-68`);
//!   the exponent is odd, at least 3 and at most 2^33 - 1, in at most five
//!   bytes (`public_exponent.rs:27-75`).  Go takes moduli from 1024 bits up
//!   with no greatest length, and exponents up to 2^31 - 1
//!   (`crypto/rsa/rsa.go:284-300`,
//!   `crypto/internal/fips140/rsa/rsa.go:326-364`).  [`RING_LIMITS`] holds
//!   ring's bounds until Go's arrive with Go's client-certificate set
//!   (ADR-0015, T4).
//! * The signature is exactly as long as the modulus, a value in (0, n)
//!   (`public_key.rs:144-172`), and is raised to e mod n.
//! * PKCS#1 v1.5: the encoding of the message's digest, `00 01`, `ff`
//!   bytes, `00` and the DigestInfo with NULL parameters, is built and
//!   compared with the result whole (`padding/pkcs1.rs:51-93`), so nothing
//!   parses the result for a forgery to aim at.  An algorithm whose
//!   certificate identifier lacks the parameters builds the same encoding.
//! * PSS: EMSA-PSS-VERIFY (RFC 8017 §9.1.2) with MGF1 over the message's
//!   hash and a salt as long as the hash, the one length TLS signs with
//!   (RFC 8446 §4.2.3) and the one ring and Go's `crypto/tls` take
//!   (`padding/pss.rs:102-191`; `rsa.PSSSaltLengthEqualsHash`,
//!   `crypto/tls/auth.go:58`).
//!
//! Key, message and signature are public, so the arithmetic runs in
//! variable time: `num-bigint`'s `modpow`, which takes Montgomery
//! multiplication for an odd modulus.  The bounds hold its cost to an
//! exponent of 33 bits on a modulus of 8192.

use core::fmt;

use num_bigint::BigUint;
use rustls::pki_types::{
    AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id,
};
use sha2::{Digest, Sha256, Sha384, Sha512};

/// The bounds a key must meet.
#[derive(Debug)]
pub(crate) struct RsaLimits {
    /// The least length of the modulus in whole bytes, as ring rounds it.
    min_modulus_bytes: usize,
    /// The greatest length of the modulus in bits.
    max_modulus_bits: u64,
    /// The greatest public exponent.
    max_exponent: u64,
}

/// ring's bounds for its `RSA_*_2048_8192_*` algorithms
/// (`ring-0.17.14/src/rsa/verification.rs:205-220`).
pub(crate) static RING_LIMITS: RsaLimits = RsaLimits {
    min_modulus_bytes: 256,
    max_modulus_bits: 8192,
    max_exponent: (1 << 33) - 1,
};

/// The hash a signature is made over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Hash {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl Hash {
    /// The length of a digest.
    fn len(self) -> usize {
        match self {
            Hash::Sha256 => 32,
            Hash::Sha384 => 48,
            Hash::Sha512 => 64,
        }
    }

    /// The digest of `parts`, one after the other.
    fn digest(self, parts: &[&[u8]]) -> Vec<u8> {
        fn of<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
            let mut hash = D::new();
            for part in parts {
                hash.update(part);
            }
            hash.finalize().to_vec()
        }
        match self {
            Hash::Sha256 => of::<Sha256>(parts),
            Hash::Sha384 => of::<Sha384>(parts),
            Hash::Sha512 => of::<Sha512>(parts),
        }
    }

    /// The DER of a DigestInfo up to its digest (RFC 8017 §9.2, note 1):
    /// the hash's AlgorithmIdentifier with NULL parameters, then the
    /// OCTET STRING's header.
    fn digest_info_prefix(self) -> &'static [u8] {
        match self {
            Hash::Sha256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            Hash::Sha384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            Hash::Sha512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
        }
    }
}

/// How the digest is encoded before it is signed.
#[derive(Clone, Copy, Debug)]
enum Padding {
    /// EMSA-PKCS1-v1_5 (RFC 8017 §9.2).
    Pkcs1(Hash),
    /// EMSA-PSS (RFC 8017 §9.1), MGF1 and the salt on the same hash.
    Pss(Hash),
}

/// One RSA verification algorithm: a padding and its hash, the identifier
/// a certificate names it by, and the bounds on the key.
pub(crate) struct RsaVerify {
    /// webpki's name for it, for `Debug`.
    name: &'static str,
    /// How the digest is encoded.
    padding: Padding,
    /// The certificate's signature algorithm identifier.
    signature_alg_id: AlgorithmIdentifier,
    /// The bounds on the key.
    limits: &'static RsaLimits,
}

impl fmt::Debug for RsaVerify {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name)
    }
}

impl RsaVerify {
    /// PKCS#1 v1.5 over `hash`, within ring's bounds, under webpki's `name`.
    pub(crate) const fn pkcs1(
        name: &'static str,
        hash: Hash,
        signature_alg_id: AlgorithmIdentifier,
    ) -> RsaVerify {
        RsaVerify {
            name,
            padding: Padding::Pkcs1(hash),
            signature_alg_id,
            limits: &RING_LIMITS,
        }
    }

    /// PSS over `hash`, with MGF1 and a salt on the same hash, within
    /// ring's bounds, under webpki's `name`.
    pub(crate) const fn pss(
        name: &'static str,
        hash: Hash,
        signature_alg_id: AlgorithmIdentifier,
    ) -> RsaVerify {
        RsaVerify {
            name,
            padding: Padding::Pss(hash),
            signature_alg_id,
            limits: &RING_LIMITS,
        }
    }

    /// Whether `signature` is this algorithm's signature of `message`
    /// under `public_key`, an `RSAPublicKey`.
    fn verifies(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Option<()> {
        let key = PublicKey::parse(public_key, self.limits)?;
        let encoded = key.raise(signature)?;
        match self.padding {
            Padding::Pkcs1(hash) => pkcs1_matches(hash, message, &encoded),
            Padding::Pss(hash) => pss_matches(hash, message, &encoded, key.bits),
        }
    }
}

impl SignatureVerificationAlgorithm for RsaVerify {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        self.verifies(public_key, message, signature)
            .ok_or(InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_alg_id
    }
}

/// An RSA public key within the bounds.
struct PublicKey {
    /// The modulus.
    n: BigUint,
    /// The public exponent.
    e: BigUint,
    /// The modulus's length in whole bytes, which a signature's must equal.
    len: usize,
    /// The modulus's length in bits.
    bits: u64,
}

impl PublicKey {
    /// `der` as ring reads an `RSAPublicKey`, its values held to `limits`.
    fn parse(der: &[u8], limits: &RsaLimits) -> Option<PublicKey> {
        let (sequence, after) = element(der, SEQUENCE)?;
        let (n, rest) = element(sequence, INTEGER)?;
        let (e, rest) = element(rest, INTEGER)?;
        if !after.is_empty() || !rest.is_empty() {
            return None;
        }
        let (n, e) = (positive(n)?, positive(e)?);

        // The modulus: odd, its length rounded up to whole bytes at least
        // the least, its bits at most the most.
        if n.len() < limits.min_modulus_bytes || n.last()? & 1 == 0 {
            return None;
        }
        let len = n.len();
        let n = BigUint::from_bytes_be(n);
        let bits = n.bits();
        if bits > limits.max_modulus_bits {
            return None;
        }

        // The exponent: at most five bytes, so it starts at the fourth of
        // eight or later; odd; from 3 to the most.
        let mut value = [0; 8];
        let start = value
            .len()
            .checked_sub(e.len())
            .filter(|&start| start >= 3)?;
        value.get_mut(start..)?.copy_from_slice(e);
        let value = u64::from_be_bytes(value);
        if value < 3 || value > limits.max_exponent || value & 1 == 0 {
            return None;
        }
        Some(PublicKey {
            n,
            e: BigUint::from(value),
            len,
            bits,
        })
    }

    /// RSAVP1 (RFC 8017 §5.2.2): `signature`, which must be the modulus's
    /// length and a value in (0, n), raised to e mod n, as many bytes as
    /// the modulus.
    fn raise(&self, signature: &[u8]) -> Option<Vec<u8>> {
        if signature.len() != self.len {
            return None;
        }
        let s = BigUint::from_bytes_be(signature);
        if s == BigUint::ZERO || s >= self.n {
            return None;
        }
        let m = s.modpow(&self.e, &self.n).to_bytes_be();
        let mut encoded = vec![0; self.len];
        encoded
            .get_mut(self.len.checked_sub(m.len())?..)?
            .copy_from_slice(&m);
        Some(encoded)
    }
}

/// An identifier: a SEQUENCE.
const SEQUENCE: u8 = 0x30;
/// An identifier: an INTEGER.
const INTEGER: u8 = 0x02;

/// The element at the start of `data`, as ring's `read_tag_and_get_value`
/// reads it (`ring-0.17.14/src/io/der.rs:75-111`), when its identifier is
/// `tag`: its content and what follows it.  A length is in the short form,
/// or in the long form of one byte from 128 up or of two bytes from 256
/// up; any other form is refused.
fn element(data: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (&identifier, rest) = data.split_first()?;
    let (&first, rest) = rest.split_first()?;
    if identifier != tag {
        return None;
    }
    let (len, rest) = match first {
        0x00..=0x7f => (usize::from(first), rest),
        0x81 => {
            let (&len, rest) = rest.split_first()?;
            (len >= 0x80).then_some((usize::from(len), rest))?
        }
        0x82 => {
            let (len, rest) = rest.split_first_chunk::<2>()?;
            let len = usize::from(u16::from_be_bytes(*len));
            (len >= 0x100).then_some((len, rest))?
        }
        _ => return None,
    };
    rest.split_at_checked(len)
}

/// The value of an INTEGER's content as ring's `positive_integer` reads it
/// (`ring-0.17.14/src/io/der.rs:148-193`, `io/positive.rs:25-36`): big-endian
/// without its sign byte, refused when it is zero, negative or not minimal.
fn positive(content: &[u8]) -> Option<&[u8]> {
    match content {
        [] | [0x00] => None,
        [0x00, rest @ ..] => (rest.first()? & 0x80 != 0).then_some(rest),
        [first, ..] => (first & 0x80 == 0).then_some(content),
    }
}

/// Whether `encoded` is EMSA-PKCS1-v1_5's encoding of `message`'s digest
/// at its length: built here, as ring builds it, and compared whole.
fn pkcs1_matches(hash: Hash, message: &[u8], encoded: &[u8]) -> Option<()> {
    let prefix = hash.digest_info_prefix();
    let padding = encoded
        .len()
        .checked_sub(3)?
        .checked_sub(prefix.len())?
        .checked_sub(hash.len())?;
    let mut expected = Vec::with_capacity(encoded.len());
    expected.extend_from_slice(&[0x00, 0x01]);
    expected.resize(padding.checked_add(2)?, 0xff);
    expected.push(0x00);
    expected.extend_from_slice(prefix);
    expected.extend_from_slice(&hash.digest(&[message]));
    (expected == encoded).then_some(())
}

/// Whether `encoded`, the result of raising a signature under a modulus of
/// `bits` bits, holds EMSA-PSS's encoding of `message` with a salt the
/// hash's length (RFC 8017 §9.1.2), as ring checks it
/// (`ring-0.17.14/src/rsa/padding/pss.rs:102-191`).
fn pss_matches(hash: Hash, message: &[u8], encoded: &[u8], bits: u64) -> Option<()> {
    let h_len = hash.len();
    // emBits is one less than the modulus's bits, so the encoding is one
    // byte shorter than the modulus when those bits fill whole bytes, and
    // that leading byte must be zero.
    let em_bits = bits.checked_sub(1)?;
    let em_len = usize::try_from(em_bits.div_ceil(8)).ok()?;
    let unused = u64::try_from(em_len)
        .ok()?
        .checked_mul(8)?
        .checked_sub(em_bits)?;
    let top_mask = 0xffu8.checked_shr(u32::try_from(unused).ok()?)?;
    let em = match encoded.len().checked_sub(em_len)? {
        0 => encoded,
        1 => match encoded.split_first()? {
            (0x00, rest) => rest,
            _ => return None,
        },
        _ => return None,
    };

    // Steps 3 to 5: room for the salt and the hash, the trailer `bc`, and
    // maskedDB, then H.
    let db_len = em_len.checked_sub(h_len)?.checked_sub(1)?;
    let ps_len = db_len.checked_sub(h_len)?.checked_sub(1)?;
    let (masked_db, rest) = em.split_at_checked(db_len)?;
    let (h, trailer) = rest.split_at_checked(h_len)?;
    if trailer != [0xbc] {
        return None;
    }
    // Step 6: maskedDB's bits beyond emBits are zero.
    if masked_db.first()? & !top_mask != 0 {
        return None;
    }
    // Steps 7 to 9: DB = maskedDB XOR MGF1(H), those bits cleared.
    let mut db = mgf1(hash, h, db_len)?;
    for (byte, masked) in db.iter_mut().zip(masked_db) {
        *byte ^= masked;
    }
    *db.first_mut()? &= top_mask;
    // Steps 10 and 11: zeros, `01`, then the salt.
    let (ps, rest) = db.split_at_checked(ps_len)?;
    let (separator, salt) = rest.split_first()?;
    if ps.iter().any(|&byte| byte != 0) || *separator != 0x01 {
        return None;
    }
    // Steps 12 to 14: H = Hash(00 * 8 || mHash || salt).
    let m_hash = hash.digest(&[message]);
    (hash.digest(&[&[0; 8], &m_hash, salt]) == h).then_some(())
}

/// MGF1 over `hash` (RFC 8017 §B.2.1): `len` bytes from `seed`.
fn mgf1(hash: Hash, seed: &[u8], len: usize) -> Option<Vec<u8>> {
    let mut mask = Vec::with_capacity(len);
    let mut counter = 0u32;
    while mask.len() < len {
        mask.extend_from_slice(&hash.digest(&[seed, &counter.to_be_bytes()]));
        counter = counter.checked_add(1)?;
    }
    mask.truncate(len);
    Some(mask)
}

/// For the fuzz body's test in `verify`: the test key's PKCS#1 v1.5
/// signature of `message` over `hash`.
#[cfg(test)]
pub(crate) fn pkcs1_signature(
    key: &dcroxide_testutil::RsaTestKey,
    hash: Hash,
    message: &[u8],
) -> Vec<u8> {
    let encoded = tests::pkcs1_encoding(hash, hash.digest_info_prefix(), message, key.n.len());
    tests::sign_raw(key, &encoded)
}

#[cfg(test)]
// Test-harness arithmetic over bounded lengths.
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use dcroxide_testutil::{RSA_TEST_KEYS, RsaTestKey, rsa_test_key};

    use super::*;

    /// A DER element: `tag`, a length in the fewest bytes, and `content`.
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let len = content.len();
        let mut out = vec![tag];
        match len {
            0..0x80 => out.push(len as u8),
            0x80..0x100 => out.extend([0x81, len as u8]),
            _ => out.extend([0x82, (len >> 8) as u8, len as u8]),
        }
        out.extend_from_slice(content);
        out
    }

    /// An INTEGER of the unsigned `value`, with the sign byte DER needs.
    fn integer(value: &[u8]) -> Vec<u8> {
        let sign = value.first().is_none_or(|first| first & 0x80 != 0);
        tlv(0x02, &[if sign { &[0][..] } else { &[] }, value].concat())
    }

    /// An `RSAPublicKey` of `n` and `e`.
    fn public_key(n: &[u8], e: &[u8]) -> Vec<u8> {
        tlv(0x30, &[integer(n), integer(e)].concat())
    }

    /// Whether `der` reads as a key within ring's bounds.
    fn takes(der: &[u8]) -> bool {
        PublicKey::parse(der, &RING_LIMITS).is_some()
    }

    /// `encoded`, an encoding of the modulus's length, raised to the test
    /// key's d by the Chinese remainder theorem: the signature that
    /// carries it.
    pub(super) fn sign_raw(key: &RsaTestKey, encoded: &[u8]) -> Vec<u8> {
        let [n, d, p, q] = [&key.n, &key.d, &key.p, &key.q].map(|v| BigUint::from_bytes_be(v));
        let c = BigUint::from_bytes_be(encoded);
        assert!(c < n, "{}: an encoding below the modulus", key.name);
        let m_p = c.modpow(&(&d % (&p - 1u8)), &p);
        let m_q = c.modpow(&(&d % (&q - 1u8)), &q);
        let q_inv = (&q % &p).modpow(&(&p - 2u8), &p);
        let h = (q_inv * ((m_p + &p - (&m_q % &p)) % &p)) % &p;
        let s = (m_q + h * q).to_bytes_be();
        [vec![0; key.n.len() - s.len()], s].concat()
    }

    /// EMSA-PKCS1-v1_5 of `message` in `len` bytes, as RFC 8017 §9.2
    /// writes it, with `prefix` as the DigestInfo up to the digest.
    pub(super) fn pkcs1_encoding(hash: Hash, prefix: &[u8], message: &[u8], len: usize) -> Vec<u8> {
        let t = [prefix, &hash.digest(&[message])].concat();
        [
            &[0x00, 0x01][..],
            &vec![0xff; len - 3 - t.len()],
            &[0x00],
            &t,
        ]
        .concat()
    }

    /// EMSA-PSS-ENCODE of `message` (RFC 8017 §9.1.1) with `salt`, for a
    /// modulus of `bits` bits, padded to the modulus's whole bytes.
    fn pss_encoding(hash: Hash, message: &[u8], salt: &[u8], bits: usize) -> Vec<u8> {
        let em_bits = bits - 1;
        let em_len = em_bits.div_ceil(8);
        let h = hash.digest(&[&[0; 8], &hash.digest(&[message]), salt]);
        let mut db = vec![0; em_len - h.len() - 1];
        let separator = db.len() - salt.len() - 1;
        db[separator] = 0x01;
        db[separator + 1..].copy_from_slice(salt);
        for (byte, mask) in db
            .iter_mut()
            .zip(mgf1(hash, &h, em_len - h.len() - 1).unwrap())
        {
            *byte ^= mask;
        }
        db[0] &= 0xff >> (8 * em_len - em_bits);
        let em = [db, h, vec![0xbc]].concat();
        [vec![0; bits.div_ceil(8) - em_len], em].concat()
    }

    /// Each key of the fixture is an RSA key: n = pq, and e * d is 1 mod
    /// p - 1 and mod q - 1, so d inverts e mod their least common multiple.
    #[test]
    fn the_fixtures_keys_are_rsa_keys() {
        for &(name, ..) in RSA_TEST_KEYS {
            let key = rsa_test_key(name);
            let [n, e, d, p, q] =
                [&key.n, &key.e, &key.d, &key.p, &key.q].map(|v| BigUint::from_bytes_be(v));
            assert_eq!(&p * &q, n, "{name}");
            let ed = e * d;
            assert_eq!(&ed % (p - 1u8), BigUint::from(1u8), "{name}");
            assert_eq!(&ed % (q - 1u8), BigUint::from(1u8), "{name}");
        }
    }

    /// Elements and INTEGERs read as ring reads them: a length in the short
    /// form, or in one or two bytes of the long form when it needs them;
    /// an INTEGER positive and minimal, its sign byte dropped.
    #[test]
    fn elements_read_as_ring_reads_them() {
        let content = [0x2a; 0x100];
        for (data, len) in [
            (&[0x02, 0x00][..], 0),
            (&[0x02, 0x01], 1),
            (&[0x02, 0x7f], 0x7f),
            (&[0x02, 0x81, 0x80], 0x80),
            (&[0x02, 0x82, 0x01, 0x00], 0x100),
        ] {
            let input = [data, &content].concat();
            let (got, rest) = element(&input, INTEGER).expect("read");
            assert_eq!(
                (got.len(), rest.len()),
                (len, input.len() - data.len() - len)
            );
        }
        for refused in [
            &[0x02, 0x81, 0x7f][..],
            &[0x02, 0x82, 0x00, 0xff],
            &[0x02, 0x83, 0x00, 0x01, 0x00],
            &[0x02, 0x80],
            &[0x03, 0x01],
        ] {
            let input = [refused, &content].concat();
            assert_eq!(element(&input, INTEGER), None, "{refused:02x?}");
        }
        for short in [&[0x02, 0x81][..], &[0x02, 0x82, 0x01], &[0x02], &[]] {
            assert_eq!(element(short, INTEGER), None, "{short:02x?}");
        }
        assert_eq!(element(&[0x02, 0x03, 0x01], INTEGER), None, "past the end");

        assert_eq!(positive(&[0x01]), Some(&[0x01][..]));
        assert_eq!(positive(&[0x7f, 0x00]), Some(&[0x7f, 0x00][..]));
        assert_eq!(positive(&[0x00, 0x80]), Some(&[0x80][..]));
        for refused in [
            &[][..],
            &[0x00],
            &[0x00, 0x7f],
            &[0x00, 0x00, 0x80],
            &[0x80],
            &[0xff],
        ] {
            assert_eq!(positive(refused), None, "{refused:02x?}");
        }
    }

    /// A key is one SEQUENCE of two INTEGERs and nothing else, as ring
    /// reads it: bytes after either, a third INTEGER, the two swapped, a
    /// zero sign byte too many or a negative exponent are refused, where
    /// Go would take the first two.
    #[test]
    fn a_key_reads_as_ring_reads_it() {
        let key = rsa_test_key("rsa2048");
        let (n, e) = (integer(&key.n), integer(&key.e));
        assert!(takes(&key.rsa_public_key()));
        assert!(takes(&tlv(0x30, &[n.clone(), e.clone()].concat())));
        for (what, der) in [
            (
                "a byte after the SEQUENCE",
                [key.rsa_public_key(), vec![0x00]].concat(),
            ),
            (
                "an INTEGER after e",
                tlv(0x30, &[n.clone(), e.clone(), integer(&[1])].concat()),
            ),
            (
                "a byte after e",
                tlv(0x30, &[n.clone(), e.clone(), vec![0x00]].concat()),
            ),
            ("e before n", tlv(0x30, &[e.clone(), n.clone()].concat())),
            ("n alone", tlv(0x30, &n)),
            (
                "a sign byte too many",
                tlv(
                    0x30,
                    &[tlv(0x02, &[&[0], &n[4..]].concat()), e.clone()].concat(),
                ),
            ),
            (
                "a negative e",
                tlv(0x30, &[n.clone(), tlv(0x02, &[0x81, 0x00, 0x01])].concat()),
            ),
            ("a SET", tlv(0x31, &[n.clone(), e.clone()].concat())),
            (
                "e in the long form",
                tlv(
                    0x30,
                    &[n.clone(), vec![0x02, 0x81, 0x03, 0x01, 0x00, 0x01]].concat(),
                ),
            ),
        ] {
            assert!(!takes(&der), "{what}");
        }
    }

    /// ring's bounds: a modulus of at least 256 whole bytes, so 2041 bits
    /// and not 2040, of at most 8192 bits, and odd; an exponent odd, from
    /// 3 to 2^33 - 1, in at most five bytes.
    #[test]
    fn the_bounds_are_rings() {
        let modulus = |bits: usize| {
            let mut n = vec![0xa5; bits.div_ceil(8)];
            n[0] = 0xff >> (n.len() * 8 - bits);
            *n.last_mut().unwrap() |= 1;
            n
        };
        for (bits, taken) in [
            (1024, false),
            (2040, false),
            (2041, true),
            (2048, true),
            (8192, true),
            (8193, false),
        ] {
            assert_eq!(
                takes(&public_key(&modulus(bits), &[1, 0, 1])),
                taken,
                "{bits} bits"
            );
        }
        let mut even = modulus(2048);
        *even.last_mut().unwrap() &= 0xfe;
        assert!(!takes(&public_key(&even, &[1, 0, 1])), "an even modulus");
        for (e, taken) in [
            (1u64, false),
            (2, false),
            (3, true),
            (4, false),
            (65537, true),
            ((1 << 31) - 1, true),
            ((1 << 31) + 1, true),
            ((1 << 32) + 1, true),
            ((1 << 33) - 1, true),
            ((1 << 33) + 1, false),
            ((1 << 40) + 1, false),
        ] {
            let bytes = e.to_be_bytes();
            let start = bytes.iter().position(|&b| b != 0).unwrap();
            assert_eq!(
                takes(&public_key(&modulus(2048), &bytes[start..])),
                taken,
                "e = {e}"
            );
        }
    }

    /// A signature is the modulus's length, neither zero nor at or above
    /// the modulus; n - 1 and 1 are raised.
    #[test]
    fn a_signature_is_in_range() {
        let key = rsa_test_key("rsa2048");
        let public = PublicKey::parse(&key.rsa_public_key(), &RING_LIMITS).expect("the key");
        let n = BigUint::from_bytes_be(&key.n);
        let at = |value: &BigUint| {
            let bytes = value.to_bytes_be();
            [vec![0; 256 - bytes.len()], bytes].concat()
        };
        let one = at(&BigUint::from(1u8));
        assert_eq!(public.raise(&one).as_deref(), Some(&one[..]));
        assert!(public.raise(&at(&(&n - 1u8))).is_some());
        for (what, signature) in [
            ("zero", vec![0; 256]),
            ("n", at(&n)),
            ("n + 1", at(&(&n + 1u8))),
            ("a byte short", one[1..].to_vec()),
            ("a byte long", [vec![0], one.clone()].concat()),
            ("nothing", Vec::new()),
        ] {
            assert_eq!(public.raise(&signature), None, "{what}");
        }
    }

    /// A PKCS#1 v1.5 signature verifies under its own hash alone, for keys
    /// of 2041, 2048 and 3072 bits and under e = 3 and an exponent above
    /// Go's cap, and is refused for keys outside ring's bounds, as PSS,
    /// and over another message; and an encoding without the NULL
    /// parameters, or with the block type a byte late, is refused.
    #[test]
    fn pkcs1_signatures_verify_as_ring_builds_them() {
        let message = b"a TLS 1.2 ServerKeyExchange's parameters";
        let hashes = [Hash::Sha256, Hash::Sha384, Hash::Sha512];
        for name in [
            "rsa2041",
            "rsa2048",
            "rsa3072",
            "rsa2048-e3",
            "rsa2048-e8589934591",
            "rsa1024",
            "rsa2040",
        ] {
            let key = rsa_test_key(name);
            let public = key.rsa_public_key();
            let in_bounds = !matches!(name, "rsa1024" | "rsa2040");
            for hash in hashes {
                let prefix = hash.digest_info_prefix();
                let encoded = pkcs1_encoding(hash, prefix, message, key.n.len());
                let signature = sign_raw(&key, &encoded);
                for other in hashes {
                    let verified = RsaVerify::pkcs1("test", other, alg_id::RSA_PKCS1_SHA256)
                        .verifies(&public, message, &signature)
                        .is_some();
                    assert_eq!(
                        verified,
                        in_bounds && hash == other,
                        "{name}, {hash:?} as {other:?}"
                    );
                }
                let pkcs1 = RsaVerify::pkcs1("test", hash, alg_id::RSA_PKCS1_SHA256);
                let pss = RsaVerify::pss("test", hash, alg_id::RSA_PSS_SHA256);
                assert!(
                    pss.verifies(&public, message, &signature).is_none(),
                    "{name}"
                );
                assert!(
                    pkcs1.verifies(&public, b"another", &signature).is_none(),
                    "{name}"
                );
                if !in_bounds {
                    continue;
                }
                let no_null = [
                    &[0x30, prefix[1] - 2, 0x30, prefix[3] - 2][..],
                    &prefix[4..15],
                    &prefix[17..],
                ]
                .concat();
                let t = [prefix, &hash.digest(&[message])].concat();
                let late = [
                    &[0x00, 0x00, 0x01][..],
                    &vec![0xff; key.n.len() - 4 - t.len()],
                    &[0x00],
                    &t,
                ]
                .concat();
                for (what, wrong) in [
                    (
                        "without NULL",
                        pkcs1_encoding(hash, &no_null, message, key.n.len()),
                    ),
                    ("the block type a byte late", late),
                ] {
                    let signature = sign_raw(&key, &wrong);
                    assert!(
                        pkcs1.verifies(&public, message, &signature).is_none(),
                        "{name}, {hash:?}, {what}"
                    );
                }
            }
        }
    }

    /// A PKCS#1 v1.5 encoding is compared whole: with any one of its fixed
    /// bytes changed, the leading `00`, the block type, a padding byte,
    /// the `00` after the padding or the arc of the DigestInfo's identifier
    /// that names the hash, the signature that carries it is refused.
    #[test]
    fn pkcs1_encodings_are_compared_whole() {
        let key = rsa_test_key("rsa2048");
        let public = key.rsa_public_key();
        let message = b"a TLS 1.3 CertificateVerify's content";
        let k = key.n.len();
        for (hash, other_arc) in [
            (Hash::Sha256, 0x02),
            (Hash::Sha384, 0x03),
            (Hash::Sha512, 0x01),
        ] {
            let pkcs1 = RsaVerify::pkcs1("test", hash, alg_id::RSA_PKCS1_SHA256);
            let prefix = hash.digest_info_prefix();
            let encoded = pkcs1_encoding(hash, prefix, message, k);
            assert!(
                pkcs1
                    .verifies(&public, message, &sign_raw(&key, &encoded))
                    .is_some(),
                "{hash:?}"
            );
            // The `00` before the DigestInfo, and the last byte of the
            // hash's identifier, 2.16.840.1.101.3.4.2.1 to .3, the 15th
            // byte of the DigestInfo.
            let separator = k - prefix.len() - hash.len() - 1;
            let arc = separator + 15;
            assert_eq!(encoded[arc], prefix[14], "{hash:?}: the arc");
            for (what, at, value) in [
                ("the leading 00", 0, 0x01),
                ("the block type", 1, 0x02),
                ("a padding byte", 2, 0xfe),
                ("the 00 after the padding", separator, 0x01),
                ("the hash's arc", arc, other_arc),
            ] {
                let mut wrong = encoded.clone();
                wrong[at] = value;
                assert!(
                    pkcs1
                        .verifies(&public, message, &sign_raw(&key, &wrong))
                        .is_none(),
                    "{hash:?}, {what}"
                );
            }
        }
    }

    /// A PSS signature with a salt the hash's length verifies under its
    /// own hash alone, for a 2041-bit key, whose encoding is a byte shorter
    /// than the modulus, and a 2048-bit one, whose encoding's top bit is
    /// unused; and is refused with another salt length, as PKCS#1 v1.5,
    /// and with each of EMSA-PSS-VERIFY's checks broken in turn: the
    /// leading byte, the unused top bit, the trailer, the zeros before the
    /// salt and the `01` after them.
    #[test]
    fn pss_signatures_verify_as_rfc_8017_encodes_them() {
        let message = b"a TLS 1.3 CertificateVerify's content";
        let hashes = [Hash::Sha256, Hash::Sha384, Hash::Sha512];
        for name in ["rsa2041", "rsa2048", "rsa2048-e3", "rsa1024"] {
            let key = rsa_test_key(name);
            let public = key.rsa_public_key();
            let bits = usize::try_from(key.bits).expect("bits");
            for hash in hashes {
                if (bits - 1).div_ceil(8) < 2 * hash.len() + 2 {
                    // No room for the salt and the hash: a 1024-bit key
                    // and SHA-512.
                    continue;
                }
                let pss = RsaVerify::pss("test", hash, alg_id::RSA_PSS_SHA256);
                let salt: Vec<u8> = (0..hash.len()).map(|i| i as u8).collect();
                let signature = sign_raw(&key, &pss_encoding(hash, message, &salt, bits));
                for other in hashes {
                    let verified = RsaVerify::pss("test", other, alg_id::RSA_PSS_SHA256)
                        .verifies(&public, message, &signature)
                        .is_some();
                    assert_eq!(
                        verified,
                        name != "rsa1024" && hash == other,
                        "{name}, {hash:?} as {other:?}"
                    );
                }
                let pkcs1 = RsaVerify::pkcs1("test", hash, alg_id::RSA_PKCS1_SHA256);
                assert!(
                    pkcs1.verifies(&public, message, &signature).is_none(),
                    "{name}"
                );
                if name == "rsa1024" {
                    continue;
                }
                for len in [0, hash.len() - 1, hash.len() + 1] {
                    let encoded = pss_encoding(hash, message, &vec![7; len], bits);
                    let signature = sign_raw(&key, &encoded);
                    assert!(
                        pss.verifies(&public, message, &signature).is_none(),
                        "{name}, {hash:?}, a salt of {len}"
                    );
                }
                let n = BigUint::from_bytes_be(&key.n);
                let k = key.n.len();
                let em_start = k - (bits - 1).div_ceil(8);
                let separator = k - 2 * hash.len() - 2;
                type Change = Box<dyn Fn(&mut Vec<u8>)>;
                let mut broken: Vec<(&str, Change)> = vec![
                    ("the trailer", Box::new(move |e| e[k - 1] = 0xbd)),
                    // The zeros and the `01` sit under the mask: a bit of
                    // maskedDB flipped there flips DB's.
                    (
                        "the zeros before the salt",
                        Box::new(move |e| e[em_start + 1] ^= 0x01),
                    ),
                    (
                        "the 01 before the salt",
                        Box::new(move |e| e[separator] ^= 0x01),
                    ),
                ];
                if em_start == 1 {
                    broken.push(("the leading byte", Box::new(|e| e[0] = 0x01)));
                } else {
                    broken.push(("the unused top bit", Box::new(|e| e[0] |= 0x80)));
                }
                for (what, change) in broken {
                    // A salt for which the broken encoding is below the
                    // modulus, so that a signature can carry it.
                    let wrong = (0..=u8::MAX)
                        .find_map(|first| {
                            let mut salt = salt.clone();
                            salt[0] = first;
                            let mut encoded = pss_encoding(hash, message, &salt, bits);
                            change(&mut encoded);
                            (BigUint::from_bytes_be(&encoded) < n).then_some(encoded)
                        })
                        .unwrap_or_else(|| panic!("{name}, {what}: no encoding below n"));
                    let signature = sign_raw(&key, &wrong);
                    assert!(
                        pss.verifies(&public, message, &signature).is_none(),
                        "{name}, {hash:?}, {what}"
                    );
                }
            }
        }
    }
}
