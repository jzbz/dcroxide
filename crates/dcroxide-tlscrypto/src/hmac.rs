// SPDX-License-Identifier: ISC
//! HMAC-SHA256 and HMAC-SHA384 as rustls's `Hmac` (ring's
//! `rustls-0.23.46/src/crypto/ring/hmac.rs`), and over them the TLS 1.3
//! HKDF and the TLS 1.2 PRF, which are rustls's own constructions on any
//! `Hmac` (`HkdfUsingHmac`, `src/crypto/tls13.rs:10-93`; `PrfUsingHmac`,
//! `src/crypto/tls12.rs:7-86`).  rustls checks HKDF's limit of 255 blocks
//! of output itself (`tls13.rs:30-33`).

use core::marker::PhantomData;

use ::hmac::{EagerHash, KeyInit, Mac};
use rustls::crypto;
use rustls::crypto::tls12::PrfUsingHmac;
use rustls::crypto::tls13::HkdfUsingHmac;
use sha2::{Digest, Sha256, Sha384};

/// HMAC-SHA256.
pub(crate) static HMAC_SHA256: HmacSha<Sha256> = HmacSha(PhantomData);
/// HMAC-SHA384.
pub(crate) static HMAC_SHA384: HmacSha<Sha384> = HmacSha(PhantomData);

/// HKDF-SHA256, the key schedule of the TLS 1.3 suites named `_SHA256`.
pub(crate) static HKDF_SHA256: HkdfUsingHmac<'static> = HkdfUsingHmac(&HMAC_SHA256);
/// HKDF-SHA384, the key schedule of TLS13_AES_256_GCM_SHA384.
pub(crate) static HKDF_SHA384: HkdfUsingHmac<'static> = HkdfUsingHmac(&HMAC_SHA384);

/// The TLS 1.2 PRF over HMAC-SHA256 (RFC 5246 §5).
pub(crate) static PRF_SHA256: PrfUsingHmac<'static> = PrfUsingHmac(&HMAC_SHA256);
/// The TLS 1.2 PRF over HMAC-SHA384, which the suites named `_SHA384`
/// take (RFC 5289 §3.2).
pub(crate) static PRF_SHA384: PrfUsingHmac<'static> = PrfUsingHmac(&HMAC_SHA384);

/// HMAC over the SHA-2 function `D`.
pub(crate) struct HmacSha<D>(PhantomData<fn() -> D>);

impl<D: EagerHash + Send + Sync + 'static> crypto::hmac::Hmac for HmacSha<D>
where
    D::Core: Send + Sync,
{
    fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        // `hmac` takes a key of any length, hashing one longer than a
        // block and padding a shorter one, and returns `Ok` for every
        // length (`hmac-0.13.0/src/block_api.rs:46-70`).
        let keyed = ::hmac::Hmac::<D>::new_from_slice(key).expect("HMAC accepts any key length");
        Box::new(HmacKey(keyed))
    }

    fn hash_output_len(&self) -> usize {
        <D as Digest>::output_size()
    }
}

/// A keyed HMAC: the hash states after the inner and outer pads.
struct HmacKey<D: EagerHash>(::hmac::Hmac<D>);

impl<D: EagerHash + Send + Sync + 'static> crypto::hmac::Key for HmacKey<D>
where
    D::Core: Send + Sync,
{
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> crypto::hmac::Tag {
        let mut mac = self.0.clone();
        mac.update(first);
        for piece in middle {
            mac.update(piece);
        }
        mac.update(last);
        crypto::hmac::Tag::new(mac.finalize().as_bytes())
    }

    fn tag_len(&self) -> usize {
        <D as Digest>::output_size()
    }
}

// What wipes a keyed HMAC when it is dropped, which includes the copy each
// tag is computed on.  `hmac`'s core holds the two SHA-2 states and has no
// `Drop` of its own (`hmac-0.13.0/src/block_api.rs:13-17`); each state
// wipes itself under `sha2`'s `zeroize` feature
// (`sha2-0.11.0/src/block_api.rs:89-101`, `:208-219`), and the block
// buffer beside them under `digest`'s
// (`block-buffer-0.12.1/src/lib.rs:433-442`), which `sha2`'s feature turns
// on, and `hmac`'s as well (`sha2-0.11.0/Cargo.toml:52`,
// `hmac-0.13.0/Cargo.toml:44`).  So this pins `sha2`'s feature, without
// which it does not compile.  The manifest enables `hmac`'s too, so that
// the buffer's wipe does not rest on what `sha2`'s feature happens to
// include.
const _: () = {
    fn wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    let _ = wiped_on_drop::<<Sha256 as EagerHash>::Core>;
    let _ = wiped_on_drop::<<Sha384 as EagerHash>::Core>;
    let _ = wiped_on_drop::<::hmac::digest::block_api::Buffer<::hmac::block_api::HmacCore<Sha256>>>;
    let _ = wiped_on_drop::<::hmac::digest::block_api::Buffer<::hmac::block_api::HmacCore<Sha384>>>;
};

#[cfg(test)]
// Test-harness arithmetic over message offsets.
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use dcroxide_testutil::hex;
    use rustls::crypto::hmac::Hmac;

    use super::*;

    /// RFC 4231's seven test cases (§4.2-4.8): key, data, and the tags
    /// HMAC-SHA256 and HMAC-SHA384 give.  Case 5's tags are truncated to
    /// 128 bits in the RFC, and are compared on that prefix.  Cases 6 and
    /// 7 have a key longer than either hash's block.
    fn rfc_4231() -> [(Vec<u8>, Vec<u8>, &'static str, &'static str); 7] {
        [
            (
                vec![0x0b; 20],
                b"Hi There".to_vec(),
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
                "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c\
                 faea9ea9076ede7f4af152e8b2fa9cb6",
            ),
            (
                b"Jefe".to_vec(),
                b"what do ya want for nothing?".to_vec(),
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
                "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e\
                 8e2240ca5e69e2c78b3239ecfab21649",
            ),
            (
                vec![0xaa; 20],
                vec![0xdd; 50],
                "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
                "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b\
                 2a5ab39dc13814b94e3ab6e101a34f27",
            ),
            (
                (0x01..=0x19).collect(),
                vec![0xcd; 50],
                "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
                "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e\
                 6801dd23c4a7d679ccf8a386c674cffb",
            ),
            (
                vec![0x0c; 20],
                b"Test With Truncation".to_vec(),
                "a3b6167473100ee06e0c796c2955552b",
                "3abf34c3503b2a23a46efc619baef897",
            ),
            (
                vec![0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
                "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c6\
                 0c2ef6ab4030fe8296248df163f44952",
            ),
            (
                vec![0xaa; 131],
                b"This is a test using a larger than block-size key and a larger \
                  than block-size data. The key needs to be hashed before being \
                  used by the HMAC algorithm."
                    .to_vec(),
                "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
                "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5\
                 a678cc31e799176d3860e6110c46523e",
            ),
        ]
    }

    /// The tag `hmac` gives over `data` with `key`, as rustls asks for one.
    fn tag(hmac: &dyn Hmac, key: &[u8], data: &[u8]) -> Vec<u8> {
        hmac.with_key(key).sign(&[data]).as_ref().to_vec()
    }

    #[test]
    fn hmac_answers_rfc_4231() {
        for (case, (key, data, sha256, sha384)) in rfc_4231().into_iter().enumerate() {
            for (hmac, expected) in [(&HMAC_SHA256 as &dyn Hmac, sha256), (&HMAC_SHA384, sha384)] {
                let tag = hex(&tag(hmac, &key, &data));
                assert!(
                    tag.starts_with(expected),
                    "case {}: {tag} for {expected}",
                    case + 1
                );
                assert_eq!(tag.len(), hmac.hash_output_len() * 2, "case {}", case + 1);
            }
        }
    }

    /// `sign_concat` signs its three parts as one message, however the
    /// message is split, and leaves the key able to sign again.
    #[test]
    fn a_tag_is_over_the_concatenation() {
        let [.., (key, data, sha256, sha384)] = rfc_4231();
        for (hmac, expected) in [(&HMAC_SHA256 as &dyn Hmac, sha256), (&HMAC_SHA384, sha384)] {
            let keyed = hmac.with_key(&key);
            assert_eq!(keyed.tag_len(), hmac.hash_output_len());
            for split in [0, 1, 64, 127, 128, data.len()] {
                let (first, rest) = data.split_at(split);
                let (middle, last) = rest.split_at(rest.len() / 2);
                let (m1, m2) = middle.split_at(middle.len() / 3);
                let tag = keyed.sign_concat(first, &[m1, &[], m2], last);
                assert_eq!(hex(tag.as_ref()), expected, "split at {split}");
            }
        }
    }

    #[test]
    fn output_lengths_are_the_hashes() {
        assert_eq!(HMAC_SHA256.hash_output_len(), 32);
        assert_eq!(HMAC_SHA384.hash_output_len(), 48);
    }
}
