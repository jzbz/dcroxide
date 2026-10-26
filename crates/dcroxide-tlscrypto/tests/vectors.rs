// SPDX-License-Identifier: ISC
//! Published known answers for what each suite hands rustls besides its
//! record protection: the transcript hash (FIPS 180-2), the TLS 1.3 HKDF
//! (RFC 5869), and the TLS 1.2 PRF (the vectors posted to the IETF TLS
//! list, which rustls tests its own PRF with,
//! `rustls-0.23.46/src/crypto/tls12.rs:88-150`).  Each is reached through
//! the suite, the way rustls reaches it.  RFC 4231's HMAC cases are unit
//! tests in `src/hmac.rs` instead: a suite's HMAC is reached directly only
//! through its HKDF's `hmac_sign`, whose key is an `OkmBlock` of at most 64
//! bytes, and two of the cases have keys of 131.  Wycheproof's HMAC and
//! HKDF files run beside these, in `src/wycheproof_tests.rs`.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_testutil::{hex, unhex};
use dcroxide_tlscrypto::cipher_suite::{
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
};
use rustls::SupportedCipherSuite;
use rustls::crypto::hash::{Hash, HashAlgorithm};
use rustls::crypto::tls12::Prf;
use rustls::crypto::tls13::{Hkdf, OkmBlock};

/// The suites built on SHA-256.
const SHA256_SUITES: [SupportedCipherSuite; 6] = [
    TLS13_AES_128_GCM_SHA256,
    TLS13_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// The suites built on SHA-384.
const SHA384_SUITES: [SupportedCipherSuite; 3] = [
    TLS13_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
];

/// A suite's transcript hash.
fn hash(suite: SupportedCipherSuite) -> &'static dyn Hash {
    match suite {
        SupportedCipherSuite::Tls13(tls13) => tls13.common.hash_provider,
        SupportedCipherSuite::Tls12(tls12) => tls12.common.hash_provider,
    }
}

/// A TLS 1.3 suite's HKDF.
fn hkdf(suite: SupportedCipherSuite) -> Option<&'static dyn Hkdf> {
    match suite {
        SupportedCipherSuite::Tls13(tls13) => Some(tls13.hkdf_provider),
        SupportedCipherSuite::Tls12(_) => None,
    }
}

/// A TLS 1.2 suite's PRF.
fn prf(suite: SupportedCipherSuite) -> Option<&'static dyn Prf> {
    match suite {
        SupportedCipherSuite::Tls12(tls12) => Some(tls12.prf_provider),
        SupportedCipherSuite::Tls13(_) => None,
    }
}

/// FIPS 180-2's messages for SHA-256 and SHA-384 (its appendices B and D,
/// one-block and multi-block), and the empty message, with their digests.
const FIPS_180_2: [(&str, &str, &str); 3] = [
    (
        "abc",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
         8086072ba1e7cc2358baeca134c825a7",
    ),
    (
        "",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da\
         274edebfe76f65fbd51ad2f14898b95b",
    ),
    (
        // SHA-256's two-block message; SHA-384's is the one below.
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6\
         b0455a8520bc4e6f5fe95b1fe3c8452b",
    ),
];

/// SHA-384's two-block message (FIPS 180-2 appendix D.2) and its digest.
const SHA384_TWO_BLOCKS: (&str, &str) = (
    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrl\
     mnopqrsmnopqrstnopqrstu",
    "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712\
     fcc7c71a557e2db966c3e9fa91746039",
);

/// Every suite's transcript hash gives FIPS 180-2's digests, in one call
/// and incrementally, and a forked computation goes on independently.
#[test]
fn every_suite_hashes_as_fips_180_2_says() {
    let mut cases: Vec<(SupportedCipherSuite, &str, &str)> = Vec::new();
    for suite in SHA256_SUITES {
        cases.extend(FIPS_180_2.map(|(msg, sha256, _)| (suite, msg, sha256)));
    }
    for suite in SHA384_SUITES {
        cases.extend(FIPS_180_2.map(|(msg, _, sha384)| (suite, msg, sha384)));
        cases.push((suite, SHA384_TWO_BLOCKS.0, SHA384_TWO_BLOCKS.1));
    }
    for (suite, msg, digest) in cases {
        let hash = hash(suite);
        assert_eq!(hex(hash.hash(msg.as_bytes()).as_ref()), digest, "{suite:?}");
        assert_eq!(hash.output_len() * 2, digest.len(), "{suite:?}");

        let mut context = hash.start();
        let (first, rest) = msg.as_bytes().split_at(msg.len() / 3);
        context.update(first);
        let forked = context.fork();
        context.update(rest);
        assert_eq!(hex(context.fork_finish().as_ref()), digest, "{suite:?}");
        // The fork has seen only `first`, and finishing the original
        // above left it able to go on.
        let mut forked = forked;
        forked.update(rest);
        assert_eq!(hex(forked.finish().as_ref()), digest, "{suite:?}: the fork");
        assert_eq!(hex(context.finish().as_ref()), digest, "{suite:?}");
    }
    for suite in SHA256_SUITES {
        assert_eq!(hash(suite).algorithm(), HashAlgorithm::SHA256);
    }
    for suite in SHA384_SUITES {
        assert_eq!(hash(suite).algorithm(), HashAlgorithm::SHA384);
    }
}

/// One of RFC 5869's cases: input keying material, salt and info, and
/// the pseudorandom key and output keying material they give.
struct HkdfCase {
    /// The input keying material.
    ikm: Vec<u8>,
    /// The salt.
    salt: Vec<u8>,
    /// The info.
    info: Vec<u8>,
    /// The pseudorandom key, in hex.
    prk: &'static str,
    /// The output keying material, in hex.
    okm: &'static str,
}

/// RFC 5869's three SHA-256 cases (appendix A.1-A.3).  Case 3 has an
/// empty salt and info.
fn rfc_5869() -> [HkdfCase; 3] {
    [
        HkdfCase {
            ikm: vec![0x0b; 22],
            salt: (0x00..=0x0c).collect(),
            info: (0xf0..=0xf9).collect(),
            prk: "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            okm: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
                  34007208d5b887185865",
        },
        HkdfCase {
            ikm: (0x00..=0x4f).collect(),
            salt: (0x60..=0xaf).collect(),
            info: (0xb0..=0xff).collect(),
            prk: "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
            okm: "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
                  59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
                  cc30c58179ec3e87c14c01d5c1f3434f1d87",
        },
        HkdfCase {
            ikm: vec![0x0b; 22],
            salt: Vec::new(),
            info: Vec::new(),
            prk: "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
            okm: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
                  9d201395faa4b61a96c8",
        },
    ]
}

/// The TLS 1.3 suites on SHA-256 extract and expand as RFC 5869 says,
/// with the info in one piece or several, from the pseudorandom key the
/// RFC gives as well as from the extraction, and with no salt as with an
/// empty one.
#[test]
fn the_tls13_suites_on_sha256_expand_as_rfc_5869_says() {
    for suite in SHA256_SUITES {
        let Some(hkdf) = hkdf(suite) else {
            continue;
        };
        for (
            case,
            HkdfCase {
                ikm,
                salt,
                info,
                prk,
                okm,
            },
        ) in rfc_5869().into_iter().enumerate()
        {
            let case = case + 1;
            let mut out = vec![0; okm.len() / 2];
            let extracted = hkdf.extract_from_secret(Some(&salt), &ikm);
            extracted
                .expand_slice(&[&info], &mut out)
                .expect("expanded");
            assert_eq!(hex(&out), okm, "{suite:?} case {case}");

            let (front, back) = info.split_at(info.len() / 2);
            extracted
                .expand_slice(&[front, &[], back], &mut out)
                .expect("expanded");
            assert_eq!(hex(&out), okm, "{suite:?} case {case}, the info in pieces");

            let from_prk = hkdf.expander_for_okm(&OkmBlock::new(&unhex(prk)));
            from_prk.expand_slice(&[&info], &mut out).expect("expanded");
            assert_eq!(hex(&out), okm, "{suite:?} case {case}, from the PRK");

            // The first block is HMAC(PRK, info || 0x01) (RFC 5869 §2.3).
            let first = from_prk.expand_block(&[&info]);
            assert_eq!(hex(first.as_ref()), okm[..64], "{suite:?} case {case}");
            let signed = hkdf.hmac_sign(&OkmBlock::new(&unhex(prk)), &[&info[..], &[1]].concat());
            assert_eq!(hex(signed.as_ref()), okm[..64], "{suite:?} case {case}");

            if salt.is_empty() {
                // No salt is HashLen zero bytes, which as an HMAC key is
                // the empty key padded (RFC 5869 §2.2).
                let unsalted = hkdf.extract_from_secret(None, &ikm);
                unsalted.expand_slice(&[&info], &mut out).expect("expanded");
                assert_eq!(hex(&out), okm, "{suite:?} case {case}, no salt");
            }
        }
    }
}

/// HKDF refuses an output longer than 255 blocks of its hash
/// (RFC 5869 §2.3), and gives one of exactly 255.
#[test]
fn the_tls13_suites_refuse_more_than_255_blocks() {
    for suite in SHA256_SUITES.into_iter().chain(SHA384_SUITES) {
        let Some(hkdf) = hkdf(suite) else {
            continue;
        };
        let expander = hkdf.extract_from_secret(Some(b"salt"), b"secret");
        let blocks = expander.hash_len() * 255;
        assert!(
            expander
                .expand_slice(&[b"info"], &mut vec![0; blocks])
                .is_ok(),
            "{suite:?}"
        );
        assert!(
            expander
                .expand_slice(&[b"info"], &mut vec![0; blocks + 1])
                .is_err(),
            "{suite:?}"
        );
    }
}

/// The TLS 1.2 PRF vectors posted to the IETF TLS list, as rustls carries
/// them (`rustls-0.23.46/src/crypto/tls12.rs:88-150`): secret, seed, the
/// label "test label", and the output for SHA-256 and SHA-384.
const PRF_SHA256: (&str, &str, &str) = (
    "9bbe436ba940f017b17652849a71db35",
    "a0ba9f936cda311827a6f796ffd5198c",
    "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a\
     6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab\
     4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff701\
     87347b66",
);

/// The SHA-384 vector of the same posting.
const PRF_SHA384: (&str, &str, &str) = (
    "b80b733d6ceefcdc71566ea48e5567df",
    "cd665cf6a8447dd6ff8b27555edb7465",
    "7b0c18e9ced410ed1804f2cfa34a336a1c14dffb4900bb5fd7942107e81c83cd\
     e9ca0faa60be9fe34f82b1233c9146a0e534cb400fed2700884f9dc236f80edd\
     8bfa961144c9e8d792eca722a7b32fc3d416d473ebc2c5fd4abfdad05d918425\
     9b5bf8cd4d90fa0d31e2dec479e4f1a26066f2eea9a69236a3e52655c9e9aee6\
     91c8f3a26854308d5eaa3be85e0990703d73e56f",
);

/// Each TLS 1.2 suite's PRF gives the posted output for its hash, and any
/// prefix of it for a shorter output.
#[test]
fn the_tls12_suites_derive_as_the_posted_prf_vectors_say() {
    let sha256 = SHA256_SUITES.into_iter().map(|suite| (suite, PRF_SHA256));
    let sha384 = SHA384_SUITES.into_iter().map(|suite| (suite, PRF_SHA384));
    let mut checked = 0;
    for (suite, (secret, seed, output)) in sha256.chain(sha384) {
        let Some(prf) = prf(suite) else {
            continue;
        };
        for len in [output.len() / 2, 1, 31, 32, 33, 48] {
            let mut out = vec![0; len];
            prf.for_secret(&mut out, &unhex(secret), b"test label", &unhex(seed));
            assert_eq!(hex(&out), output[..len * 2], "{suite:?}, {len} bytes");
        }
        checked += 1;
    }
    assert_eq!(checked, 6, "every TLS 1.2 suite");
}
