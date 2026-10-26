// SPDX-License-Identifier: ISC
//! Parity with rustls's ring provider, proven while ring is still in the
//! tree (ADR-0015, step 1): what this crate replaces ring with must make
//! ring's choices and interoperate with it.
//!
//! For the cipher suites: each is assembled as ring's suite of the same
//! name is, and the lists are ring's in ring's order; the hashes, HKDFs and
//! PRFs give ring's answers; records sealed by either open under the
//! other; and a full handshake in memory runs for each suite with this
//! crate's suite on one side and ring's on the other, both ways, carrying
//! application data each way and, in TLS 1.3, across a key update, after
//! which both ends hand out the same traffic secrets.  The keys and
//! certificate verification are ring's on both sides, since the crate has
//! none of its own yet, so those handshakes run the two key schedules and
//! record layers against each other.
//!
//! For the key exchange groups ring has, X25519, P-256 and P-384: the
//! default list is ring's; each group takes and refuses the shares ring's
//! takes and refuses, the generated ones of `kx_shares` and every public
//! key of Wycheproof's files for the group; each agrees ring's secret with
//! ring's key share and ring agrees its with the group's; and a handshake
//! in each TLS version negotiates the group with this crate's on one side
//! and ring's on the other, both ways.  P-521, which ring lacks, runs the
//! same handshakes with this crate's group on both sides, and is held to
//! Go's verdicts instead (`tests/go_differential.rs`).
//!
//! The ring half of this file goes at the switch, with the dev-dependency
//! that selects ring.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

mod kx_shares;

use std::io::{Read, Write};
use std::sync::Arc;

use dcroxide_testutil::unhex;
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, Iv, MessageDecrypter, MessageEncrypter, OutboundChunks,
    OutboundPlainMessage, Tls12AeadAlgorithm, Tls13AeadAlgorithm,
};
use rustls::crypto::hash::Hash;
use rustls::crypto::tls13::OkmBlock;
use rustls::crypto::{CryptoProvider, SupportedKxGroup, ring};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, ConnectionCommon, ConnectionTrafficSecrets, ContentType,
    NamedGroup, ProtocolVersion, RootCertStore, ServerConfig, ServerConnection, SignatureScheme,
    SupportedCipherSuite,
};

/// This crate's nine suites, each beside ring's of the same name.
fn pairs() -> [(SupportedCipherSuite, SupportedCipherSuite); 9] {
    use dcroxide_tlscrypto::cipher_suite as ours;
    use ring::cipher_suite as rings;
    [
        (
            ours::TLS13_AES_128_GCM_SHA256,
            rings::TLS13_AES_128_GCM_SHA256,
        ),
        (
            ours::TLS13_AES_256_GCM_SHA384,
            rings::TLS13_AES_256_GCM_SHA384,
        ),
        (
            ours::TLS13_CHACHA20_POLY1305_SHA256,
            rings::TLS13_CHACHA20_POLY1305_SHA256,
        ),
        (
            ours::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            rings::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        ),
        (
            ours::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            rings::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        ),
        (
            ours::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            rings::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        ),
        (
            ours::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            rings::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ),
        (
            ours::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            rings::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ),
        (
            ours::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            rings::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ),
    ]
}

/// A suite's transcript hash.
fn hash_of(suite: SupportedCipherSuite) -> &'static dyn Hash {
    match suite {
        SupportedCipherSuite::Tls13(tls13) => tls13.common.hash_provider,
        SupportedCipherSuite::Tls12(tls12) => tls12.common.hash_provider,
    }
}

/// The suite lists are ring's, suite for suite and in ring's order, and
/// the default is what ring's provider offers.
#[test]
fn the_suite_lists_are_rings() {
    let names =
        |suites: &[SupportedCipherSuite]| suites.iter().map(|s| s.suite()).collect::<Vec<_>>();
    assert_eq!(
        names(dcroxide_tlscrypto::ALL_CIPHER_SUITES),
        names(ring::ALL_CIPHER_SUITES)
    );
    assert_eq!(
        names(dcroxide_tlscrypto::DEFAULT_CIPHER_SUITES),
        names(&ring::default_provider().cipher_suites)
    );
    for (ours, rings) in pairs() {
        assert_eq!(ours.suite(), rings.suite());
        assert_eq!(ours.version(), rings.version(), "{:?}", ours.suite());
    }
}

/// Each suite is assembled as ring's of the same name: its hash, its
/// confidentiality limit and its AEAD, by the secrets the AEAD hands out,
/// which name it, and by its key length, and in TLS 1.2 its key exchange,
/// its signature schemes and its key block.  Ring's TLS 1.3 suites also
/// carry QUIC keys, which these do not.
#[test]
fn each_suite_is_assembled_as_rings() {
    for (ours, rings) in pairs() {
        let name = ours.suite();
        assert_eq!(
            hash_of(ours).algorithm(),
            hash_of(rings).algorithm(),
            "{name:?}"
        );
        match (ours, rings) {
            (SupportedCipherSuite::Tls13(ours), SupportedCipherSuite::Tls13(rings)) => {
                assert_eq!(
                    ours.common.confidentiality_limit, rings.common.confidentiality_limit,
                    "{name:?}"
                );
                let aead = |aead: &dyn Tls13AeadAlgorithm| {
                    let secrets = aead
                        .extract_keys(AeadKey::from(KEY), Iv::from(IV))
                        .expect("extracted");
                    named(&secrets).0
                };
                assert_eq!(aead(ours.aead_alg), aead(rings.aead_alg), "{name:?}");
                assert_eq!(
                    ours.aead_alg.key_len(),
                    rings.aead_alg.key_len(),
                    "{name:?}"
                );
                assert!(ours.quic.is_none() && rings.quic.is_some(), "{name:?}");
            }
            (SupportedCipherSuite::Tls12(ours), SupportedCipherSuite::Tls12(rings)) => {
                assert_eq!(
                    ours.common.confidentiality_limit, rings.common.confidentiality_limit,
                    "{name:?}"
                );
                assert_eq!(ours.kx, rings.kx, "{name:?}");
                assert_eq!(ours.sign, rings.sign, "{name:?}");
                let (o, r) = (
                    ours.aead_alg.key_block_shape(),
                    rings.aead_alg.key_block_shape(),
                );
                assert_eq!(
                    (o.enc_key_len, o.fixed_iv_len, o.explicit_nonce_len),
                    (r.enc_key_len, r.fixed_iv_len, r.explicit_nonce_len),
                    "{name:?}"
                );
                let (iv, explicit) = IV.split_at(o.fixed_iv_len);
                let explicit = &explicit[..o.explicit_nonce_len];
                let aead = |aead: &dyn Tls12AeadAlgorithm| {
                    let secrets = aead
                        .extract_keys(AeadKey::from(KEY), iv, explicit)
                        .expect("extracted");
                    named(&secrets).0
                };
                assert_eq!(aead(ours.aead_alg), aead(rings.aead_alg), "{name:?}");
            }
            _ => panic!("{name:?}: the versions differ"),
        }
    }
}

/// Inputs of the lengths the key schedules see and the edges around a
/// hash's block: empty, one byte, a hash's output, a block, and past it.
fn inputs() -> Vec<Vec<u8>> {
    [0usize, 1, 13, 32, 48, 63, 64, 65, 127, 128, 129, 300]
        .into_iter()
        .map(|len| (0..len).map(|i| (i * 7 + len) as u8).collect())
        .collect()
}

/// Each suite's transcript hash gives ring's digests, whole, forked and
/// continued.
#[test]
fn the_hashes_answer_as_rings() {
    for (ours, rings) in pairs() {
        let (ours, rings) = (hash_of(ours), hash_of(rings));
        assert_eq!(ours.output_len(), rings.output_len());
        for input in inputs() {
            assert_eq!(ours.hash(&input).as_ref(), rings.hash(&input).as_ref());
            let (mut o, mut r) = (ours.start(), rings.start());
            o.update(&input);
            r.update(&input);
            assert_eq!(o.fork().finish().as_ref(), r.fork_finish().as_ref());
            o.update(b"more");
            r.update(b"more");
            assert_eq!(o.finish().as_ref(), r.finish().as_ref());
        }
    }
}

/// Each TLS 1.3 suite's HKDF gives ring's answers: extraction from a
/// secret and from zeros, with no salt, an empty one or another, expansion
/// to a block and to lengths from one byte to the limit of 255 blocks,
/// expansion from a given key, and the HMAC the Finished messages use.
#[test]
fn the_tls13_key_schedules_answer_as_rings() {
    let mut checked = 0;
    for (ours, rings) in pairs() {
        let (SupportedCipherSuite::Tls13(ours), SupportedCipherSuite::Tls13(rings)) = (ours, rings)
        else {
            continue;
        };
        let name = ours.common.suite;
        let (o, r) = (ours.hkdf_provider, rings.hkdf_provider);
        let inputs = inputs();
        let mut salts: Vec<Option<&[u8]>> = vec![None];
        salts.extend(inputs.iter().map(|salt| Some(&salt[..])));
        for salt in salts {
            let (oz, rz) = (o.extract_from_zero_ikm(salt), r.extract_from_zero_ikm(salt));
            assert_eq!(oz.hash_len(), rz.hash_len(), "{name:?}");
            assert_eq!(
                oz.expand_block(&[b"zero"]).as_ref(),
                rz.expand_block(&[b"zero"]).as_ref(),
                "{name:?}"
            );
            for secret in &inputs {
                let (oe, re) = (
                    o.extract_from_secret(salt, secret),
                    r.extract_from_secret(salt, secret),
                );
                let info: [&[u8]; 3] = [b"tls13 ", secret, b"c hs traffic"];
                assert_eq!(
                    oe.expand_block(&info).as_ref(),
                    re.expand_block(&info).as_ref(),
                    "{name:?}"
                );
                for len in [1, 12, 16, 32, 48, 100, oe.hash_len() * 255] {
                    let (mut ob, mut rb) = (vec![0; len], vec![0; len]);
                    oe.expand_slice(&info, &mut ob).expect("ours");
                    re.expand_slice(&info, &mut rb).expect("ring's");
                    assert_eq!(ob, rb, "{name:?}, {len} bytes");
                }
            }
        }
        for key in inputs.iter().filter(|key| key.len() <= OkmBlock::MAX_LEN) {
            let okm = OkmBlock::new(key);
            assert_eq!(
                o.expander_for_okm(&okm).expand_block(&[b"key"]).as_ref(),
                r.expander_for_okm(&okm).expand_block(&[b"key"]).as_ref(),
                "{name:?}"
            );
            for message in &inputs {
                assert_eq!(
                    o.hmac_sign(&okm, message).as_ref(),
                    r.hmac_sign(&okm, message).as_ref(),
                    "{name:?}"
                );
            }
        }
        checked += 1;
    }
    assert_eq!(checked, 3, "every TLS 1.3 suite");
}

/// Each TLS 1.2 suite's PRF gives ring's output, for the master secret's
/// 48 bytes, a key block's and longer.  No two bytes of a seed are alike,
/// so a seed taken with its parts out of order, the two randoms swapped
/// say, gives another answer.
#[test]
fn the_tls12_prfs_answer_as_rings() {
    let mut checked = 0;
    for (ours, rings) in pairs() {
        let (SupportedCipherSuite::Tls12(ours), SupportedCipherSuite::Tls12(rings)) = (ours, rings)
        else {
            continue;
        };
        let name = ours.common.suite;
        for secret in inputs() {
            for (label, seed_len) in [
                (&b"master secret"[..], 64),
                (b"key expansion", 64),
                (b"client finished", 32),
                (b"extended master secret", 48),
            ] {
                let seed: Vec<u8> = (0..seed_len).map(|i| (i * 5 + seed_len) as u8).collect();
                for len in [12, 48, 88, 104, 300] {
                    let (mut o, mut r) = (vec![0; len], vec![0; len]);
                    ours.prf_provider.for_secret(&mut o, &secret, label, &seed);
                    rings.prf_provider.for_secret(&mut r, &secret, label, &seed);
                    assert_eq!(o, r, "{name:?}, {len} bytes");
                }
            }
        }
        checked += 1;
    }
    assert_eq!(checked, 6, "every TLS 1.2 suite");
}

/// The sequence numbers records are sealed at: the first two, the last
/// before AES-GCM's confidentiality limit, and the last a connection can
/// reach.
const SEQS: [u64; 4] = [0, 1, (1 << 24) - 1, u64::MAX];

/// A 32-byte traffic key, the one length rustls lets a caller build.
const KEY: [u8; 32] = [
    0x92, 0x4e, 0x0b, 0xd7, 0x63, 0x18, 0xa5, 0xfc, 0x31, 0x86, 0x5d, 0xe2, 0x0f, 0xb4, 0x79, 0x2a,
    0xc8, 0x55, 0x14, 0xef, 0x3a, 0x97, 0x60, 0x0d, 0xbb, 0x26, 0xd1, 0x48, 0x83, 0xfe, 0x1c, 0x6f,
];

/// Twelve bytes of key block after the keys: a TLS 1.3 or ChaCha20-Poly1305
/// IV, or an AES-GCM salt and explicit-nonce seed.
const IV: [u8; 12] = [
    0x5b, 0xe0, 0x27, 0x9c, 0x44, 0xf1, 0x0a, 0xb3, 0x6d, 0x18, 0xc5, 0x72,
];

/// Seal `plaintext` as a record of `typ` at `seq`.
fn seal(
    encrypter: &mut dyn MessageEncrypter,
    seq: u64,
    typ: ContentType,
    plaintext: &[u8],
) -> (ContentType, ProtocolVersion, Vec<u8>) {
    let sealed = encrypter
        .encrypt(
            OutboundPlainMessage {
                typ,
                version: ProtocolVersion::TLSv1_2,
                payload: OutboundChunks::Single(plaintext),
            },
            seq,
        )
        .expect("sealed");
    (sealed.typ, sealed.version, sealed.payload.as_ref().to_vec())
}

/// Open a record sealed by [`seal`].
fn open(
    decrypter: &mut dyn MessageDecrypter,
    seq: u64,
    (typ, version, mut body): (ContentType, ProtocolVersion, Vec<u8>),
) -> (ContentType, ProtocolVersion, Vec<u8>) {
    let plain = decrypter
        .decrypt(InboundOpaqueMessage::new(typ, version, &mut body), seq)
        .expect("opened");
    (plain.typ, plain.version, plain.payload.to_vec())
}

/// Records sealed by this crate's AEADs are ring's records, byte for byte,
/// and each opens the other's.  Only the AEADs with 32-byte keys can be
/// keyed from outside rustls; AES-128-GCM meets ring's in the handshakes
/// below.
#[test]
fn records_are_rings_byte_for_byte() {
    let long = vec![0xc3; 16_384];
    let messages: [&[u8]; 3] = [b"", b"a record", &long];
    let mut checked = 0;
    for (ours, rings) in pairs() {
        let name = ours.suite();
        let ((mut oe, mut od), (mut re, mut rd)) = match (ours, rings) {
            (SupportedCipherSuite::Tls13(o), SupportedCipherSuite::Tls13(r))
                if o.aead_alg.key_len() == KEY.len() =>
            {
                let keyed = |aead: &dyn Tls13AeadAlgorithm| {
                    (
                        aead.encrypter(AeadKey::from(KEY), Iv::from(IV)),
                        aead.decrypter(AeadKey::from(KEY), Iv::from(IV)),
                    )
                };
                (keyed(o.aead_alg), keyed(r.aead_alg))
            }
            (SupportedCipherSuite::Tls12(o), SupportedCipherSuite::Tls12(r))
                if o.aead_alg.key_block_shape().enc_key_len == KEY.len() =>
            {
                let keyed = |aead: &dyn Tls12AeadAlgorithm| {
                    let shape = aead.key_block_shape();
                    let (iv, extra) = IV.split_at(shape.fixed_iv_len);
                    (
                        aead.encrypter(AeadKey::from(KEY), iv, &extra[..shape.explicit_nonce_len]),
                        aead.decrypter(AeadKey::from(KEY), iv),
                    )
                };
                (keyed(o.aead_alg), keyed(r.aead_alg))
            }
            _ => continue,
        };
        for seq in SEQS {
            for typ in [ContentType::ApplicationData, ContentType::Handshake] {
                for plaintext in messages {
                    let theirs = seal(re.as_mut(), seq, typ, plaintext);
                    let mine = seal(oe.as_mut(), seq, typ, plaintext);
                    assert_eq!(mine, theirs, "{name:?} at {seq}");
                    let opened_by_ring = open(rd.as_mut(), seq, mine);
                    let opened_here = open(od.as_mut(), seq, theirs);
                    assert_eq!(opened_by_ring, opened_here, "{name:?} at {seq}");
                    assert_eq!(opened_here.2, plaintext, "{name:?} at {seq}");
                }
            }
        }
        checked += 1;
    }
    assert_eq!(checked, 6, "two TLS 1.3 and four TLS 1.2 suites");
}

/// The P-256 server certificate the ECDSA and TLS 1.3 handshakes use:
/// self-signed for `localhost`, valid from 2026 to 9999, made once with
/// Go 1.26.2's `crypto/x509` for these tests.
const P256_CERT: &str = "\
    3082018b30820130a003020102020101300a06082a8648ce3d04030230273125\
    30230603550403131c6463726f786964652d746c7363727970746f2074657374\
    20503235363020170d3236303130313030303030305a180f3939393931323331\
    3233353935395a3027312530230603550403131c6463726f786964652d746c73\
    63727970746f207465737420503235363059301306072a8648ce3d020106082a\
    8648ce3d030107034200048906089259a44192a029477117b3dac5d142059a7e\
    39acd172143cf3db9a710f109ca52ad1203cf22f4cff10adbbdbdff10962e551\
    b12d03684ed5adea1b7762a34b3049300e0603551d0f0101ff04040302078030\
    130603551d25040c300a06082b06010505070301300c0603551d130101ff0402\
    300030140603551d11040d300b82096c6f63616c686f7374300a06082a8648ce\
    3d0403020349003046022100af5fad70b55d476e25af5234969c03d0dea48f62\
    6cda45b1c1a55dfe6503afd302210099190288504f5f42c6d989ba7a92540dab\
    d3c171a4775957d51d8ed3f5f942bc";

/// [`P256_CERT`]'s key, in PKCS#8.  A test key, made for these tests
/// alone.
const P256_KEY: &str = "\
    308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02\
    01010420a9868ed882e56ef01d5ce5f867e19593cc5316442917c9e07010bc34\
    166428d4a144034200048906089259a44192a029477117b3dac5d142059a7e39\
    acd172143cf3db9a710f109ca52ad1203cf22f4cff10adbbdbdff10962e551b1\
    2d03684ed5adea1b7762";

/// The RSA-2048 server certificate the ECDHE-RSA handshakes use, made as
/// [`P256_CERT`] was.
const RSA2048_CERT: &str = "\
    3082031c30820204a003020102020102300d06092a864886f70d01010b050030\
    2a312830260603550403131f6463726f786964652d746c7363727970746f2074\
    65737420525341323034383020170d3236303130313030303030305a180f3939\
    3939313233313233353935395a302a312830260603550403131f6463726f7869\
    64652d746c7363727970746f2074657374205253413230343830820122300d06\
    092a864886f70d01010105000382010f003082010a0282010100b7b8234bf9ad\
    5bb312abcbdd1f1ca7bec6617ca729d87afec32a0b31c42173039c63a5c0b244\
    a112e288bc0440fc18f7ab143c59fac686f9305ee8a65fabf0d22e8a7f0348bd\
    6bce194c764b222133e727da007053d453d380d1e530a8fdba10d774286fe763\
    efa2781d80265cdbcca625ee787a796c0b971c09e4002d3ec53f918e658d20fb\
    7a2ef20a7fc139bc2b46265492a369d078a2418bc40b2ba3449efead2e7bf827\
    294c204e6dcd2489230ff8a962f1684b9e7d45cd0be8035a705636bda9a94cd5\
    13ddbda70bd0f86370cf7921ceee327078b997c9cba7e407dfc6ccca7b6a8336\
    1053a3f896f5b8b875b44ca761c8250577999979039d02a4980f0203010001a3\
    4b3049300e0603551d0f0101ff04040302078030130603551d25040c300a0608\
    2b06010505070301300c0603551d130101ff0402300030140603551d11040d30\
    0b82096c6f63616c686f7374300d06092a864886f70d01010b05000382010100\
    8c7060eba7d740206fd6815ca7e74fc15daa2cb6728f7b2dda86e0e45fbe433d\
    e4eb0d4688b0b7cf8b9597f2c8d8447287938bbe74657e79eb072ae362dce9e8\
    ca624fcfb7046d108e47022f17553257816f9e6358d92dc91cbbc64cda1df3d8\
    8748ceda309aaac1da2c38a92a27a00022abd1d52ff09f0f0db640b4bc8522d9\
    905c4e167e9241834a56795974e56fb7584ffaf8422bf442b99986bedbf8e7e4\
    374ff76ed1aefdc375a8fa009711092bf833ab0b3f68689240e184b15c7a673e\
    a27e025eb09e94a85bf212b3c419ebba045a1e3ea3caa82407a308e5f6b90274\
    51e1b396ef221476bbb94121d79cbc2599889bb9e40bab6819884e427c776ca1";

/// [`RSA2048_CERT`]'s key, in PKCS#8.  A test key, made for these tests
/// alone; ring signs with it, which this crate will not (ADR-0015 T6).
const RSA2048_KEY: &str = "\
    308204be020100300d06092a864886f70d0101010500048204a8308204a40201\
    000282010100b7b8234bf9ad5bb312abcbdd1f1ca7bec6617ca729d87afec32a\
    0b31c42173039c63a5c0b244a112e288bc0440fc18f7ab143c59fac686f9305e\
    e8a65fabf0d22e8a7f0348bd6bce194c764b222133e727da007053d453d380d1\
    e530a8fdba10d774286fe763efa2781d80265cdbcca625ee787a796c0b971c09\
    e4002d3ec53f918e658d20fb7a2ef20a7fc139bc2b46265492a369d078a2418b\
    c40b2ba3449efead2e7bf827294c204e6dcd2489230ff8a962f1684b9e7d45cd\
    0be8035a705636bda9a94cd513ddbda70bd0f86370cf7921ceee327078b997c9\
    cba7e407dfc6ccca7b6a83361053a3f896f5b8b875b44ca761c8250577999979\
    039d02a4980f02030100010282010018df67229c14ea509e25d5732f091eca11\
    eaea336a28e8234c4cdee31d488cb25fc93b36e6c0ffdaf7571d0d53b6f85d0a\
    33b27aaec6e89dc7fcb1715a368463659afe831ffa9fce7157b6bede9f5c2589\
    71ac3ede3a90216c53fe66ce1a3bc7429973f80d28572dc9d144a397a2c7b174\
    2535a3c4833f8bca675464e9bb3bd2454d9ce65c85134829252c3ae0c4ee0089\
    5e0e0c72ee75f097cb0abf528dbb68ff6260ae24d2810356e868d815813ab808\
    cb54f67093af2d04e8e22e8f791dbf2fb4deba3a5e23e60b6cdcd58a73974356\
    7d2922aae7817edba35115e1b0460bd66f3b84083714e5219c45609422c4ffcb\
    ee71bd4d2bd6fc8ba301c914dbe3e102818100d19990501ce2e033b94c1c828e\
    8c2d6c7f292d5b4e335658c5cfd383fcbf72b810f5556de3de302b9dc82aaa10\
    d949d9858c55a72d2d4c9b8ab47514f84c6f8a7572d3c02ce3598cb4feadc4b5\
    5e4f8c24b6597be1666e207ba4e0b6ff81e16134a52186e8fa33cc3d7e821556\
    ad1132bdce8be2377176816b5c1bdde8e93dd902818100e063df1177198cbb2c\
    f8c8c4269611bc47ab5d48d9578424e2fabeedf022421451dada991621d59f9e\
    2252e543b2c4096f3046590e24a7c3f3d2bbf6d497184fccf279ea7a65752e24\
    40cc4fa4cc428d2947c001bb7b358f0e4549ed85ff64e5c35ff1543b558bf755\
    827086c7db00b79ec934f722ec315331d694437a260c270281804dcf0d24c064\
    74c89ecc23755007b7c1243f9c07de32eea60be107eb62838bc9caf9d859f012\
    869d5a78796622d5173639fe8bb980eae51a84d652f492ec8527c84bf551cd18\
    252137fba77473c3ec11e17b142309dce59b076b80c44e7bdfb81f3c02033c2f\
    cdd4cf2b4c8d315d141a5b1df70de679277e09e5eaae698d54990281810084ef\
    65f608e32016bbbbdfe5251efefed64ed583150fddffa460fcc025e585d457f2\
    1a535b634c15b62f8b80bbacaaab142e3b5f031c002ffcc13a0e2f401c6d1a74\
    047a3f6ce01127f52395838267630db3ae32d88953df9e8aba1377b1286b5e65\
    f6a8fa45e217f396c56773fb70df57b8c8222994585c7b482eaa13317b3d0281\
    8100cb97dbc1905c837fb6c70c4eba98a3011cc32de1710a961884fee46e9709\
    3de1961819c891a95e26113035ef8a89ed3037f427ad18abbbd02a0ba19af7c2\
    c3427ae614a388dc3d217c68558ca8bc1b08511fe125b3985a15938ed8afea67\
    edfc87a9858eeeee90a9637434d721ed30bdec6b4ae66e17246717d0c4431d62\
    8465";

/// The server certificate and key for `suite`: RSA for an ECDHE-RSA suite,
/// P-256 for the rest.
fn server_pair(suite: SupportedCipherSuite) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let rsa = match suite {
        SupportedCipherSuite::Tls12(tls12) => tls12.sign.contains(&SignatureScheme::RSA_PSS_SHA256),
        SupportedCipherSuite::Tls13(_) => false,
    };
    let (cert, key) = if rsa {
        (RSA2048_CERT, RSA2048_KEY)
    } else {
        (P256_CERT, P256_KEY)
    };
    (
        CertificateDer::from(unhex(cert)),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(unhex(key))),
    )
}

/// Ring's provider offering `suite` alone and the key exchange groups
/// `groups`.
fn offering(
    suite: SupportedCipherSuite,
    groups: &[&'static dyn SupportedKxGroup],
) -> Arc<CryptoProvider> {
    Arc::new(CryptoProvider {
        cipher_suites: vec![suite],
        kx_groups: groups.to_vec(),
        ..ring::default_provider()
    })
}

/// One end of a handshake: the suite it offers and its key exchange
/// groups.
type End<'a> = (SupportedCipherSuite, &'a [&'static dyn SupportedKxGroup]);

/// A server and a client offering what their ends give, both of the
/// server suite's version, the client trusting the server's certificate
/// and checking it with ring's verifier, and both able to hand out their
/// traffic secrets.
fn configs(server_end: End<'_>, client_end: End<'_>) -> (Arc<ServerConfig>, Arc<ClientConfig>) {
    let (server_suite, server_groups) = server_end;
    let (client_suite, client_groups) = client_end;
    let version = server_suite.version();
    let (cert, key) = server_pair(server_suite);
    let mut server = ServerConfig::builder_with_provider(offering(server_suite, server_groups))
        .with_protocol_versions(&[version])
        .expect("the server's version")
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .expect("the server's key");
    server.enable_secret_extraction = true;

    let mut roots = RootCertStore::empty();
    roots.add(cert).expect("the certificate as a root");
    let verifier = WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(ring::default_provider()),
    )
    .build()
    .expect("the verifier");
    let mut client = ClientConfig::builder_with_provider(offering(client_suite, client_groups))
        .with_protocol_versions(&[version])
        .expect("the client's version")
        .with_webpki_verifier(verifier)
        .with_no_client_auth();
    client.enable_secret_extraction = true;
    (Arc::new(server), Arc::new(client))
}

/// Move every record `from` has to send into `to`, process them as they
/// arrive, and return the application data `to` read from them.  The
/// plaintext is drained as it is processed, since rustls buffers no more
/// than 16 KiB of it unread.
fn deliver<A, B>(from: &mut ConnectionCommon<A>, to: &mut ConnectionCommon<B>) -> Vec<u8> {
    let mut wire = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut wire).expect("the records written");
    }
    let mut rest = wire.as_slice();
    let mut received = Vec::new();
    while !rest.is_empty() {
        to.read_tls(&mut rest).expect("the records read");
        let state = to.process_new_packets().expect("the records processed");
        let mut plaintext = vec![0; state.plaintext_bytes_to_read()];
        std::io::Read::read_exact(&mut to.reader(), &mut plaintext).expect("the plaintext read");
        received.extend_from_slice(&plaintext);
    }
    received
}

/// Send each message from the client and back from the server, checking
/// that each arrives whole.
fn exchange(client: &mut ClientConnection, server: &mut ServerConnection, what: &str) {
    let messages = [
        b"ping".to_vec(),
        (0..16_384).map(|i| i as u8).collect(),
        (0..40_000).map(|i| (i / 7) as u8).collect(),
    ];
    for message in messages {
        client
            .writer()
            .write_all(&message)
            .expect("the client writes");
        assert!(
            deliver(client, server) == message,
            "{what}: the server reads"
        );
        server
            .writer()
            .write_all(&message)
            .expect("the server writes");
        assert!(
            deliver(server, client) == message,
            "{what}: the client reads"
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

/// Run a handshake between `server_suite` and `client_suite`, which share
/// a name, with ring's key exchange groups on both sides, then
/// application data each way, a key update in TLS 1.3 and more data under
/// the new keys, and check that the two ends hand out the same traffic
/// secrets for each direction.
fn handshake(server_suite: SupportedCipherSuite, client_suite: SupportedCipherSuite, what: &str) {
    handshake_between(
        (server_suite, ring::ALL_KX_GROUPS),
        (client_suite, ring::ALL_KX_GROUPS),
        what,
    );
}

/// [`handshake`] between two ends, which may differ in their key exchange
/// groups: the group the two ends agree on, which must be the same at
/// both.
fn handshake_between(server_end: End<'_>, client_end: End<'_>, what: &str) -> NamedGroup {
    let server_suite = server_end.0;
    let name = server_suite.suite();
    let what = format!("{name:?}, {what}");
    let (server_config, client_config) = configs(server_end, client_end);
    let server_name = ServerName::try_from("localhost").expect("the server name");
    let mut client = ClientConnection::new(client_config, server_name).expect("the client");
    let mut server = ServerConnection::new(server_config).expect("the server");
    // One round per client flight: two in either version's full handshake.
    for _ in 0..2 {
        deliver(&mut client, &mut server);
        deliver(&mut server, &mut client);
    }
    assert!(
        !client.is_handshaking() && !server.is_handshaking(),
        "{what}: the handshake completes"
    );
    assert_eq!(
        client.negotiated_cipher_suite().map(|s| s.suite()),
        Some(name),
        "{what}"
    );
    assert_eq!(
        server.protocol_version(),
        Some(server_suite.version().version),
        "{what}"
    );
    let group = |kx: Option<&'static dyn SupportedKxGroup>| kx.map(|kx| kx.name());
    let agreed = group(client.negotiated_key_exchange_group());
    assert_eq!(
        agreed,
        group(server.negotiated_key_exchange_group()),
        "{what}: the key exchange group"
    );
    let agreed = agreed.unwrap_or_else(|| panic!("{what}: no key exchange group"));

    exchange(&mut client, &mut server, &what);
    if server_suite.version().version == ProtocolVersion::TLSv1_3 {
        // The client asks for an update, and the server answers with its
        // own, so both directions change keys.
        client.refresh_traffic_keys().expect("the key update");
        deliver(&mut client, &mut server);
        deliver(&mut server, &mut client);
        exchange(
            &mut client,
            &mut server,
            &format!("{what}, after a key update"),
        );
    }

    let client_secrets = client
        .dangerous_extract_secrets()
        .expect("the client's secrets");
    let server_secrets = server
        .dangerous_extract_secrets()
        .expect("the server's secrets");
    assert_eq!(
        client_secrets.tx.0, server_secrets.rx.0,
        "{what}: the sequence numbers"
    );
    assert_eq!(
        client_secrets.rx.0, server_secrets.tx.0,
        "{what}: the sequence numbers"
    );
    let (client_tx, server_rx) = (named(&client_secrets.tx.1), named(&server_secrets.rx.1));
    assert_eq!(client_tx, server_rx, "{what}: the client's traffic secrets");
    let (client_rx, server_tx) = (named(&client_secrets.rx.1), named(&server_secrets.tx.1));
    assert_eq!(client_rx, server_tx, "{what}: the server's traffic secrets");
    let aead = format!("{name:?}").replace('_', "-").to_uppercase();
    assert!(
        aead.contains(&client_tx.0.to_uppercase()),
        "{what}: secrets named {}",
        client_tx.0
    );
    agreed
}

/// For each of the nine suites, a handshake with application data, and in
/// TLS 1.3 a key update, runs with this crate serving and ring dialing,
/// with ring serving and this crate dialing, and with this crate on both
/// sides.
#[test]
fn each_suite_handshakes_with_rings_both_ways() {
    for (ours, rings) in pairs() {
        handshake(ours, rings, "this crate serving, ring dialing");
        handshake(rings, ours, "ring serving, this crate dialing");
        handshake(ours, ours, "this crate on both sides");
    }
}

/// The default key exchange groups are ring's, in ring's order, and the
/// full list adds P-521 after them.
#[test]
fn the_group_lists_are_rings() {
    let names = |groups: &[&dyn SupportedKxGroup]| {
        groups.iter().map(|group| group.name()).collect::<Vec<_>>()
    };
    let rings = names(ring::ALL_KX_GROUPS);
    assert_eq!(names(dcroxide_tlscrypto::DEFAULT_KX_GROUPS), rings);
    assert_eq!(names(&ring::default_provider().kx_groups), rings);
    assert_eq!(
        names(dcroxide_tlscrypto::ALL_KX_GROUPS),
        [rings, vec![NamedGroup::secp521r1]].concat()
    );
}

/// One of this crate's groups, ring's of the same name, and the
/// Wycheproof file for the group.
type GroupPair = (
    &'static dyn SupportedKxGroup,
    &'static dyn SupportedKxGroup,
    &'static str,
);

/// This crate's three groups that ring has, each beside ring's.
fn group_pairs() -> [GroupPair; 3] {
    use dcroxide_tlscrypto::kx_group as ours;
    use ring::kx_group as rings;
    [
        (ours::X25519, rings::X25519, "x25519_test.json"),
        (
            ours::SECP256R1,
            rings::SECP256R1,
            "ecdh_secp256r1_ecpoint_test.json",
        ),
        (
            ours::SECP384R1,
            rings::SECP384R1,
            "ecdh_secp384r1_ecpoint_test.json",
        ),
    ]
}

/// The public keys of a Wycheproof key exchange file, each labelled by
/// its case.
fn wycheproof_shares(file: &str) -> Vec<(String, Vec<u8>)> {
    let path = format!(
        "{}/tests/data/wycheproof/{file}.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut json = String::new();
    flate2::read::GzDecoder::new(std::fs::File::open(&path).expect("the file"))
        .read_to_string(&mut json)
        .expect("the file decompressed");
    let vectors: serde_json::Value = serde_json::from_str(&json).expect("JSON");
    vectors["testGroups"]
        .as_array()
        .expect("testGroups")
        .iter()
        .flat_map(|group| group["tests"].as_array().expect("tests"))
        .map(|case| {
            (
                format!("{file} tcId {}", case["tcId"]),
                unhex(case["public"].as_str().expect("a public key")),
            )
        })
        .collect()
}

/// Whether `group`, from a fresh key, takes `share`; a refusal must be an
/// invalid key share.
fn takes(group: &dyn SupportedKxGroup, share: &[u8], label: &str) -> bool {
    match group.start().expect("started").complete(share) {
        Ok(_) => true,
        Err(err) => {
            assert_eq!(
                err,
                rustls::Error::PeerMisbehaved(rustls::PeerMisbehaved::InvalidKeyShare),
                "{:?}, {label}",
                group.name()
            );
            false
        }
    }
}

/// Each group takes exactly the shares ring's takes: whether a share is
/// taken depends on the share alone, never on the key drawn, since an
/// X25519 share of small order zeroes every clamped key's secret and a
/// NIST curve's checks read only the share.  Both answers are counted, so
/// a run in which every share went one way fails.
#[test]
fn each_group_takes_the_shares_ring_takes() {
    for (ours, rings, file) in group_pairs() {
        let name = ours.name();
        let mut shares = kx_shares::shares(name);
        shares.extend(wycheproof_shares(file));
        let (mut taken, mut refused) = (0, 0);
        for (label, share) in &shares {
            let verdict = takes(ours, share, label);
            assert_eq!(verdict, takes(rings, share, label), "{name:?}, {label}");
            if verdict {
                taken += 1;
            } else {
                refused += 1;
            }
        }
        assert!(
            taken > 100 && refused > 100,
            "{name:?}: {taken} taken, {refused} refused"
        );
    }
}

/// Each group agrees ring's secret: this crate's exchange completed with
/// ring's key share gives what ring's completed with this crate's gives.
#[test]
fn each_group_agrees_rings_secret() {
    for (ours, rings, _) in group_pairs() {
        for _ in 0..16 {
            let (o, r) = (ours.start().expect("ours"), rings.start().expect("ring's"));
            let (o_pub, r_pub) = (o.pub_key().to_vec(), r.pub_key().to_vec());
            let ours_agreed = o.complete(&r_pub).expect("ours completes");
            let rings_agreed = r.complete(&o_pub).expect("ring's completes");
            assert_eq!(
                ours_agreed.secret_bytes(),
                rings_agreed.secret_bytes(),
                "{:?}",
                ours.name()
            );
        }
    }
}

/// A handshake in each TLS version negotiates each group with this
/// crate's on one side and ring's on the other, both ways, and P-521 with
/// this crate's on both sides, the suites ring's throughout.
#[test]
fn each_group_handshakes_with_rings_both_ways() {
    let suites = [
        ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
        ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    ];
    for suite in suites {
        for (ours, rings, _) in group_pairs() {
            let name = ours.name();
            let (ours, rings) = (&[ours][..], &[rings][..]);
            let agreed =
                handshake_between((suite, ours), (suite, rings), "this crate's group serving");
            assert_eq!(agreed, name);
            let agreed =
                handshake_between((suite, rings), (suite, ours), "this crate's group dialing");
            assert_eq!(agreed, name);
        }
        let p521 = &[dcroxide_tlscrypto::kx_group::SECP521R1][..];
        let agreed = handshake_between((suite, p521), (suite, p521), "P-521 on both sides");
        assert_eq!(agreed, NamedGroup::secp521r1);
    }
}
