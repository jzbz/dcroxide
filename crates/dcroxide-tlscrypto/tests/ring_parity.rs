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
//! For the signing keys: each key the provider signs with loads with
//! ring's public key, algorithm and choice of scheme, ring verifies its
//! signatures and the provider's verifier-to-be verifies ring's, two of
//! its ECDSA signatures of one message differ, as two of ring's do, and
//! Ed25519 signatures are ring's byte for byte; every key of `key_corpus`
//! ring loads, under its PEM label, the provider loads as the same key,
//! but an RSA key, which it refuses (ADR-0015, T6); and a handshake in
//! each TLS version with ring's client completes against a server whose
//! key and certificate the provider loaded and signed, on P-256, P-384 and
//! Ed25519.  P-521, which ring cannot load or verify, has its signatures
//! held to `ecdsa`'s verifier, here and in the node's `tests/rpclisten.rs`
//! over a real handshake, and its loading to Go
//! (`tests/go_differential.rs`).
//!
//! The ring half of this file goes at the switch, with the dev-dependency
//! that selects ring.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

mod key_corpus;
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

/// The server certificate and key for `suite`: RSA for an ECDHE-RSA suite,
/// P-256 for the rest.
fn server_pair(suite: SupportedCipherSuite) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let rsa = match suite {
        SupportedCipherSuite::Tls12(tls12) => tls12.sign.contains(&SignatureScheme::RSA_PSS_SHA256),
        SupportedCipherSuite::Tls13(_) => false,
    };
    let (cert, key) = if rsa {
        (key_corpus::RSA2048_CERT, key_corpus::RSA2048_KEY)
    } else {
        (key_corpus::P256_CERT, key_corpus::P256_KEY)
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

/// Every signature scheme a TLS peer may offer for the keys here.
const SCHEMES: [SignatureScheme; 6] = [
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::ED25519,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA256,
];

/// The public key a SubjectPublicKeyInfo's BIT STRING holds.
fn public_key_bits(spki: &[u8]) -> Vec<u8> {
    key_corpus::content(key_corpus::elements(spki)[1])[1..].to_vec()
}

/// The messages each key signs here: empty, short, a SHA-512 block, and
/// the length of a TLS 1.3 CertificateVerify's content.
fn messages() -> [Vec<u8>; 4] {
    [
        Vec::new(),
        b"m".to_vec(),
        (0..128).map(|i| i as u8).collect(),
        (0..130).map(|i| (i * 7) as u8).collect(),
    ]
}

/// Whether `signature` is a DER signature of `message` by `public` under
/// the ECDSA `scheme`, by `ecdsa`'s verifier, on which the provider's own
/// will run.
fn ecdsa_verifies(
    scheme: SignatureScheme,
    public: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    use p256::ecdsa::signature::Verifier;
    match scheme {
        SignatureScheme::ECDSA_NISTP256_SHA256 => {
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public).expect("a point");
            p256::ecdsa::DerSignature::from_bytes(signature)
                .is_ok_and(|signature| key.verify(message, &signature).is_ok())
        }
        SignatureScheme::ECDSA_NISTP384_SHA384 => {
            let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(public).expect("a point");
            p384::ecdsa::DerSignature::from_bytes(signature)
                .is_ok_and(|signature| key.verify(message, &signature).is_ok())
        }
        SignatureScheme::ECDSA_NISTP521_SHA512 => {
            let key = p521::ecdsa::VerifyingKey::from_sec1_bytes(public).expect("a point");
            p521::ecdsa::DerSignature::from_bytes(signature)
                .is_ok_and(|signature| key.verify(message, &signature).is_ok())
        }
        other => panic!("not an ECDSA scheme: {other:?}"),
    }
}

/// Each key the provider signs with loads as ring's loader loads it from
/// the same PKCS#8, with the same public key, algorithm and choice of
/// scheme from each list a peer might offer; ring's verification
/// algorithm for the scheme verifies the provider's signatures, `ecdsa`'s
/// verifier, on which the provider's own will run, verifies ring's ECDSA
/// signatures, and the two Ed25519 signatures are equal.  Two of the
/// provider's ECDSA signatures of one message, each hedged with a fresh
/// draw, differ as two of ring's do, and both verify, the P-521 key's
/// among them, which ring cannot load; two Ed25519 signatures of one
/// message are the same.
#[test]
fn each_signing_key_signs_as_rings() {
    use rustls::pki_types::PrivatePkcs8KeyDer;

    let algorithms = ring::default_provider().signature_verification_algorithms;
    let scheme = |key: &dyn rustls::sign::SigningKey, offered: &[SignatureScheme]| {
        key.choose_scheme(offered).map(|signer| signer.scheme())
    };
    let twice = |key: &dyn rustls::sign::SigningKey, scheme: SignatureScheme, message: &[u8]| {
        let signer = key.choose_scheme(&[scheme]).expect("the scheme");
        [
            signer.sign(message).expect("signed"),
            signer.sign(message).expect("signed"),
        ]
    };
    let (mut signed, mut ring_refused) = (Vec::new(), Vec::new());
    for base in key_corpus::base_keys() {
        let name = base.name;
        let der = || PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(base.pkcs8.clone()));
        let ours = dcroxide_tlscrypto::sign::KEY_PROVIDER
            .load_private_key(der())
            .expect("the provider loads its own key");
        let spki = ours.public_key().expect("a public key");
        assert_eq!(spki.as_ref(), &base.spki[..], "{name}");
        let public = public_key_bits(spki.as_ref());
        let chosen = scheme(&*ours, &SCHEMES).expect("a scheme");
        let message = &messages()[3];
        let [first, second] = twice(&*ours, chosen, message);
        if chosen == SignatureScheme::ED25519 {
            assert_eq!(first, second, "{name}: Ed25519 signs deterministically");
        } else {
            assert_ne!(first, second, "{name}: each signature hedged afresh");
            for signature in [&first, &second] {
                assert!(
                    ecdsa_verifies(chosen, &public, message, signature),
                    "{name}"
                );
            }
        }
        let rings = ring::default_provider()
            .key_provider
            .load_private_key(der());
        if name == "P-521" {
            assert!(rings.is_err(), "ring has no P-521 signer");
            ring_refused.push(name);
            continue;
        }
        let rings = rings.expect("ring loads the key");
        assert_eq!(
            rings.public_key().map(|spki| spki.as_ref().to_vec()),
            Some(base.spki.clone()),
            "{name}"
        );
        assert_eq!(ours.algorithm(), rings.algorithm(), "{name}");
        let mut lists: Vec<Vec<SignatureScheme>> = vec![SCHEMES.to_vec(), Vec::new()];
        lists.extend(SCHEMES.iter().map(|scheme| vec![*scheme]));
        for offered in &lists {
            assert_eq!(
                scheme(&*ours, offered),
                scheme(&*rings, offered),
                "{name}, {offered:?}"
            );
        }
        let [ring_first, ring_second] = twice(&*rings, chosen, message);
        assert_eq!(
            ring_first == ring_second,
            first == second,
            "{name}: ring's two signatures of one message"
        );
        let verify = algorithms
            .mapping
            .iter()
            .find(|(scheme, _)| *scheme == chosen)
            .map(|(_, algorithms)| algorithms[0])
            .expect("ring verifies the scheme");
        for message in messages() {
            let sign = |key: &dyn rustls::sign::SigningKey| {
                key.choose_scheme(&[chosen])
                    .expect("the scheme")
                    .sign(&message)
                    .expect("signed")
            };
            let (our_signature, ring_signature) = (sign(&*ours), sign(&*rings));
            assert!(
                verify
                    .verify_signature(&public, &message, &our_signature)
                    .is_ok(),
                "{name}: ring verifies the provider's signature"
            );
            let ring_verified = match chosen {
                SignatureScheme::ED25519 => our_signature == ring_signature,
                _ => ecdsa_verifies(chosen, &public, &message, &ring_signature),
            };
            assert!(
                ring_verified,
                "{name}: ring's signature, {} bytes signed",
                message.len()
            );
        }
        signed.push(name);
    }
    assert_eq!(
        (signed, ring_refused),
        (vec!["P-256 (Go's)", "P-384", "Ed25519"], vec!["P-521"]),
        "the keys signed both ways, and the one ring cannot load"
    );
}

/// The keys of the corpus ring loads and Go refuses, as the provider does:
/// SEC 1 keys that name no curve.  rustls hands ring a SEC 1 key wrapped
/// in a PKCS#8 prefix that names P-256, then one that names P-384
/// (`rustls-0.23.46/src/crypto/ring/sign.rs:228`, `:245-286`), so the
/// curve comes from the prefix, where Go finds none
/// (`crypto/x509/sec1.go:102-110`).  ring needs the public key besides,
/// so the same keys without one load in neither.
const RING_ONLY: &[&str] = &[
    "P-256 (Go's), SEC 1, no curve",
    "P-256, SEC 1, no curve",
    "P-384, SEC 1, no curve",
];

/// Every key of the corpus that ring's loader loads, handed to it as the
/// node's PEM reader hands it today (by label: `PRIVATE KEY` as PKCS#8,
/// `EC PRIVATE KEY` as SEC 1, `RSA PRIVATE KEY` as PKCS#1, other labels not
/// at all), the provider loads too, as the same key, matching the
/// certificate of the key it was mutated from; but an RSA key, which the
/// provider refuses with its own text (ADR-0015, T6), and the keys of
/// [`RING_ONLY`], which it refuses with Go's.  Otherwise the provider
/// loads more than ring does, as Go does, which `tests/go_differential.rs`
/// holds it to.
#[test]
fn the_provider_loads_every_key_ring_loads() {
    use rustls::pki_types::{PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};

    let (mut loaded, mut rsa, mut ring_only) = (0, 0, Vec::new());
    for case in key_corpus::cases() {
        let label = &case.label;
        let der = match case.pem_label {
            "PRIVATE KEY" => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(case.der.clone())),
            "EC PRIVATE KEY" => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(case.der.clone())),
            "RSA PRIVATE KEY" => PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(case.der.clone())),
            _ => continue,
        };
        let Ok(rings) = ring::default_provider()
            .key_provider
            .load_private_key(der.clone_key())
        else {
            continue;
        };
        match dcroxide_tlscrypto::sign::KEY_PROVIDER.load_private_key(der) {
            Ok(ours) => {
                loaded += 1;
                assert_eq!(
                    ours.public_key().map(|spki| spki.as_ref().to_vec()),
                    rings.public_key().map(|spki| spki.as_ref().to_vec()),
                    "{label}"
                );
                let certified =
                    rustls::sign::CertifiedKey::new(vec![CertificateDer::from(case.cert)], ours);
                assert!(certified.keys_match().is_ok(), "{label}");
            }
            Err(rustls::Error::General(text))
                if text == dcroxide_tlscrypto::sign::RSA_KEY_REFUSED =>
            {
                assert_eq!(
                    rings.algorithm(),
                    rustls::SignatureAlgorithm::RSA,
                    "{label}"
                );
                rsa += 1;
            }
            Err(rustls::Error::General(text)) => {
                assert_eq!(text, "tls: failed to parse private key", "{label}");
                ring_only.push(label.clone());
            }
            Err(other) => panic!("{label}: {other:?}"),
        }
    }
    assert_eq!(ring_only, RING_ONLY, "the keys ring loads and Go refuses");
    assert!(loaded >= 17 && rsa >= 3, "{loaded} loaded, {rsa} RSA");
}

/// A self-signed certificate for `key`, with `P256_CERT`'s names, validity
/// and extensions, signed by `key` with `scheme` under the signature
/// algorithm `algorithm`.
fn self_signed(
    key: &dyn rustls::sign::SigningKey,
    scheme: SignatureScheme,
    algorithm: &[u8],
) -> CertificateDer<'static> {
    let template = unhex(key_corpus::P256_CERT);
    let tbs = key_corpus::elements(key_corpus::elements(&template)[0]);
    assert_eq!(tbs.len(), 8, "version to extensions");
    let algorithm = key_corpus::seq(&[&key_corpus::tlv(0x06, algorithm)]);
    let spki = key.public_key().expect("a public key");
    let tbs = key_corpus::seq(&[
        tbs[0],
        tbs[1],
        &algorithm,
        tbs[3],
        tbs[4],
        tbs[5],
        spki.as_ref(),
        tbs[7],
    ]);
    let signature = key
        .choose_scheme(&[scheme])
        .expect("the scheme")
        .sign(&tbs)
        .expect("signed");
    CertificateDer::from(key_corpus::seq(&[
        &tbs,
        &algorithm,
        &key_corpus::tlv(0x03, &[&[0][..], &signature].concat()),
    ]))
}

/// A handshake in each TLS version, and application data each way,
/// between ring's client, which verifies the server's certificate and its
/// handshake signature with ring, and a server on ring's suites and key
/// exchange whose key and certificate the provider loaded and signed: on
/// the Go-made P-256 key, the P-384 key and the Ed25519 key.
#[test]
fn handshakes_complete_on_the_providers_keys() {
    use rustls::pki_types::PrivatePkcs8KeyDer;

    let mut completed = Vec::new();
    for base in key_corpus::base_keys() {
        let (scheme, algorithm): (_, &[u8]) = match base.name {
            "P-256 (Go's)" => (
                SignatureScheme::ECDSA_NISTP256_SHA256,
                &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02],
            ),
            "P-384" => (
                SignatureScheme::ECDSA_NISTP384_SHA384,
                &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03],
            ),
            "Ed25519" => (SignatureScheme::ED25519, &[0x2b, 0x65, 0x70]),
            _ => continue,
        };
        let der = || PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(base.pkcs8.clone()));
        let key = dcroxide_tlscrypto::sign::KEY_PROVIDER
            .load_private_key(der())
            .expect("the key");
        let cert = self_signed(&*key, scheme, algorithm);
        for suite in [
            ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
            ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        ] {
            let what = format!("{}, {:?}", base.name, suite.suite());
            let version = suite.version();
            let server_provider = Arc::new(CryptoProvider {
                cipher_suites: vec![suite],
                key_provider: dcroxide_tlscrypto::sign::KEY_PROVIDER,
                ..ring::default_provider()
            });
            let server = ServerConfig::builder_with_provider(server_provider)
                .with_protocol_versions(&[version])
                .expect("the server's version")
                .with_no_client_auth()
                .with_single_cert(vec![cert.clone()], der())
                .expect("the provider's key and its certificate");
            let mut roots = RootCertStore::empty();
            roots.add(cert.clone()).expect("the certificate as a root");
            let verifier = WebPkiServerVerifier::builder_with_provider(
                Arc::new(roots),
                Arc::new(ring::default_provider()),
            )
            .build()
            .expect("the verifier");
            let client = ClientConfig::builder_with_provider(offering(suite, ring::ALL_KX_GROUPS))
                .with_protocol_versions(&[version])
                .expect("the client's version")
                .with_webpki_verifier(verifier)
                .with_no_client_auth();
            let server_name = ServerName::try_from("localhost").expect("the server name");
            let mut client =
                ClientConnection::new(Arc::new(client), server_name).expect("the client");
            let mut server = ServerConnection::new(Arc::new(server)).expect("the server");
            for _ in 0..2 {
                deliver(&mut client, &mut server);
                deliver(&mut server, &mut client);
            }
            assert!(
                !client.is_handshaking() && !server.is_handshaking(),
                "{what}: the handshake completes"
            );
            exchange(&mut client, &mut server, &what);
            completed.push(what);
        }
    }
    assert_eq!(
        completed.len(),
        6,
        "three keys in each TLS version: {completed:#?}"
    );
}
