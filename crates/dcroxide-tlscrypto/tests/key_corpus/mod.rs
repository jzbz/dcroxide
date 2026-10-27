// SPDX-License-Identifier: ISC
//! The private keys `tests/go_differential.rs` and `tests/ring_parity.rs`
//! load, valid and not, so that the provider's key loading can be held to
//! Go's `tls.X509KeyPair` and to ring's loader key by key (ADR-0015, step
//! 1), and the test keys and certificates both use.
//!
//! The corpus is a set of base keys, each written in the forms Go reads
//! and then mutated in each rule of Go's `parsePrivateKey` that
//! `src/keys.rs` ports, one rule at a time: the structure's versions; the
//! scalar's padding and its value at the edges of `[1, n)`; the curve
//! named inside the SEC 1 key, in PKCS#8's parameters, in both or in
//! neither, and naming the wrong curve, P-224, an unknown one or a
//! malformed identifier; a `[0]` that holds no OBJECT IDENTIFIER, a
//! primitive or empty one, one whose length is wrong, and a `[1]` whose BIT
//! STRING is badly padded, holds another type, or a wrong public key;
//! PKCS#8's parameters, algorithms and attributes; elements and bytes that
//! do not read inside each structure and after it; PKCS#1 with a negative
//! version, without its CRT values and with additional primes; Ed25519
//! seeds of other lengths and X25519 keys; and each key's canonical forms
//! under PEM labels that differ from their content.  The bases are the
//! Go-made P-256 key below, keys on P-256, P-384 and P-521 with scalars
//! fixed from a seed (the P-256 and P-521 ones with a leading zero byte),
//! the P-224 key whose scalar is 1, so that its public key is the
//! generator, an Ed25519 key, and the RSA key below.  Every run makes the
//! same keys.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::{Scalar, clamp_integer};
use dcroxide_testutil::{SplitMix64, unhex};
use p256::elliptic_curve::sec1::ToSec1Point;
use sha2::{Digest, Sha512};

/// One key of the corpus.
pub struct Case {
    /// What it is, for messages: the base key and the mutation.
    pub label: String,
    /// The key's DER.
    pub der: Vec<u8>,
    /// The label of the PEM block it is given to Go under.
    pub pem_label: &'static str,
    /// A certificate for the base key it was mutated from: a key that
    /// reads as that key matches it.
    pub cert: Vec<u8>,
}

/// A key the provider signs with, as its tests use it.
pub struct BaseKey {
    /// The key's name, for messages.
    pub name: &'static str,
    /// The key in PKCS#8, as Go's `x509.MarshalPKCS8PrivateKey` writes it.
    pub pkcs8: Vec<u8>,
    /// Its SubjectPublicKeyInfo.
    pub spki: Vec<u8>,
}

/// A DER element: `tag`, its length in the fewest bytes, and `content`.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
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

/// A SEQUENCE of `parts`.
pub fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

/// The elements of a DER element's content, each whole, header included;
/// short- and long-form lengths of up to two bytes, as the fixtures here
/// have.
pub fn elements(element: &[u8]) -> Vec<&[u8]> {
    let mut rest = content(element);
    let mut out = Vec::new();
    while !rest.is_empty() {
        let len = header_len(rest) + content(rest).len();
        out.push(&rest[..len]);
        rest = &rest[len..];
    }
    out
}

/// A DER element's content.
pub fn content(element: &[u8]) -> &[u8] {
    let (start, len) = match element[1] {
        len @ 0..=0x7f => (2, usize::from(len)),
        0x81 => (3, usize::from(element[2])),
        0x82 => (4, usize::from(element[2]) << 8 | usize::from(element[3])),
        other => panic!("a length form the fixtures do not use: {other:#04x}"),
    };
    &element[start..start + len]
}

/// The length of a DER element's header.
fn header_len(element: &[u8]) -> usize {
    match element[1] {
        0..=0x7f => 2,
        0x81 => 3,
        _ => 4,
    }
}

/// A certificate for `spki` that Go's `x509.ParseCertificate` and
/// webpki read: version 3, no extensions, and a signature that is
/// well formed and signs nothing, since neither `tls.X509KeyPair` nor
/// `CertifiedKey::keys_match` checks one.
pub fn certificate(spki: &[u8]) -> Vec<u8> {
    let algorithm = seq(&[&tlv(0x06, ECDSA_WITH_SHA256)]);
    let name = seq(&[&tlv(
        0x31,
        &seq(&[
            &tlv(0x06, &[0x55, 0x04, 0x03]),
            &tlv(0x0c, b"dcroxide-tlscrypto test"),
        ]),
    )]);
    let validity = seq(&[&tlv(0x17, b"260101000000Z"), &tlv(0x18, b"99991231235959Z")]);
    let tbs = seq(&[
        &tlv(0xa0, &tlv(0x02, &[2])),
        &tlv(0x02, &[1]),
        &algorithm,
        &name,
        &validity,
        &name,
        spki,
    ]);
    let signature = seq(&[&tlv(0x02, &[1]), &tlv(0x02, &[1])]);
    seq(&[
        &tbs,
        &algorithm,
        &tlv(0x03, &[&[0][..], &signature].concat()),
    ])
}

/// `ecdsa-with-SHA256`, 1.2.840.10045.4.3.2.
const ECDSA_WITH_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
/// `rsaEncryption`, 1.2.840.113549.1.1.1.
const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
/// `id-ecPublicKey`, 1.2.840.10045.2.1.
const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// `id-ecDH`, 1.3.132.1.12, an EC algorithm Go does not read.
const EC_DH: &[u8] = &[0x2b, 0x81, 0x04, 0x01, 0x0c];
/// `id-Ed25519`, 1.3.101.112.
const ED25519: &[u8] = &[0x2b, 0x65, 0x70];
/// `id-Ed448`, 1.3.101.113.
const ED448: &[u8] = &[0x2b, 0x65, 0x71];
/// `id-X25519`, 1.3.101.110.
const X25519: &[u8] = &[0x2b, 0x65, 0x6e];
/// `secp256k1`, 1.3.132.0.10, a curve Go does not read.
const SECP256K1: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x0a];

/// The four NIST curves Go reads: name, OID and order.
const CURVES: [(&str, &[u8], &str); 4] = [
    (
        "P-224",
        &[0x2b, 0x81, 0x04, 0x00, 0x21],
        "ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d",
    ),
    (
        "P-256",
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    ),
    (
        "P-384",
        &[0x2b, 0x81, 0x04, 0x00, 0x22],
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf\
         581a0db248b0a77aecec196accc52973",
    ),
    (
        "P-521",
        &[0x2b, 0x81, 0x04, 0x00, 0x23],
        "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
         fffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138\
         6409",
    ),
];

/// P-224's generator, the public key of the scalar 1
/// (`crypto/elliptic/nistec.go:25-26`).
const P224_GENERATOR: &str = "04b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21\
                              bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34";

/// The OID of the curve named `name`.
fn curve_oid(name: &str) -> &'static [u8] {
    CURVES
        .iter()
        .find(|(curve, _, _)| *curve == name)
        .map(|(_, oid, _)| *oid)
        .expect("a curve of the table")
}

/// A base key on a NIST curve.
struct EcBase {
    /// Its name, for labels.
    name: &'static str,
    /// Its curve's name.
    curve: &'static str,
    /// Its scalar at the field's length.
    scalar: Vec<u8>,
    /// Its public key, uncompressed.
    public: Vec<u8>,
    /// A certificate for it.
    cert: Vec<u8>,
}

/// An EC SubjectPublicKeyInfo on `curve` for `public`.
fn ec_spki(curve: &str, public: &[u8]) -> Vec<u8> {
    seq(&[
        &seq(&[&tlv(0x06, EC_PUBLIC_KEY), &tlv(0x06, curve_oid(curve))]),
        &tlv(0x03, &[&[0][..], public].concat()),
    ])
}

/// An EC base key from its scalar, its public key from the curve crate.
fn ec_base(name: &'static str, curve: &'static str, scalar: Vec<u8>) -> EcBase {
    let public = match curve {
        "P-256" => p256::SecretKey::from_slice(&scalar)
            .expect("a scalar")
            .public_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec(),
        "P-384" => p384::SecretKey::from_slice(&scalar)
            .expect("a scalar")
            .public_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec(),
        "P-521" => p521::SecretKey::from_slice(&scalar)
            .expect("a scalar")
            .public_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec(),
        _ => unhex(P224_GENERATOR),
    };
    let cert = certificate(&ec_spki(curve, &public));
    EcBase {
        name,
        curve,
        scalar,
        public,
        cert,
    }
}

/// The base keys on NIST curves.
fn ec_bases() -> Vec<EcBase> {
    let mut rng = SplitMix64(0x7c3_2026_1026);
    let mut drawn = |len: usize, first: u8| {
        let mut scalar = vec![0; len];
        rng.fill(&mut scalar);
        scalar[0] = first;
        scalar
    };
    let go_der = unhex(P256_KEY);
    let go_key = elements(&go_der);
    let go_inner = elements(content(go_key[2]));
    let mut go = ec_base("P-256 (Go's)", "P-256", content(go_inner[1]).to_vec());
    go.cert = unhex(P256_CERT);
    let mut p224 = vec![0; 28];
    p224[27] = 1;
    vec![
        go,
        ec_base("P-256", "P-256", drawn(32, 0x00)),
        ec_base("P-384", "P-384", drawn(48, 0x7f)),
        ec_base("P-521", "P-521", drawn(66, 0x00)),
        ec_base("P-224", "P-224", p224),
    ]
}

/// The Ed25519 base key's seed, and its public key.
fn ed25519_base() -> ([u8; 32], [u8; 32]) {
    let mut seed = [0; 32];
    SplitMix64(0xed_2026_1026).fill(&mut seed);
    seed[0] = 0x30;
    let hash = Sha512::digest(seed);
    let scalar = clamp_integer(hash[..32].try_into().expect("32 bytes"));
    let public = EdwardsPoint::mul_base(&Scalar::from_bytes_mod_order(scalar))
        .compress()
        .to_bytes();
    (seed, public)
}

/// The keys the provider signs with, each in Go's PKCS#8, with its
/// SubjectPublicKeyInfo: the Go-made P-256 key, the P-384 and P-521 bases
/// and the Ed25519 one.
pub fn base_keys() -> Vec<BaseKey> {
    let mut keys: Vec<BaseKey> = ec_bases()
        .into_iter()
        .filter(|base| base.curve != "P-224" && base.name != "P-256")
        .map(|base| BaseKey {
            name: base.name,
            pkcs8: pkcs8(
                &[0],
                &[&tlv(0x06, EC_PUBLIC_KEY), &tlv(0x06, curve_oid(base.curve))],
                &sec1(&[1], &base.scalar, &[&public_key(&base.public)]),
                &[],
            ),
            spki: ec_spki(base.curve, &base.public),
        })
        .collect();
    let (seed, public) = ed25519_base();
    keys.push(BaseKey {
        name: "Ed25519",
        pkcs8: pkcs8(&[0], &[&tlv(0x06, ED25519)], &tlv(0x04, &seed), &[]),
        spki: ed25519_spki(&public),
    });
    keys
}

/// An Ed25519 SubjectPublicKeyInfo for `public`.
fn ed25519_spki(public: &[u8]) -> Vec<u8> {
    seq(&[
        &seq(&[&tlv(0x06, ED25519)]),
        &tlv(0x03, &[&[0][..], public].concat()),
    ])
}

/// A SEC 1 key: `version`, `scalar`, then `inside`.
fn sec1(version: &[u8], scalar: &[u8], inside: &[&[u8]]) -> Vec<u8> {
    seq(&[&[&tlv(0x02, version)[..], &tlv(0x04, scalar)][..], inside].concat())
}

/// A PKCS#8 key: `version`, the algorithm identifier of `algorithm`,
/// `key` in its OCTET STRING, then `inside`.
fn pkcs8(version: &[u8], algorithm: &[&[u8]], key: &[u8], inside: &[&[u8]]) -> Vec<u8> {
    seq(&[
        &[&tlv(0x02, version)[..], &seq(algorithm), &tlv(0x04, key)][..],
        inside,
    ]
    .concat())
}

/// SEC 1's `[0]` naming the curve of `oid`.
fn named(oid: &[u8]) -> Vec<u8> {
    tlv(0xa0, &tlv(0x06, oid))
}

/// SEC 1's `[1]` holding `public`.
fn public_key(public: &[u8]) -> Vec<u8> {
    tlv(0xa1, &tlv(0x03, &[&[0][..], public].concat()))
}

/// `value` less one, big-endian.
fn minus_one(value: &[u8]) -> Vec<u8> {
    let mut out = value.to_vec();
    for byte in out.iter_mut().rev() {
        let borrow = *byte == 0;
        *byte = byte.wrapping_sub(1);
        if !borrow {
            break;
        }
    }
    out
}

/// `element` with its length written in a form that is not the fewest
/// bytes: the long form for a short length, or a leading zero.
fn long_length(element: &[u8]) -> Vec<u8> {
    let body = content(element);
    let len = body.len();
    let header: Vec<u8> = if len < 0x80 {
        vec![element[0], 0x81, len as u8]
    } else {
        vec![element[0], 0x83, 0, (len >> 8) as u8, len as u8]
    };
    [&header[..], body].concat()
}

/// The corpus.
pub fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for base in ec_bases() {
        ec_cases(&base, &mut cases);
    }
    ed25519_cases(&mut cases);
    rsa_cases(&mut cases);
    cases
}

/// The cases of an EC base key.
fn ec_cases(base: &EcBase, cases: &mut Vec<Case>) {
    let mut add = |what: String, der: Vec<u8>, pem_label: &'static str| {
        cases.push(Case {
            label: format!("{}, {what}", base.name),
            der,
            pem_label,
            cert: base.cert.clone(),
        });
    };
    const SEC1: &str = "EC PRIVATE KEY";
    const PKCS8: &str = "PRIVATE KEY";
    let d = &base.scalar[..];
    let q = &base.public[..];
    let own = curve_oid(base.curve);
    let order = CURVES
        .iter()
        .find(|(curve, _, _)| *curve == base.curve)
        .map(|(_, _, order)| unhex(order))
        .expect("the base's curve");
    assert_eq!(
        order.len(),
        d.len(),
        "{}: the order at the field's length",
        base.curve
    );
    let curve = named(own);
    let public = public_key(q);
    let full = sec1(&[1], d, &[&curve, &public]);
    let null = [0x05, 0x00];

    add("SEC 1".into(), full.clone(), SEC1);
    add(
        "SEC 1, no public key".into(),
        sec1(&[1], d, &[&curve]),
        SEC1,
    );
    add("SEC 1, no curve".into(), sec1(&[1], d, &[&public]), SEC1);
    add(
        "SEC 1, no curve or public key".into(),
        sec1(&[1], d, &[]),
        SEC1,
    );
    for (what, version) in [
        ("0", &[0][..]),
        ("2", &[2]),
        ("-1", &[0xff]),
        ("256", &[1, 0]),
        ("1, not minimal", &[0, 1]),
        ("1 in nine bytes", &[0, 0, 0, 0, 0, 0, 0, 0, 1]),
    ] {
        add(
            format!("SEC 1, version {what}"),
            sec1(version, d, &[&curve, &public]),
            SEC1,
        );
    }
    let stripped: Vec<u8> = d.iter().copied().skip_while(|&byte| byte == 0).collect();
    let mut one = vec![0; d.len()];
    *one.last_mut().expect("a scalar") = 1;
    for (what, scalar) in [
        ("one zero byte ahead", [&[0][..], d].concat()),
        ("two zero bytes ahead", [&[0, 0][..], d].concat()),
        ("a non-zero byte ahead", [&[1][..], d].concat()),
        ("its leading zero bytes dropped", stripped),
        ("empty", Vec::new()),
        ("zero", vec![0; d.len()]),
        ("1", one),
        ("n", order.clone()),
        ("all ones", vec![0xff; d.len()]),
    ] {
        add(
            format!("SEC 1, scalar {what}"),
            sec1(&[1], &scalar, &[&curve, &public]),
            SEC1,
        );
    }
    if base.curve != "P-224" {
        // n - 1's public key is the negated generator, which the P-224
        // base's certificate does not certify.
        add(
            "SEC 1, scalar n - 1".into(),
            sec1(&[1], &minus_one(&order), &[&curve, &public]),
            SEC1,
        );
    }
    for (name, oid, _) in CURVES {
        if name != base.curve {
            add(
                format!("SEC 1, [0] naming {name}"),
                sec1(&[1], d, &[&named(oid), &public]),
                SEC1,
            );
        }
    }
    let wrapped = |inner: &[u8]| tlv(0xa0, inner);
    let own_oid = tlv(0x06, own);
    for (what, zero) in [
        ("naming secp256k1", named(SECP256K1)),
        ("an empty OID", wrapped(&[0x06, 0x00])),
        ("an OID cut short", wrapped(&[0x06, 0x01, 0x81])),
        (
            "an OID with a non-minimal arc",
            wrapped(&[0x06, 0x02, 0x80, 0x01]),
        ),
        ("holding an INTEGER", wrapped(&[0x02, 0x01, 0x01])),
        ("holding a NULL", wrapped(&null)),
        (
            "primitive",
            [&[0x80, own_oid.len() as u8][..], &own_oid].concat(),
        ),
        (
            "shorter than its OID",
            [&[0xa0, 0x01][..], &own_oid].concat(),
        ),
        (
            "longer than the key",
            [&[0xa0, 0x7f][..], &own_oid].concat(),
        ),
        ("empty", vec![0xa0, 0x00]),
        (
            "in the high-tag form",
            [&[0xbf, 0x00, own_oid.len() as u8][..], &own_oid].concat(),
        ),
        (
            "of the private class",
            [&[0xe0, own_oid.len() as u8][..], &own_oid].concat(),
        ),
    ] {
        add(
            format!("SEC 1, [0] {what}"),
            sec1(&[1], d, &[&zero, &public]),
            SEC1,
        );
    }
    let mut off_curve = q.to_vec();
    *off_curve.last_mut().expect("a point") ^= 1;
    let half = (q.len() - 1) / 2;
    let compressed = [&[0x02 | (q[q.len() - 1] & 1)][..], &q[1..=half]].concat();
    for (what, one) in [
        (
            "unused bits 8",
            tlv(0xa1, &tlv(0x03, &[&[8][..], q].concat())),
        ),
        ("an unused bit set", tlv(0xa1, &tlv(0x03, &[0x01, 0x01]))),
        ("unused bits with no bits", tlv(0xa1, &tlv(0x03, &[0x01]))),
        ("an empty BIT STRING", tlv(0xa1, &tlv(0x03, &[]))),
        ("empty", vec![0xa1, 0x00]),
        ("holding an OCTET STRING", tlv(0xa1, &tlv(0x04, q))),
        ("a point off the curve", public_key(&off_curve)),
        ("a compressed point", public_key(&compressed)),
        (
            "seven unused zero bits",
            tlv(0xa1, &tlv(0x03, &[0x07, 0x80])),
        ),
    ] {
        add(
            format!("SEC 1, [1] {what}"),
            sec1(&[1], d, &[&curve, &one]),
            SEC1,
        );
    }
    for (what, inside) in [
        (
            "a NULL after [1]",
            vec![curve.clone(), public.clone(), null.to_vec()],
        ),
        (
            "bytes that do not read after [1]",
            vec![curve.clone(), public.clone(), vec![0xff]],
        ),
        (
            "a second [0] after [1]",
            vec![curve.clone(), public.clone(), curve.clone()],
        ),
        (
            "a NULL closing it after [0]",
            vec![curve.clone(), null.to_vec()],
        ),
        (
            "two NULLs after [0]",
            vec![curve.clone(), [null, null].concat()],
        ),
        (
            "a NULL between [0] and [1]",
            vec![curve.clone(), null.to_vec(), public.clone()],
        ),
        (
            "bytes that do not read after [0]",
            vec![curve.clone(), vec![0xff]],
        ),
        ("a NULL closing it after the scalar", vec![null.to_vec()]),
        ("two NULLs after the scalar", vec![[null, null].concat()]),
    ] {
        let inside: Vec<&[u8]> = inside.iter().map(Vec::as_slice).collect();
        add(format!("SEC 1, {what}"), sec1(&[1], d, &inside), SEC1);
    }
    for (what, after) in [
        ("a zero byte", &[0x00][..]),
        ("a NULL", &null),
        ("bytes that do not read", &[0xff, 0xff]),
    ] {
        add(
            format!("SEC 1, {what} after it"),
            [&full[..], after].concat(),
            SEC1,
        );
    }
    add(
        "SEC 1, a length not minimal".into(),
        long_length(&full),
        SEC1,
    );
    add(
        "SEC 1, an indefinite length".into(),
        [&[0x30, 0x80][..], content(&full), &[0, 0]].concat(),
        SEC1,
    );
    add(
        "SEC 1, a SET".into(),
        [&[0x31][..], &full[1..]].concat(),
        SEC1,
    );
    add(
        "SEC 1, the scalar a constructed OCTET STRING".into(),
        seq(&[&tlv(0x02, &[1]), &tlv(0x24, &tlv(0x04, d)), &curve, &public]),
        SEC1,
    );

    let ec = tlv(0x06, EC_PUBLIC_KEY);
    let params = tlv(0x06, own);
    let inner = sec1(&[1], d, &[&public]);
    let canonical = pkcs8(&[0], &[&ec, &params], &inner, &[]);
    add("PKCS#8".into(), canonical.clone(), PKCS8);
    add(
        "PKCS#8, the curve inside too".into(),
        pkcs8(&[0], &[&ec, &params], &full, &[]),
        PKCS8,
    );
    for (name, oid, _) in CURVES {
        if name != base.curve {
            add(
                format!("PKCS#8, the inner key naming {name}"),
                pkcs8(
                    &[0],
                    &[&ec, &params],
                    &sec1(&[1], d, &[&named(oid), &public]),
                    &[],
                ),
                PKCS8,
            );
            add(
                format!("PKCS#8, parameters naming {name}"),
                pkcs8(&[0], &[&ec, &tlv(0x06, oid)], &full, &[]),
                PKCS8,
            );
        }
    }
    for (what, zero) in [
        ("naming secp256k1", named(SECP256K1)),
        ("an OID cut short", wrapped(&[0x06, 0x01, 0x81])),
        ("holding an INTEGER", wrapped(&[0x02, 0x01, 0x01])),
    ] {
        add(
            format!("PKCS#8, the inner [0] {what}"),
            pkcs8(
                &[0],
                &[&ec, &params],
                &sec1(&[1], d, &[&zero, &public]),
                &[],
            ),
            PKCS8,
        );
    }
    for (what, algorithm, key) in [
        (
            "no parameters, the curve inside",
            vec![ec.clone()],
            full.clone(),
        ),
        (
            "no parameters and no curve inside",
            vec![ec.clone()],
            inner.clone(),
        ),
        (
            "NULL parameters, the curve inside",
            vec![ec.clone(), null.to_vec()],
            full.clone(),
        ),
        (
            "NULL parameters and no curve inside",
            vec![ec.clone(), null.to_vec()],
            inner.clone(),
        ),
        (
            "parameters an OID cut short, the curve inside",
            vec![ec.clone(), vec![0x06, 0x01, 0x81]],
            full.clone(),
        ),
        (
            "parameters naming secp256k1, the curve inside",
            vec![ec.clone(), tlv(0x06, SECP256K1)],
            full.clone(),
        ),
        (
            "parameters a constructed element",
            vec![ec.clone(), seq(&[&params])],
            full.clone(),
        ),
        (
            "an element after the parameters",
            vec![ec.clone(), params.clone(), null.to_vec()],
            inner.clone(),
        ),
        (
            "bytes that do not read after the parameters",
            vec![ec.clone(), params.clone(), vec![0xff]],
            inner.clone(),
        ),
        (
            "bytes that do not read after the algorithm",
            vec![ec.clone(), vec![0xff]],
            full.clone(),
        ),
        (
            "the algorithm id-ecDH",
            vec![tlv(0x06, EC_DH), params.clone()],
            inner.clone(),
        ),
        (
            "the algorithm rsaEncryption",
            vec![tlv(0x06, RSA_ENCRYPTION), params.clone()],
            inner.clone(),
        ),
        (
            "the algorithm an OID cut short",
            vec![vec![0x06, 0x01, 0x81], params.clone()],
            inner.clone(),
        ),
        (
            "the inner key version 0",
            vec![ec.clone(), params.clone()],
            sec1(&[0], d, &[&public]),
        ),
        (
            "the inner scalar one zero byte ahead",
            vec![ec.clone(), params.clone()],
            sec1(&[1], &[&[0][..], d].concat(), &[&public]),
        ),
        (
            "bytes after the inner key",
            vec![ec.clone(), params.clone()],
            [&inner[..], &[0xff, 0xff]].concat(),
        ),
        (
            "a NULL closing the inner key after its scalar",
            vec![ec.clone(), params.clone()],
            sec1(&[1], d, &[&null]),
        ),
        (
            "two NULLs after the inner key's scalar",
            vec![ec.clone(), params.clone()],
            sec1(&[1], d, &[&[null, null].concat()]),
        ),
    ] {
        let algorithm: Vec<&[u8]> = algorithm.iter().map(Vec::as_slice).collect();
        add(
            format!("PKCS#8, {what}"),
            pkcs8(&[0], &algorithm, &key, &[]),
            PKCS8,
        );
    }
    for (what, version) in [
        ("1", &[1][..]),
        ("-1", &[0xff]),
        ("2^62", &[0x40, 0, 0, 0, 0, 0, 0, 0]),
        ("1 in nine bytes", &[0, 0, 0, 0, 0, 0, 0, 0, 1]),
    ] {
        add(
            format!("PKCS#8, version {what}"),
            pkcs8(version, &[&ec, &params], &inner, &[]),
            PKCS8,
        );
    }
    for (what, after) in [
        ("attributes", tlv(0xa0, &tlv(0x31, &[]))),
        ("a public key", tlv(0x81, &[&[0][..], q].concat())),
        ("bytes that do not read", vec![0xff]),
    ] {
        add(
            format!("PKCS#8, {what} after the key"),
            pkcs8(&[0], &[&ec, &params], &inner, &[&after]),
            PKCS8,
        );
    }
    add(
        "PKCS#8, a NULL after it".into(),
        [&canonical[..], &null].concat(),
        PKCS8,
    );
    add(
        "PKCS#8, the key a constructed OCTET STRING".into(),
        seq(&[
            &tlv(0x02, &[0]),
            &seq(&[&ec, &params]),
            &tlv(0x24, &tlv(0x04, &inner)),
        ]),
        PKCS8,
    );

    for label in ["PRIVATE KEY", "RSA PRIVATE KEY", "OPENSSH PRIVATE KEY"] {
        add(format!("SEC 1 under {label}"), full.clone(), label);
    }
    for label in ["EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY"] {
        add(format!("PKCS#8 under {label}"), canonical.clone(), label);
    }
}

/// The cases of the Ed25519 base key, and of X25519 keys.
fn ed25519_cases(cases: &mut Vec<Case>) {
    let (seed, public) = ed25519_base();
    let cert = certificate(&ed25519_spki(&public));
    let mut add = |what: &str, der: Vec<u8>, pem_label: &'static str| {
        cases.push(Case {
            label: format!("Ed25519, {what}"),
            der,
            pem_label,
            cert: cert.clone(),
        });
    };
    const PKCS8: &str = "PRIVATE KEY";
    let ed = tlv(0x06, ED25519);
    let x = tlv(0x06, X25519);
    let key = tlv(0x04, &seed);
    let null = [0x05, 0x00];
    let canonical = pkcs8(&[0], &[&ed], &key, &[]);
    let mut other = public;
    other[0] ^= 1;
    add("PKCS#8", canonical.clone(), PKCS8);
    for (what, version, algorithm, key, inside) in [
        (
            "version 1, its public key after it",
            &[1][..],
            vec![ed.clone()],
            key.clone(),
            vec![tlv(0x81, &[&[0][..], &public].concat())],
        ),
        (
            "version 1, another public key after it",
            &[1],
            vec![ed.clone()],
            key.clone(),
            vec![tlv(0x81, &[&[0][..], &other].concat())],
        ),
        (
            "attributes after it",
            &[0],
            vec![ed.clone()],
            key.clone(),
            vec![tlv(0xa0, &tlv(0x31, &[]))],
        ),
        ("version -1", &[0xff], vec![ed.clone()], key.clone(), vec![]),
        (
            "NULL parameters",
            &[0],
            vec![ed.clone(), null.to_vec()],
            key.clone(),
            vec![],
        ),
        (
            "parameters an OID",
            &[0],
            vec![ed.clone(), tlv(0x06, ED25519)],
            key.clone(),
            vec![],
        ),
        (
            "a seed of 31 bytes",
            &[0],
            vec![ed.clone()],
            tlv(0x04, &seed[..31]),
            vec![],
        ),
        (
            "a seed of 33 bytes",
            &[0],
            vec![ed.clone()],
            tlv(0x04, &[&seed[..], &[0]].concat()),
            vec![],
        ),
        (
            "an empty seed",
            &[0],
            vec![ed.clone()],
            tlv(0x04, &[]),
            vec![],
        ),
        (
            "the seed bare",
            &[0],
            vec![ed.clone()],
            seed.to_vec(),
            vec![],
        ),
        (
            "the seed an INTEGER",
            &[0],
            vec![ed.clone()],
            tlv(0x02, &[&[0][..], &seed].concat()),
            vec![],
        ),
        (
            "bytes after the seed",
            &[0],
            vec![ed.clone()],
            [&key[..], &[0xff, 0xff]].concat(),
            vec![],
        ),
        (
            "the seed a constructed OCTET STRING",
            &[0],
            vec![ed.clone()],
            tlv(0x24, &key),
            vec![],
        ),
        (
            "the algorithm id-Ed448",
            &[0],
            vec![tlv(0x06, ED448)],
            key.clone(),
            vec![],
        ),
        (
            "the algorithm id-X25519",
            &[0],
            vec![x.clone()],
            key.clone(),
            vec![],
        ),
        (
            "the algorithm id-X25519, 31 bytes",
            &[0],
            vec![x.clone()],
            tlv(0x04, &seed[..31]),
            vec![],
        ),
        (
            "the algorithm id-X25519, NULL parameters",
            &[0],
            vec![x.clone(), null.to_vec()],
            key.clone(),
            vec![],
        ),
    ] {
        let algorithm: Vec<&[u8]> = algorithm.iter().map(Vec::as_slice).collect();
        let inside: Vec<&[u8]> = inside.iter().map(Vec::as_slice).collect();
        add(what, pkcs8(version, &algorithm, &key, &inside), PKCS8);
    }
    add("a NULL after it", [&canonical[..], &null].concat(), PKCS8);
    for label in ["EC PRIVATE KEY", "RSA PRIVATE KEY"] {
        add(&format!("PKCS#8 under {label}"), canonical.clone(), label);
    }
}

/// The cases of the RSA base key.
fn rsa_cases(cases: &mut Vec<Case>) {
    let cert = unhex(RSA2048_CERT);
    let mut add = |what: &str, der: Vec<u8>, pem_label: &'static str| {
        cases.push(Case {
            label: format!("RSA, {what}"),
            der,
            pem_label,
            cert: cert.clone(),
        });
    };
    const PKCS1: &str = "RSA PRIVATE KEY";
    let wrapped = unhex(RSA2048_KEY);
    let pkcs1_der = content(elements(&wrapped)[2]).to_vec();
    let fields: Vec<Vec<u8>> = elements(&pkcs1_der).iter().map(|e| e.to_vec()).collect();
    assert_eq!(
        fields.len(),
        9,
        "version, N, E, D, P, Q and the three CRT values"
    );
    let key = |fields: &[Vec<u8>], after: &[&[u8]]| {
        let fields: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
        seq(&[&fields[..], after].concat())
    };
    let with = |index: usize, value: Vec<u8>| {
        let mut fields = fields.clone();
        fields[index] = value;
        fields
    };
    let int = |content: &[u8]| tlv(0x02, content);
    let null = [0x05, 0x00];
    let prime = seq(&[&int(&[3]), &int(&[1]), &int(&[1])]);
    add("PKCS#1", key(&fields, &[]), PKCS1);
    add(
        "PKCS#1, version -1",
        key(&with(0, int(&[0xff])), &[]),
        PKCS1,
    );
    add("PKCS#1, version 1", key(&with(0, int(&[1])), &[]), PKCS1);
    add("PKCS#1, version 2", key(&with(0, int(&[2])), &[]), PKCS1);
    add("PKCS#1, no CRT values", key(&fields[..6], &[]), PKCS1);
    add("PKCS#1, Dp alone", key(&fields[..7], &[]), PKCS1);
    add(
        "PKCS#1, a CRT exponent wrong",
        key(&with(6, int(&[1])), &[]),
        PKCS1,
    );
    add(
        "PKCS#1, P negative",
        key(&with(4, int(&[0xff])), &[]),
        PKCS1,
    );
    add(
        "PKCS#1, an additional prime",
        key(&with(0, int(&[1])), &[&seq(&[&prime])]),
        PKCS1,
    );
    add(
        "PKCS#1, no additional primes",
        key(&fields, &[&seq(&[])]),
        PKCS1,
    );
    add(
        "PKCS#1, an additional prime of two values",
        key(&fields, &[&seq(&[&seq(&[&int(&[3]), &int(&[1])])])]),
        PKCS1,
    );
    add("PKCS#1, a NULL after it", key(&fields, &[&null]), PKCS1);
    add(
        "PKCS#1, bytes that do not read after it",
        key(&fields, &[&[0xff]]),
        PKCS1,
    );
    add(
        "PKCS#1, a zero byte after it",
        [&key(&fields, &[])[..], &[0]].concat(),
        PKCS1,
    );
    add(
        "PKCS#1, E in nine bytes",
        key(&with(2, int(&[1, 0, 0, 0, 0, 0, 0, 0, 1])), &[]),
        PKCS1,
    );
    add(
        "PKCS#1, N not minimal",
        key(
            &with(1, int(&[&[0][..], content(&fields[1])].concat())),
            &[],
        ),
        PKCS1,
    );
    add("PKCS#8", wrapped.clone(), "PRIVATE KEY");
    add(
        "PKCS#8, no parameters",
        pkcs8(&[0], &[&tlv(0x06, RSA_ENCRYPTION)], &pkcs1_der, &[]),
        "PRIVATE KEY",
    );
    add(
        "PKCS#8, a zero byte after the inner key",
        pkcs8(
            &[0],
            &[&tlv(0x06, RSA_ENCRYPTION), &null],
            &[&pkcs1_der[..], &[0]].concat(),
            &[],
        ),
        "PRIVATE KEY",
    );
    for label in ["PRIVATE KEY", "EC PRIVATE KEY"] {
        add(&format!("PKCS#1 under {label}"), key(&fields, &[]), label);
    }
}

/// The P-256 server certificate the ECDSA and TLS 1.3 handshakes of
/// `tests/ring_parity.rs` use, and the certificate of the Go-made P-256
/// base key: self-signed for `localhost`, valid from 2026 to 9999, made
/// once with Go 1.26.2's `crypto/x509` for these tests.
pub const P256_CERT: &str = "\
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
pub const P256_KEY: &str = "\
    308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02\
    01010420a9868ed882e56ef01d5ce5f867e19593cc5316442917c9e07010bc34\
    166428d4a144034200048906089259a44192a029477117b3dac5d142059a7e39\
    acd172143cf3db9a710f109ca52ad1203cf22f4cff10adbbdbdff10962e551b1\
    2d03684ed5adea1b7762";

/// The RSA-2048 server certificate the ECDHE-RSA handshakes use, and the
/// RSA base key's, made as [`P256_CERT`] was.
pub const RSA2048_CERT: &str = "\
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
pub const RSA2048_KEY: &str = "\
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
