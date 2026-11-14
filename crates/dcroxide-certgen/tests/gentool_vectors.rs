// SPDX-License-Identifier: ISC
//! Checks for the gencerts machinery: authority and issued
//! certificates round-trip through the CA loader across the
//! algorithms, the issuance checks match dcrd's, the template rules
//! (validity clamp, elapsed error) hold, and the CA key is read and
//! paired as Go's `tls.X509KeyPair` reads and pairs it.

use dcroxide_certgen::gentool::{
    GenEnv, ToolKeyPair, create_issued_cert, generate_authority, generate_key, load_ca_pair,
    pem_private_key,
};

/// A scripted clock and serial source.
struct FixedEnv {
    now: i64,
    serial: u8,
}

impl GenEnv for FixedEnv {
    fn now_unix(&mut self) -> i64 {
        self.now
    }

    fn serial_bytes(&mut self) -> Vec<u8> {
        self.serial = self.serial.wrapping_add(1);
        vec![self.serial; 16]
    }
}

fn env() -> FixedEnv {
    FixedEnv {
        now: 1_752_000_000, // 2025-07-08
        serial: 0,
    }
}

/// Authorities round-trip through the CA loader for every non-RSA
/// algorithm: the PKCS#8 key parses and matches the certificate, and
/// the -S key usage is readable back.
#[test]
fn authorities_round_trip_across_algorithms() {
    for algo in ["P-256", "P-384", "P-521", "Ed25519"] {
        let key = generate_key(algo).expect("known algorithm");
        let hosts = vec!["localhost".to_string(), "127.0.0.1".to_string()];
        let ca = generate_authority(&mut env(), &key, &hosts, "org", 10, true)
            .unwrap_or_else(|e| panic!("{algo}: generate authority: {e}"));
        let key_pem = pem_private_key(&key.marshal_pkcs8().expect("marshal"));
        let (loaded, loaded_key) =
            load_ca_pair(&ca.pem, &key_pem).unwrap_or_else(|e| panic!("{algo}: load pair: {e}"));
        assert!(loaded.cert_sign, "{algo}: -S must set keyCertSign");
        assert!(
            loaded.subject_key_id.is_some(),
            "{algo}: an authority carries a subject key id"
        );
        assert_eq!(
            loaded_key.public_bytes(),
            key.public_bytes(),
            "{algo}: the loaded key must be the generated one"
        );
    }
}

/// An issued certificate carries the CA's validity clamp and cannot
/// itself issue without keyCertSign, and the pair loader refuses a
/// mismatched key with Go's error.
#[test]
fn issuance_checks_match_dcrd() {
    let ca_key = generate_key("P-256").expect("keygen");
    let ca = generate_authority(
        &mut env(),
        &ca_key,
        &["localhost".to_string()],
        "org",
        1, // a SHORT authority validity: the leaf clamps to it
        true,
    )
    .expect("authority");
    let ca_key_pem = pem_private_key(&ca_key.marshal_pkcs8().expect("marshal"));
    let (loaded_ca, loaded_ca_key) = load_ca_pair(&ca.pem, &ca_key_pem).expect("load ca");

    // The leaf asks for ten years but clamps to the CA's NotAfter.
    let leaf_key = generate_key("Ed25519").expect("keygen");
    let leaf = create_issued_cert(
        &mut env(),
        &leaf_key,
        &loaded_ca,
        &loaded_ca_key,
        &["localhost".to_string()],
        "org",
        10,
        false,
    )
    .expect("issue leaf");
    let leaf_key_pem = pem_private_key(&leaf_key.marshal_pkcs8().expect("marshal"));
    let (loaded_leaf, _) = load_ca_pair(&leaf.pem, &leaf_key_pem).expect("load leaf");
    assert_eq!(
        loaded_leaf.not_after_unix, loaded_ca.not_after_unix,
        "the issued validity clamps to the parent's"
    );
    assert!(
        !loaded_leaf.cert_sign,
        "an issued certificate without -S cannot sign"
    );
    assert!(
        loaded_leaf.subject_key_id.is_none(),
        "Go only auto-computes the subject key id for CA certificates"
    );

    // Issuing FROM the leaf fails dcrd's parent check.
    let another = generate_key("P-256").expect("keygen");
    let err = create_issued_cert(
        &mut env(),
        &another,
        &loaded_leaf,
        &leaf_key,
        &[],
        "org",
        1,
        false,
    )
    .map(|_| ())
    .expect_err("a non-signing parent must be refused");
    assert_eq!(err, "parent certificate cannot sign other certificates");

    // A mismatched pair is refused with Go's error, here for a key of
    // another type than the certificate's.
    let err = load_ca_pair(&ca.pem, &leaf_key_pem)
        .map(|_| ())
        .expect_err("mismatch");
    assert_eq!(err, "tls: private key type does not match public key type");
}

/// The template refuses an already-elapsed validity with Go's
/// rendered time, and negative years produce exactly that.
#[test]
fn elapsed_validity_is_refused() {
    let key = generate_key("P-256").expect("keygen");
    let err = generate_authority(&mut env(), &key, &[], "org", -1, false)
        .map(|_| ())
        .expect_err("negative years must fail");
    assert!(
        err.starts_with("valid until date ") && err.ends_with(" already elapsed"),
        "unexpected error: {err}"
    );
}

/// A DER element: `tag`, its length in DER's shortest form, `content`.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let len = content.len();
    let mut out = vec![tag];
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(content);
    out
}

/// A SEQUENCE of `parts`.
fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

/// An INTEGER of a big-endian magnitude, with the zero byte DER asks for
/// ahead of a high bit.
fn int(magnitude: &[u8]) -> Vec<u8> {
    let sign = magnitude.first().is_none_or(|first| first & 0x80 != 0);
    tlv(
        0x02,
        &[if sign { &[0][..] } else { &[] }, magnitude].concat(),
    )
}

/// `id-ecPublicKey`.
const EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// `id-Ed25519`.
const ED25519: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
/// `id-X25519`.
const X25519: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x6e];
/// `rsaEncryption`.
const RSA_ENCRYPTION: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
];
/// `id-ml-dsa-44`, `id-ml-dsa-65` and `id-ml-dsa-87`.
const ML_DSA_44: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11,
];
const ML_DSA_65: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12,
];
const ML_DSA_87: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13,
];
/// `secp224r1`, `prime256v1`, `secp384r1`, `secp521r1` and `secp256k1`.
const P224: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x21];
const P256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const P384: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
const P521: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23];
const SECP256K1: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a];
/// ASN.1 NULL.
const NULL: &[u8] = &[0x05, 0x00];
/// P-256's order.
const P256_ORDER: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

/// A SEC 1 `ECPrivateKey`: version, scalar, and the `[0]` curve and `[1]`
/// public key when given.
fn sec1(version: u8, scalar: &[u8], curve: Option<&[u8]>, public: Option<&[u8]>) -> Vec<u8> {
    let mut parts = vec![tlv(0x02, &[version]), tlv(0x04, scalar)];
    if let Some(curve) = curve {
        parts.push(tlv(0xa0, curve));
    }
    if let Some(public) = public {
        parts.push(tlv(0xa1, &tlv(0x03, &[&[0][..], public].concat())));
    }
    tlv(0x30, &parts.concat())
}

/// A PKCS#8 `PrivateKeyInfo`: version 0, the algorithm identifier's
/// elements, the key's OCTET STRING.
fn pkcs8(algorithm: &[&[u8]], key: &[u8]) -> Vec<u8> {
    seq(&[&[0x02, 0x01, 0x00], &seq(algorithm), &tlv(0x04, key)])
}

/// `der` in a PEM block labelled `label`.
fn pem(label: &str, der: &[u8]) -> Vec<u8> {
    String::from_utf8(pem_private_key(der))
        .expect("PEM is text")
        .replace("PRIVATE KEY", label)
        .into_bytes()
}

/// The elements of the DER element `der`'s content, each whole, in order.
fn children(der: &[u8]) -> Vec<&[u8]> {
    let header = |der: &[u8]| match der[1] {
        short @ 0..0x80 => (2, usize::from(short)),
        long => {
            let count = usize::from(long & 0x7f);
            let len = der[2..2 + count]
                .iter()
                .fold(0, |len, byte| len << 8 | usize::from(*byte));
            (2 + count, len)
        }
    };
    let end = |(start, len): (usize, usize)| start.checked_add(len).expect("a length that fits");
    let (start, len) = header(der);
    let mut rest = &der[start..end((start, len))];
    let mut out = Vec::new();
    while !rest.is_empty() {
        let (element, after) = rest.split_at(end(header(rest)));
        out.push(element);
        rest = after;
    }
    out
}

/// The certificate `der` with its SubjectPublicKeyInfo replaced by `spki`,
/// in a CERTIFICATE PEM block.  Neither Go nor the loader checks the
/// signature when it loads a pair.
fn with_key(der: &[u8], spki: &[u8]) -> Vec<u8> {
    let certificate = children(der);
    let mut tbs = children(certificate[0]);
    // The version, serial, signature algorithm, issuer, validity and
    // subject come first.
    assert_eq!(tbs[0][0], 0xa0, "a version 3 certificate");
    tbs[6] = spki;
    let der = seq(&[&seq(&tbs), certificate[1], certificate[2]]);
    pem("CERTIFICATE", &der)
}

/// A SubjectPublicKeyInfo: the algorithm identifier's elements, the key's
/// BIT STRING content.
fn spki(algorithm: &[&[u8]], key: &[u8]) -> Vec<u8> {
    seq(&[&seq(algorithm), &tlv(0x03, &[&[0][..], key].concat())])
}

/// The loader's answer for a CA pair in the words of the oracle's
/// `x509_key_pair`: "ok" and the key's type, or "refused: " and the text.
fn port_pair(cert_pem: &[u8], key_pem: &[u8]) -> String {
    match load_ca_pair(cert_pem, key_pem) {
        Ok((_, key)) => match key {
            ToolKeyPair::P256(_) => "ok ECDSA P-256",
            ToolKeyPair::P384(_) => "ok ECDSA P-384",
            ToolKeyPair::P521(_) => "ok ECDSA P-521",
            ToolKeyPair::Ed25519(_) => "ok Ed25519",
        }
        .to_owned(),
        Err(text) => format!("refused: {text}"),
    }
}

/// Go's answer for a CA pair: `tls.X509KeyPair`, which dcrd's gencerts
/// opens the pair with (`cmd/gencerts/gencerts.go:140`), through the
/// oracle's `x509_key_pair`.
fn go_pair(oracle: &mut dcroxide_testutil::Oracle, cert_pem: &[u8], key_pem: &[u8]) -> String {
    let request = serde_json::json!({
        "cert_pem": String::from_utf8_lossy(cert_pem),
        "key_pem": String::from_utf8_lossy(key_pem),
    });
    let response = oracle.call("x509_key_pair", request.to_string().as_bytes());
    dcroxide_testutil::require_reference_go(response["go_version"].as_str().unwrap_or_default());
    response["result"]
        .as_str()
        .unwrap_or_else(|| panic!("the oracle answered {response}"))
        .to_owned()
}

/// Go's text for a key none of its parsers reads, before the cause.
const UNPARSABLE: &str = "refused: tls: failed to parse private key: ";

/// Go's answers for a key it read that is not the certificate's, of the
/// certificate's type and of another (`crypto/tls/tls.go:318-353`).
const NOT_THE_KEY: &str = "refused: tls: private key does not match public key";
const NOT_THE_TYPE: &str = "refused: tls: private key type does not match public key type";

/// The loader's words for an RSA key, which Go loads and issues with.
const RSA_REFUSED: &str = "refused: RSA private keys are not supported: gencerts issues with \
                           ECDSA (P-256, P-384, P-521) and Ed25519 keys";

/// `asn1`'s dump of a field's parameters, the same for every field Go
/// reads a key with.
const PARAMETERS: &str = "{optional:false explicit:false application:false private:false \
                          defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false \
                          omitEmpty:false}";

/// A CA key file: what it holds, its PEM label, its DER, the certificate
/// it is paired with, the loader's answer, and Go's where it differs.
type CaKeyRow<'a> = (&'a str, &'a str, Vec<u8>, usize, String, Option<&'a str>);

/// The CA key gencerts loads is read as Go's `tls.X509KeyPair` reads it,
/// whatever PEM label of the two the loader finds it under: each form
/// Go loads, PKCS#8 EC keys that name their curve only inside among them,
/// loads as Go loads it; a key Go refuses is refused with Go's
/// "tls: failed to parse private key: " and the cause Go gives; and the
/// keys Go loads that gencerts does not issue with, RSA, P-224 and ML-DSA,
/// are refused with words of the port's own where Go reads them.  A key
/// that is not the certificate's is refused with Go's text for a key of
/// the certificate's type and of another, for each type of certificate
/// key Go pairs, and a certificate key of a type Go pairs with none with
/// Go's text for that.  Each row's answer is written out, and held to
/// Go's through the oracle where one runs.
#[test]
fn ca_keys_load_as_go_loads_them() {
    let mut env = env();
    let keys: Vec<ToolKeyPair> = ["P-256", "P-384", "P-521", "Ed25519"]
        .into_iter()
        .map(|algo| generate_key(algo).expect("known algorithm"))
        .collect();
    let rsa = dcroxide_testutil::rsa_test_key("rsa2048");
    // The authorities of the four keys, in order; then the P-256 one with
    // its key swapped for the Ed25519 key named X25519, a type Go reads in
    // a certificate and pairs with no private key; then for an RSA key and
    // an ML-DSA-44, -65 and -87 key, the other types Go pairs.
    let mut certs: Vec<Vec<u8>> = keys
        .iter()
        .map(|key| {
            generate_authority(&mut env, key, &[], "org", 1, true)
                .expect("authority")
                .pem
        })
        .collect();
    let p256_der = generate_authority(&mut env, &keys[0], &[], "org", 1, true)
        .expect("authority")
        .der;
    let rsa_key = seq(&[&int(&rsa.n), &int(&rsa.e)]);
    for key in [
        spki(&[X25519], &keys[3].public_bytes()),
        spki(&[RSA_ENCRYPTION, NULL], &rsa_key),
        spki(&[ML_DSA_44], &[0; 1312]),
        spki(&[ML_DSA_65], &[0; 1952]),
        spki(&[ML_DSA_87], &[0; 2592]),
    ] {
        certs.push(with_key(&p256_der, &key));
    }
    let scalar = |key: &ToolKeyPair| -> Vec<u8> {
        match key {
            ToolKeyPair::P256(key) => key.to_bytes().to_vec(),
            ToolKeyPair::P384(key) => key.to_bytes().to_vec(),
            ToolKeyPair::P521(key) => key.to_bytes().to_vec(),
            ToolKeyPair::Ed25519(seed) => seed.to_vec(),
        }
    };
    let (p256, p384, p521, ed) = (&keys[0], &keys[1], &keys[2], &keys[3]);
    let s256 = scalar(p256);
    let pub256 = p256.public_bytes();
    let other_p256 = generate_key("P-256").expect("keygen");
    let pkcs1 = seq(&[
        &int(&[0]),
        &int(&rsa.n),
        &int(&rsa.e),
        &int(&rsa.d),
        &int(&rsa.p),
        &int(&rsa.q),
    ]);

    let rows: Vec<CaKeyRow> = vec![
        // The forms gencerts writes and reads back.
        (
            "PKCS#8 P-256, as gencerts writes it",
            "PRIVATE KEY",
            p256.marshal_pkcs8().expect("marshal"),
            0,
            "ok ECDSA P-256".into(),
            None,
        ),
        (
            "PKCS#8 Ed25519, as gencerts writes it",
            "PRIVATE KEY",
            ed.marshal_pkcs8().expect("marshal"),
            3,
            "ok Ed25519".into(),
            None,
        ),
        (
            "SEC 1 P-256 with its curve and public key",
            "EC PRIVATE KEY",
            sec1(1, &s256, Some(P256), Some(&pub256)),
            0,
            "ok ECDSA P-256".into(),
            None,
        ),
        (
            "SEC 1 P-256, the scalar after a zero byte",
            "EC PRIVATE KEY",
            sec1(1, &[&[0][..], &s256].concat(), Some(P256), None),
            0,
            "ok ECDSA P-256".into(),
            None,
        ),
        // The forms Go loads that the loader refused.
        (
            "PKCS#8 P-256 naming its curve only inside",
            "PRIVATE KEY",
            pkcs8(&[EC_PUBLIC_KEY], &sec1(1, &s256, Some(P256), None)),
            0,
            "ok ECDSA P-256".into(),
            None,
        ),
        (
            "PKCS#8 P-384 naming its curve only inside",
            "PRIVATE KEY",
            pkcs8(&[EC_PUBLIC_KEY], &sec1(1, &scalar(p384), Some(P384), None)),
            1,
            "ok ECDSA P-384".into(),
            None,
        ),
        (
            "PKCS#8 P-521 naming its curve only inside",
            "PRIVATE KEY",
            pkcs8(&[EC_PUBLIC_KEY], &sec1(1, &scalar(p521), Some(P521), None)),
            2,
            "ok ECDSA P-521".into(),
            None,
        ),
        (
            "PKCS#8 P-256 with NULL parameters, its curve inside",
            "PRIVATE KEY",
            pkcs8(&[EC_PUBLIC_KEY, NULL], &sec1(1, &s256, Some(P256), None)),
            0,
            "ok ECDSA P-256".into(),
            None,
        ),
        (
            "PKCS#8 P-256 under EC PRIVATE KEY",
            "EC PRIVATE KEY",
            p256.marshal_pkcs8().expect("marshal"),
            0,
            "ok ECDSA P-256".into(),
            None,
        ),
        (
            "PKCS#8 Ed25519 under EC PRIVATE KEY",
            "EC PRIVATE KEY",
            ed.marshal_pkcs8().expect("marshal"),
            3,
            "ok Ed25519".into(),
            None,
        ),
        (
            "SEC 1 P-256 under PRIVATE KEY",
            "PRIVATE KEY",
            sec1(1, &s256, Some(P256), None),
            0,
            "ok ECDSA P-256".into(),
            None,
        ),
        // The forms the loader took that Go refuses.
        (
            "PKCS#8 Ed25519 with NULL parameters",
            "PRIVATE KEY",
            pkcs8(&[ED25519, NULL], &tlv(0x04, &scalar(ed))),
            3,
            format!("{UNPARSABLE}x509: invalid Ed25519 private key parameters"),
            None,
        ),
        (
            "SEC 1 P-256, its scalar's length in the long form",
            "EC PRIVATE KEY",
            tlv(
                0x30,
                &[
                    &[0x02, 0x01, 0x01, 0x04, 0x81, 0x20][..],
                    &s256,
                    &tlv(0xa0, P256),
                ]
                .concat(),
            ),
            0,
            format!("{UNPARSABLE}asn1: structure error: non-minimal length"),
            None,
        ),
        // Go's causes.
        (
            "not DER",
            "PRIVATE KEY",
            b"not a key".to_vec(),
            0,
            format!(
                "{UNPARSABLE}asn1: structure error: tags don't match (16 vs {{class:1 tag:14 length:111 isCompound:true}}) {PARAMETERS} pkcs8 @2"
            ),
            None,
        ),
        (
            "an empty block",
            "PRIVATE KEY",
            Vec::new(),
            0,
            format!("{UNPARSABLE}asn1: syntax error: sequence truncated"),
            None,
        ),
        (
            "PKCS#8 P-256 cut short",
            "PRIVATE KEY",
            p256.marshal_pkcs8().expect("marshal")[..20].to_vec(),
            0,
            format!("{UNPARSABLE}asn1: syntax error: data truncated"),
            None,
        ),
        (
            "PKCS#8 of an unknown algorithm",
            "PRIVATE KEY",
            pkcs8(&[&[0x06, 0x03, 0x2a, 0x03, 0x04]], &[0x04, 0x00]),
            0,
            format!(
                "{UNPARSABLE}x509: PKCS#8 wrapping contained private key with unknown algorithm: 1.2.3.4"
            ),
            None,
        ),
        (
            "PKCS#8 Ed25519, a seed of 31 bytes",
            "PRIVATE KEY",
            pkcs8(&[ED25519], &tlv(0x04, &[7; 31])),
            3,
            format!("{UNPARSABLE}x509: invalid Ed25519 private key length: 31"),
            None,
        ),
        (
            "PKCS#8 P-256, a zero scalar",
            "PRIVATE KEY",
            pkcs8(&[EC_PUBLIC_KEY, P256], &sec1(1, &[0; 32], None, None)),
            0,
            format!(
                "{UNPARSABLE}x509: failed to parse EC private key embedded in PKCS#8: ecdsa: invalid public key encoding"
            ),
            None,
        ),
        (
            "PKCS#8 P-256, the order as its scalar",
            "PRIVATE KEY",
            pkcs8(
                &[EC_PUBLIC_KEY, P256],
                &sec1(1, &dcroxide_testutil::unhex(P256_ORDER), None, None),
            ),
            0,
            format!(
                "{UNPARSABLE}x509: failed to parse EC private key embedded in PKCS#8: ecdsa: invalid public key encoding"
            ),
            None,
        ),
        (
            "PKCS#8 P-256, a scalar of 33 bytes",
            "PRIVATE KEY",
            pkcs8(
                &[EC_PUBLIC_KEY, P256],
                &sec1(1, &[&[1][..], &s256].concat(), None, None),
            ),
            0,
            format!(
                "{UNPARSABLE}x509: failed to parse EC private key embedded in PKCS#8: x509: invalid private key length"
            ),
            None,
        ),
        (
            "PKCS#8 EC on secp256k1",
            "PRIVATE KEY",
            pkcs8(&[EC_PUBLIC_KEY, SECP256K1], &sec1(1, &s256, None, None)),
            0,
            format!(
                "{UNPARSABLE}x509: failed to parse EC private key embedded in PKCS#8: x509: unknown elliptic curve"
            ),
            None,
        ),
        (
            "SEC 1 of version 2",
            "EC PRIVATE KEY",
            sec1(2, &s256, Some(P256), None),
            0,
            format!(
                "{UNPARSABLE}x509: failed to parse private key (use ParseECPrivateKey instead for this key format)"
            ),
            None,
        ),
        (
            "SEC 1 naming no curve",
            "EC PRIVATE KEY",
            sec1(1, &s256, None, Some(&pub256)),
            0,
            format!(
                "{UNPARSABLE}x509: failed to parse private key (use ParseECPrivateKey instead for this key format)"
            ),
            None,
        ),
        (
            "PKCS#8 ML-DSA-65, an unknown tag",
            "PRIVATE KEY",
            pkcs8(&[ML_DSA_65], &[0x05, 0x00]),
            0,
            format!("{UNPARSABLE}x509: invalid ML-DSA private key: invalid ASN.1 tag 05"),
            None,
        ),
        (
            "PKCS#8 X25519",
            "PRIVATE KEY",
            pkcs8(&[X25519], &tlv(0x04, &[9; 32])),
            0,
            "refused: tls: found unknown private key type in PKCS#8 wrapping".into(),
            None,
        ),
        // The keys Go loads that gencerts does not issue with.
        (
            "PKCS#1 RSA",
            "PRIVATE KEY",
            pkcs1.clone(),
            0,
            RSA_REFUSED.into(),
            Some(NOT_THE_TYPE),
        ),
        (
            "PKCS#8 RSA",
            "PRIVATE KEY",
            pkcs8(&[RSA_ENCRYPTION, NULL], &pkcs1),
            0,
            RSA_REFUSED.into(),
            Some(NOT_THE_TYPE),
        ),
        (
            "SEC 1 P-224",
            "EC PRIVATE KEY",
            sec1(1, &[1], Some(P224), None),
            0,
            "refused: unsupported private key: ECDSA P-224".into(),
            Some(NOT_THE_KEY),
        ),
        (
            "PKCS#8 ML-DSA-65 seed",
            "PRIVATE KEY",
            pkcs8(&[ML_DSA_65], &tlv(0x80, &[3; 32])),
            0,
            "refused: unsupported private key: ML-DSA-65".into(),
            Some(NOT_THE_TYPE),
        ),
        // Keys that are not the certificate's.
        (
            "another P-256 key",
            "PRIVATE KEY",
            other_p256.marshal_pkcs8().expect("marshal"),
            0,
            NOT_THE_KEY.into(),
            None,
        ),
        (
            "a P-384 key for a P-256 certificate",
            "PRIVATE KEY",
            p384.marshal_pkcs8().expect("marshal"),
            0,
            NOT_THE_KEY.into(),
            None,
        ),
        (
            "an Ed25519 key for a P-256 certificate",
            "PRIVATE KEY",
            ed.marshal_pkcs8().expect("marshal"),
            0,
            NOT_THE_TYPE.into(),
            None,
        ),
        (
            "a P-256 key for an Ed25519 certificate",
            "PRIVATE KEY",
            p256.marshal_pkcs8().expect("marshal"),
            3,
            NOT_THE_TYPE.into(),
            None,
        ),
        (
            "an Ed25519 key for a certificate of an X25519 key",
            "PRIVATE KEY",
            ed.marshal_pkcs8().expect("marshal"),
            4,
            "refused: tls: unknown public key algorithm".into(),
            None,
        ),
        (
            "a P-256 key for an RSA certificate",
            "PRIVATE KEY",
            p256.marshal_pkcs8().expect("marshal"),
            5,
            NOT_THE_TYPE.into(),
            None,
        ),
        (
            "a P-256 key for an ML-DSA-44 certificate",
            "PRIVATE KEY",
            p256.marshal_pkcs8().expect("marshal"),
            6,
            NOT_THE_TYPE.into(),
            None,
        ),
        (
            "a P-256 key for an ML-DSA-65 certificate",
            "PRIVATE KEY",
            p256.marshal_pkcs8().expect("marshal"),
            7,
            NOT_THE_TYPE.into(),
            None,
        ),
        (
            "a P-256 key for an ML-DSA-87 certificate",
            "PRIVATE KEY",
            p256.marshal_pkcs8().expect("marshal"),
            8,
            NOT_THE_TYPE.into(),
            None,
        ),
    ];

    let mut oracle = dcroxide_testutil::oracle_or_skip();
    let mut wrong = Vec::new();
    for (what, label, der, cert, want, go_want) in &rows {
        let key_pem = pem(label, der);
        let port = port_pair(&certs[*cert], &key_pem);
        if port != *want {
            wrong.push(format!("{what}: the port answers {port:?}, not {want:?}"));
        }
        if let Some(oracle) = oracle.as_mut() {
            let go = go_pair(oracle, &certs[*cert], &key_pem);
            let go_want = go_want.unwrap_or(want);
            if go != go_want {
                wrong.push(format!("{what}: Go answers {go:?}, not {go_want:?}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
