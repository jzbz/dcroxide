// SPDX-License-Identifier: ISC
//! This crate's verdicts against Go's, through the oracle (ADR-0015 T10):
//! what dcrd's `crypto/tls` would do with the same input.
//!
//! For key exchange, on all four groups: each takes and refuses the shares
//! Go's `crypto/ecdh` takes and refuses, the generated ones of
//! `kx_shares`, and agrees Go's secret over a fresh key share of its own.
//! P-521 is the group these tests mattered most for while ring was in the
//! tree, since ring had none to hold it to; Wycheproof's vectors go
//! through Go too, in the crate's unit tests, where a vector's private key
//! can be set.
//!
//! For key loading: `sign::load_der` reads each key of `key_corpus` as
//! Go's `tls.X509KeyPair` reads it under its PEM label, the key and its
//! type where Go loads it, Go's text where Go refuses it, the cause after
//! "tls: failed to parse private key: " whole; the RSA, P-224 and ML-DSA
//! keys Go reads are refused with this crate's texts.  Mutations of every
//! key are held to Go's answers the same way, a sample of them in each run
//! and all of them in the nightly job.  And Ed25519, which is
//! deterministic, signs as Go's `ed25519.Sign` signs, byte for byte.
//!
//! For verification: each of the fourteen algorithms gives Go's verdict,
//! through the oracle's `sig_verify`, on every generated case of the
//! parity corpus (`sig_corpus`), as Go checks a certificate's signature and
//! as its `crypto/tls` checks a handshake's under each signature scheme
//! the algorithm serves, and Go's verdict is still the one the corpus
//! recorded; but in the classes `sig_corpus::GO_DIFFERS` lists, RSA keys
//! outside ring's bounds and Go's and an `RSAPublicKey` with bytes after
//! its values, where the provider keeps ring's differences from Go until
//! Go's client-certificate set (ADR-0015, T4; `GO_DIFFERS` says where
//! PARITY.md records them).  Wycheproof's cases, which the corpus
//! holds too, are held to Go case by case in the crate's unit tests.
//! ML-DSA's three algorithms, which ring never had and the corpus does not
//! hold, give Go's verdict on Go's own signatures and the crate's, and on
//! signatures mutated in each field FIPS 204's decoding checks, under each
//! set's x509 name and TLS scheme.
//!
//! Without an oracle the tests skip, unless `DCROXIDE_REQUIRE_ORACLE` is
//! set, as in CI, where they also require the reference Go.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

mod key_corpus;
mod kx_shares;
mod sig_corpus;

use std::collections::{BTreeMap, HashMap};

use curve25519_dalek::montgomery::MontgomeryPoint;
use dcroxide_testutil::{Oracle, SplitMix64, hex, unhex};
use dcroxide_tlscrypto::sign::{self, KeyAlgorithm};
use p256::elliptic_curve::sec1::ToSec1Point;
use rustls::crypto::SupportedKxGroup;
use rustls::{Error, NamedGroup, PeerMisbehaved};

/// A group as these tests put it beside Go's.
struct Paired {
    /// This crate's group.
    group: &'static dyn SupportedKxGroup,
    /// The curve's name in the oracle's `ecdh`.
    curve: &'static str,
    /// The fixed private key Go takes for it.
    private: Vec<u8>,
    /// That key's public key, as a key share carries it.
    public: Vec<u8>,
}

/// The four groups.  Go's fixed keys are `0x01` repeated at the field's
/// length, below each curve's order, and X25519's at 32 bytes.
fn groups() -> [Paired; 4] {
    use dcroxide_tlscrypto::kx_group;
    let p256 = p256::NonZeroScalar::from_repr(p256::FieldBytes::from([1; 32]))
        .into_option()
        .expect("below the order");
    let p384 = p384::NonZeroScalar::from_repr(p384::FieldBytes::from([1; 48]))
        .into_option()
        .expect("below the order");
    let p521 = p521::NonZeroScalar::from_repr(p521::FieldBytes::from([1; 66]))
        .into_option()
        .expect("below the order");
    [
        Paired {
            group: kx_group::X25519,
            curve: "X25519",
            private: vec![1; 32],
            public: MontgomeryPoint::mul_base_clamped([1; 32])
                .to_bytes()
                .to_vec(),
        },
        Paired {
            group: kx_group::SECP256R1,
            curve: "P-256",
            private: vec![1; 32],
            public: p256::PublicKey::from_secret_scalar(&p256)
                .to_sec1_point(false)
                .as_bytes()
                .to_vec(),
        },
        Paired {
            group: kx_group::SECP384R1,
            curve: "P-384",
            private: vec![1; 48],
            public: p384::PublicKey::from_secret_scalar(&p384)
                .to_sec1_point(false)
                .as_bytes()
                .to_vec(),
        },
        Paired {
            group: kx_group::SECP521R1,
            curve: "P-521",
            private: vec![1; 66],
            public: p521::PublicKey::from_secret_scalar(&p521)
                .to_sec1_point(false)
                .as_bytes()
                .to_vec(),
        },
    ]
}

/// Go's answer to a key share: the secret `private` agrees with `public`
/// on `curve`, or `None` where Go refuses the share.
fn go_ecdh(oracle: &mut Oracle, curve: &str, private: &[u8], public: &[u8]) -> Option<Vec<u8>> {
    let request = serde_json::json!({
        "curve": curve,
        "private": hex(private),
        "public": hex(public),
    });
    let response = oracle.call("ecdh", request.to_string().as_bytes());
    dcroxide_testutil::require_reference_go(response["go_version"].as_str().unwrap_or_default());
    match response["result"].as_str() {
        Some(refused) if refused.starts_with("refused: ") => None,
        Some(secret) => Some(unhex(secret)),
        None => panic!("the oracle answered {response}"),
    }
}

/// Each group takes exactly the shares Go takes, and refuses the others
/// as an invalid key share.  A share's verdict depends on the share
/// alone, so this crate's fresh key and Go's fixed one judge the same
/// thing.  A few verdicts are also checked by name, so that a corpus gone
/// wrong, say with every share off the curve, cannot pass on agreement
/// alone.
#[test]
fn each_group_takes_the_shares_go_takes() {
    let Some(mut oracle) = dcroxide_testutil::oracle_or_skip() else {
        return;
    };
    for Paired {
        group,
        curve,
        private,
        ..
    } in groups()
    {
        let name = group.name();
        let mut verdicts = HashMap::new();
        for (label, share) in kx_shares::shares(name) {
            let go = go_ecdh(&mut oracle, curve, &private, &share).is_some();
            let ours = group.start().expect("started").complete(&share);
            if let Err(err) = &ours {
                assert_eq!(
                    *err,
                    Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare),
                    "{name:?}, {label}"
                );
            }
            assert_eq!(ours.is_ok(), go, "{name:?}, {label}");
            verdicts.insert(label, go);
        }
        let named: &[(&str, bool)] = if name == NamedGroup::X25519 {
            &[
                ("32 bytes under 0x04", true),
                ("9, the base point", true),
                ("p + 9, the base point, top bit set", true),
                ("2, on the twist", true),
                ("0, of order 2", false),
                ("of order 8, top bit set", false),
                ("p + 1, which is 1", false),
                ("31 bytes under 0x04", false),
            ]
        } else {
            &[
                ("the point at x = 0, x written as 0", true),
                ("the point at x = 0, x written as p", false),
                ("the point at x = 0, x written as p + 1", false),
                ("the generator with a bit of y flipped", false),
                ("the generator's x with y written as p", false),
                ("1 bytes under 0x00", false),
            ]
        };
        for (label, taken) in named {
            assert_eq!(verdicts.get(*label), Some(taken), "{name:?}, {label}");
        }
        let taken = verdicts.values().filter(|&&taken| taken).count();
        let refused = verdicts.len() - taken;
        assert!(
            taken >= 2 && refused > 900,
            "{name:?}: {taken} taken, {refused} refused"
        );
    }
}

/// Each group agrees Go's secret: this crate's exchange completed with
/// the public key of Go's fixed private key gives what Go agrees with the
/// exchange's own key share.
#[test]
fn each_group_agrees_gos_secret() {
    let Some(mut oracle) = dcroxide_testutil::oracle_or_skip() else {
        return;
    };
    for Paired {
        group,
        curve,
        private,
        public,
    } in groups()
    {
        for _ in 0..8 {
            let ours = group.start().expect("started");
            let go = go_ecdh(&mut oracle, curve, &private, ours.pub_key())
                .unwrap_or_else(|| panic!("{curve}: Go refused a fresh key share"));
            let agreed = ours.complete(&public).expect("Go's public key taken");
            assert_eq!(agreed.secret_bytes(), go, "{curve}");
        }
    }
}

/// `der` as a PEM block of `label`: base64 in lines of 64 characters.
fn pem(label: &str, der: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut base64 = String::new();
    for chunk in der.chunks(3) {
        let bytes = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let bits = u32::from(bytes[0]) << 16 | u32::from(bytes[1]) << 8 | u32::from(bytes[2]);
        for (i, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            base64.push(if i <= chunk.len() {
                char::from(ALPHABET[(bits >> shift & 0x3f) as usize])
            } else {
                '='
            });
        }
    }
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in base64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// Go's prefix for a key none of its parsers reads, before the PKCS#8
/// parser's error (`crypto/tls/tls.go:371`).
const UNPARSABLE: &str = "tls: failed to parse private key: ";

/// Go's answers for a key it read and then found not to be the
/// certificate's, of the certificate's type and of another
/// (`crypto/tls/tls.go:318-353`).
const GO_READ_ANOTHER_KEY: [&str; 2] = [
    "refused: tls: private key does not match public key",
    "refused: tls: private key type does not match public key type",
];

/// Go's verdict on a certificate and a key: `tls.X509KeyPair` on the
/// certificate's PEM and the key's under `label`.
fn go_key_pair(oracle: &mut Oracle, cert: &[u8], label: &str, key: &[u8]) -> String {
    let request = serde_json::json!({
        "cert_pem": pem("CERTIFICATE", cert),
        "key_pem": pem(label, key),
    });
    let response = oracle.call("x509_key_pair", request.to_string().as_bytes());
    dcroxide_testutil::require_reference_go(response["go_version"].as_str().unwrap_or_default());
    response["result"]
        .as_str()
        .unwrap_or_else(|| panic!("the oracle answered {response}"))
        .to_owned()
}

/// Go's verdicts on many keys, each under `label`, in order, through the
/// oracle's `x509_key_pairs`: each against `cert`, or against the
/// certificate of the same index in `certs` where one is given there.
fn go_key_pairs(
    oracle: &mut Oracle,
    cert: &[u8],
    label: &str,
    keys: &[Vec<u8>],
    certs: &[Option<Vec<u8>>],
) -> Vec<String> {
    let request = serde_json::json!({
        "cert_pem": pem("CERTIFICATE", cert),
        "label": label,
        "keys": keys.iter().map(|key| hex(key)).collect::<Vec<_>>(),
        "cert_pems": certs
            .iter()
            .map(|cert| cert.as_deref().map(|cert| pem("CERTIFICATE", cert)).unwrap_or_default())
            .collect::<Vec<_>>(),
    });
    let response = oracle.call("x509_key_pairs", request.to_string().as_bytes());
    dcroxide_testutil::require_reference_go(response["go_version"].as_str().unwrap_or_default());
    let answers: Vec<String> = response["detail"]
        .as_array()
        .unwrap_or_else(|| panic!("the oracle answered {response}"))
        .iter()
        .map(|answer| answer.as_str().expect("an answer").to_owned())
        .collect();
    assert_eq!(answers.len(), keys.len(), "an answer for each key");
    answers
}

/// Go's name for a key's type, in `x509_key_pair`'s answer.
fn go_type(algorithm: KeyAlgorithm) -> &'static str {
    match algorithm {
        KeyAlgorithm::EcdsaP256 => "ECDSA P-256",
        KeyAlgorithm::EcdsaP384 => "ECDSA P-384",
        KeyAlgorithm::EcdsaP521 => "ECDSA P-521",
        KeyAlgorithm::Ed25519 => "Ed25519",
        other => panic!("a key load_der loads cannot be {other:?}"),
    }
}

/// The RSA keys of the corpus Go refuses for their values: a CRT exponent
/// `Validate` finds wrong (`crypto/internal/fips140/rsa/rsa.go:236-250`)
/// and a prime `ParsePKCS1PrivateKey` finds negative
/// (`crypto/x509/pkcs1.go:74-79`).  Both are PKCS#1, which Go then refuses
/// with the PKCS#8 parser's error, [`RSA_GO_REFUSES_WITH`].  This crate,
/// which signs with no RSA key, reads their structure alone and refuses
/// them with its own text.  Go loads the key with an additional prime: a
/// key of more than two primes is checked through N, E and D alone
/// (`crypto/rsa/rsa.go:571-572`, `:610-617`).
const RSA_GO_REFUSES: &[&str] = &[
    "RSA, PKCS#1, a CRT exponent wrong",
    "RSA, PKCS#1, P negative",
];

/// Go's answer to the keys of [`RSA_GO_REFUSES`]: the PKCS#8 parser's
/// hint for a PKCS#1 structure (`crypto/x509/pkcs8.go:46`), the error
/// `parsePrivateKey` keeps (`crypto/tls/tls.go:362-372`).
const RSA_GO_REFUSES_WITH: &str = "refused: tls: failed to parse private key: x509: failed to \
                                   parse private key (use ParsePKCS1PrivateKey instead for \
                                   this key format)";

/// A refusal's cause as the corpus's tally counts it: Go's parameter dump,
/// the same in every "tags don't match" text (`src/keys.rs`), as `{P}`,
/// and each number that is not part of a name (`asn1`, `PKCS#8`,
/// `ASN.1`) as `N`.
fn shape(cause: &str) -> String {
    const PARAMETERS: &str = "{optional:false explicit:false application:false private:false \
                              defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false \
                              omitEmpty:false}";
    let mut out = String::new();
    let mut previous = ' ';
    let mut number = false;
    for c in cause.replace(PARAMETERS, "{P}").chars() {
        let named = previous.is_ascii_alphanumeric() || previous == '#' || out.ends_with("ASN.");
        if c.is_ascii_digit() && (number || !named) {
            if !number {
                out.push('N');
            }
            number = true;
        } else {
            out.push(c);
            number = false;
        }
        previous = c;
    }
    out
}

/// `load_der` reads every key of the corpus as Go's `tls.X509KeyPair`
/// does.  Where it loads a key, Go loads the same key, of the same type,
/// under the key's PEM label against a certificate made for the key
/// `load_der` gave, so a key Go reads with another scalar, on another
/// curve or of another type does not match.  Where it refuses one with
/// Go's text, the PKCS#8 parser's error after Go's prefix among them, Go
/// refuses it with that text, whole, against the certificate of the key
/// it was mutated from, which Go would load were the refusal wrong.  An
/// RSA key it refuses with its own text is loaded by Go, or refused by
/// Go's `Validate` (`RSA_GO_REFUSES`); a P-224 key is loaded by Go as
/// P-224; and an ML-DSA key, refused with this crate's interim text, is
/// read by Go and refused only as not the certificate's type.  The count
/// of each verdict is pinned too, a refusal's by the shape of its cause
/// ([`shape`]), so that a corpus gone wrong, a case lost or sent to
/// another verdict, cannot pass on agreement alone.
#[test]
fn keys_load_as_go_loads_them() {
    let Some(mut oracle) = dcroxide_testutil::oracle_or_skip() else {
        return;
    };
    let mut verdicts: BTreeMap<String, usize> = BTreeMap::new();
    let mut rsa_refused = Vec::new();
    for case in key_corpus::cases() {
        let label = &case.label;
        let verdict = match sign::load_der(&case.der) {
            Ok(key) => {
                let spki = key.public_key().expect("a public key");
                let algorithm = sign::key_algorithm(&case.der).expect("a key load_der loads");
                let cert = key_corpus::certificate(spki.as_ref());
                let go = go_key_pair(&mut oracle, &cert, case.pem_label, &case.der);
                let want = format!("ok {}", go_type(algorithm));
                assert_eq!(go, want, "{label}");
                want
            }
            Err(rustls::Error::General(text)) => {
                let go = go_key_pair(&mut oracle, &case.cert, case.pem_label, &case.der);
                if text == sign::RSA_KEY_REFUSED {
                    assert_eq!(
                        sign::key_algorithm(&case.der),
                        Some(KeyAlgorithm::Rsa),
                        "{label}"
                    );
                    if go == "ok RSA 2048" {
                        "RSA, which Go loads".to_owned()
                    } else {
                        assert_eq!(go, RSA_GO_REFUSES_WITH, "{label}");
                        rsa_refused.push(label.clone());
                        "RSA, which Go refuses".to_owned()
                    }
                } else if text == "unsupported private key: ECDSA P-224" {
                    assert_eq!(go, "ok ECDSA P-224", "{label}");
                    text
                } else if text.starts_with("unsupported private key: ML-DSA-") {
                    assert_eq!(go, GO_READ_ANOTHER_KEY[1], "{label}");
                    text
                } else {
                    assert_eq!(go, format!("refused: {text}"), "{label}");
                    match text.strip_prefix(UNPARSABLE) {
                        Some(cause) => shape(cause),
                        None => text,
                    }
                }
            }
            Err(other) => panic!("{label}: {other:?}"),
        };
        *verdicts.entry(verdict).or_default() += 1;
    }
    assert_eq!(rsa_refused, RSA_GO_REFUSES, "the RSA keys Go refuses");
    let expected: BTreeMap<String, usize> = [
        ("RSA, which Go loads", 12),
        ("RSA, which Go refuses", 2),
        ("asn1: structure error: base N integer too large", 1),
        ("asn1: structure error: integer not minimally-encoded", 15),
        ("asn1: structure error: non-minimal length", 3),
        ("asn1: structure error: superfluous leading zeros in length", 2),
        ("asn1: structure error: tags don't match (N vs {class:N tag:N length:N isCompound:false}) {P} AlgorithmIdentifier @N", 69),
        ("asn1: structure error: tags don't match (N vs {class:N tag:N length:N isCompound:false}) {P} int @N", 1),
        ("asn1: structure error: tags don't match (N vs {class:N tag:N length:N isCompound:true}) {P}  @N", 5),
        ("asn1: structure error: tags don't match (N vs {class:N tag:N length:N isCompound:true}) {P} AlgorithmIdentifier @N", 5),
        ("asn1: structure error: tags don't match (N vs {class:N tag:N length:N isCompound:true}) {P} pkcs8 @N", 5),
        ("asn1: syntax error: indefinite length found (not DER)", 5),
        ("asn1: syntax error: non-minimal tag", 1),
        ("asn1: syntax error: truncated base N integer", 10),
        ("crypto/ecdh: invalid private key size", 2),
        ("ok ECDSA P-256", 100),
        ("ok ECDSA P-384", 55),
        ("ok ECDSA P-521", 57),
        ("ok Ed25519", 9),
        ("tls: found unknown private key type in PKCS#8 wrapping", 1),
        ("unsupported private key: ECDSA P-224", 48),
        ("unsupported private key: ML-DSA-44", 1),
        ("unsupported private key: ML-DSA-65", 1),
        ("unsupported private key: ML-DSA-87", 1),
        ("x509: ML-DSA private keys with both seed and expanded key are not supported, use e.g. \"openssl pkey -provparam ml-dsa.output_formats=seed-only\" to convert to a seed-only key", 1),
        ("x509: PKCS#8 wrapping contained private key with unknown algorithm: N.N", 2),
        ("x509: PKCS#8 wrapping contained private key with unknown algorithm: N.N.N", 1),
        ("x509: PKCS#8 wrapping contained private key with unknown algorithm: N.N.N.N", 1),
        ("x509: PKCS#8 wrapping contained private key with unknown algorithm: N.N.N.N.N", 5),
        ("x509: failed to parse EC private key embedded in PKCS#8: ecdsa: invalid public key encoding", 10),
        ("x509: failed to parse EC private key embedded in PKCS#8: input overflows the modulus", 5),
        ("x509: failed to parse EC private key embedded in PKCS#8: x509: failed to parse EC private key: asn1: structure error: explicit tag has no child", 5),
        ("x509: failed to parse EC private key embedded in PKCS#8: x509: failed to parse EC private key: asn1: syntax error: invalid padding bits in BIT STRING", 1),
        ("x509: failed to parse EC private key embedded in PKCS#8: x509: failed to parse EC private key: asn1: syntax error: truncated base N integer", 5),
        ("x509: failed to parse EC private key embedded in PKCS#8: x509: failed to parse EC private key: asn1: syntax error: zero length BIT STRING", 1),
        ("x509: failed to parse EC private key embedded in PKCS#8: x509: failed to parse private key (use ParsePKCS1PrivateKey instead for this key format)", 1),
        ("x509: failed to parse EC private key embedded in PKCS#8: x509: failed to parse private key (use ParsePKCS8PrivateKey instead for this key format)", 1),
        ("x509: failed to parse EC private key embedded in PKCS#8: x509: invalid private key length", 7),
        ("x509: failed to parse EC private key embedded in PKCS#8: x509: unknown EC private key version N", 5),
        ("x509: failed to parse EC private key embedded in PKCS#8: x509: unknown elliptic curve", 15),
        ("x509: failed to parse RSA private key embedded in PKCS#8: asn1: structure error: integer not minimally-encoded", 1),
        ("x509: failed to parse RSA private key embedded in PKCS#8: asn1: syntax error: sequence truncated", 1),
        ("x509: failed to parse RSA private key embedded in PKCS#8: asn1: syntax error: trailing data", 1),
        ("x509: failed to parse RSA private key embedded in PKCS#8: x509: failed to parse private key (use ParseECPrivateKey instead for this key format)", 5),
        ("x509: failed to parse RSA private key embedded in PKCS#8: x509: failed to parse private key (use ParsePKCS8PrivateKey instead for this key format)", 1),
        ("x509: failed to parse RSA private key embedded in PKCS#8: x509: unsupported private key version", 1),
        ("x509: failed to parse private key (use ParseECPrivateKey instead for this key format)", 92),
        ("x509: failed to parse private key (use ParsePKCS1PrivateKey instead for this key format)", 2),
        ("x509: invalid Ed25519 private key length: N", 3),
        ("x509: invalid Ed25519 private key parameters", 2),
        ("x509: invalid Ed25519 private key: asn1: structure error: length too large", 1),
        ("x509: invalid Ed25519 private key: asn1: structure error: tags don't match (N vs {class:N tag:N length:N isCompound:false}) {P}  @N", 1),
        ("x509: invalid Ed25519 private key: asn1: structure error: tags don't match (N vs {class:N tag:N length:N isCompound:true}) {P}  @N", 1),
        ("x509: invalid ML-DSA private key ASN.1 encoding", 1),
        ("x509: invalid ML-DSA private key length: N", 2),
        ("x509: invalid ML-DSA private key parameters", 1),
        ("x509: invalid ML-DSA private key: invalid ASN.1 tag N", 1),
        ("x509: invalid X25519 private key parameters", 1),
        ("x509: invalid X25519 private key: asn1: structure error: tags don't match (N vs {class:N tag:N length:N isCompound:false}) {P}  @N", 1),
        ("x509: semi-expanded ML-DSA private keys without seed are not supported", 1),
    ]
    .into_iter()
    .map(|(verdict, count)| (verdict.to_owned(), count))
    .collect();
    assert_eq!(verdicts, expected, "the count of each verdict");
}

/// The mutations of a key the sweep makes, each with its name: every
/// truncation, a zero byte appended, and each of the first 64 bytes and
/// every seventh after them set in turn to 0x00, 0xff, itself with bit 5
/// or bit 7 flipped, and itself plus and less one, where that changes it.
fn mutations(der: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> = (0..der.len())
        .map(|len| (format!("trunc{len}"), der[..len].to_vec()))
        .collect();
    out.push(("append00".to_owned(), [der, &[0]].concat()));
    for (at, &byte) in der.iter().enumerate() {
        if at >= 64 && at % 7 != 0 {
            continue;
        }
        let values = [
            0x00,
            0xff,
            byte ^ 0x20,
            byte ^ 0x80,
            byte.wrapping_add(1),
            byte.wrapping_sub(1),
        ];
        for value in values {
            if value != byte {
                let mut mutated = der.to_vec();
                mutated[at] = value;
                out.push((format!("set{at}={value:02x}"), mutated));
            }
        }
    }
    out
}

/// The crate's answer to a key of the sweep: for a key `load_der` loads,
/// its type and a certificate made for the public key it gave, which Go
/// loads the key against only if it reads the same key; for one it
/// refuses, the text.
type SweepAnswer = Result<(KeyAlgorithm, Vec<u8>), String>;

/// `load_der`'s answer to `der`, as the sweep compares it.
fn sweep_answer(der: &[u8]) -> SweepAnswer {
    match sign::load_der(der) {
        Ok(key) => {
            let spki = key.public_key().expect("a public key");
            let algorithm = sign::key_algorithm(der).expect("a key load_der loads");
            Ok((algorithm, key_corpus::certificate(spki.as_ref())))
        }
        Err(rustls::Error::General(text)) => Err(text),
        Err(other) => Err(format!("{other:?}")),
    }
}

/// Whether Go's answer refuses an RSA key for its values, which is how
/// Go refuses a key this crate refuses as RSA, reading its structure
/// alone: the PKCS#8 parser's hint for a PKCS#1 key,
/// [`RSA_GO_REFUSES_WITH`], or, for one inside PKCS#8, `crypto/rsa`'s
/// error or `crypto/x509`'s for a value that is not positive
/// (`crypto/x509/pkcs8.go:51-54`, `crypto/x509/pkcs1.go:74-79`, `:95-97`,
/// `:104-119`).
fn go_refuses_rsa_values(go: &str) -> bool {
    const EMBEDDED: &str = "refused: tls: failed to parse private key: x509: failed to parse \
                            RSA private key embedded in PKCS#8: ";
    go == RSA_GO_REFUSES_WITH
        || go.strip_prefix(EMBEDDED).is_some_and(|cause| {
            cause.starts_with("crypto/rsa: ")
                || cause.starts_with("x509: private key contains zero or negative ")
        })
}

/// Whether the crate's answer to a key agrees with Go's, and in which
/// class: a key it loads, one Go loads, of the same type, against a
/// certificate made for the public key the crate gave; and against the
/// certificate of the corpus case the key was mutated from, a refusal in
/// Go's words, the same text; an RSA key, one Go reads, or refuses for
/// its values ([`go_refuses_rsa_values`]), which Go checks and this
/// crate does not; and the P-224 and ML-DSA keys it refuses with its own
/// text, keys Go reads.  The text it gives is the error.
fn sweep_class(ours: &SweepAnswer, go: &str) -> Result<&'static str, String> {
    let read_another = GO_READ_ANOTHER_KEY.contains(&go);
    match ours {
        Ok((algorithm, _)) => {
            if go.strip_prefix("ok ") == Some(go_type(*algorithm)) {
                Ok("loaded, the key Go reads")
            } else {
                Err(format!("loaded as {algorithm:?}"))
            }
        }
        Err(text) => {
            let class = if text == sign::RSA_KEY_REFUSED {
                if go.starts_with("ok RSA ") || go == GO_READ_ANOTHER_KEY[0] {
                    Some("RSA, which Go reads")
                } else if go_refuses_rsa_values(go) {
                    Some("RSA, which Go refuses")
                } else {
                    None
                }
            } else if text == "unsupported private key: ECDSA P-224" {
                (go == "ok ECDSA P-224" || read_another).then_some("P-224, which Go reads")
            } else if text.starts_with("unsupported private key: ML-DSA-") {
                (go == GO_READ_ANOTHER_KEY[1]).then_some("ML-DSA, which Go reads")
            } else {
                (go == format!("refused: {text}")).then_some("refused in Go's words")
            };
            class.ok_or_else(|| text.clone())
        }
    }
}

/// How many of the sweep's inputs one is compared:
/// `DCROXIDE_KEY_SWEEP_EVERY`, one in ten by default, 1 for every input,
/// as the nightly job runs it.
fn sweep_every() -> u64 {
    match std::env::var("DCROXIDE_KEY_SWEEP_EVERY") {
        Ok(every) => {
            let every = every.parse().expect("DCROXIDE_KEY_SWEEP_EVERY is a count");
            assert!(every > 0, "DCROXIDE_KEY_SWEEP_EVERY is at least 1");
            every
        }
        Err(_) => 10,
    }
}

/// `load_der` answers mutations of every key of the corpus as Go's
/// `tls.X509KeyPair` does ([`sweep_class`]), Go given each under its
/// case's PEM label, through the oracle's `x509_key_pairs`, against a
/// certificate made for the key `load_der` gave where it loads one and
/// against its case's certificate where it refuses one: in every run a
/// sample of one input in ten
/// drawn from a fixed generator, the same sample each time, and in the
/// nightly job every input (`DCROXIDE_KEY_SWEEP_EVERY`).  Go's answers
/// come from the oracle as the test runs, so no answer is frozen in the
/// tree.  The count of inputs is pinned, so that a generator gone wrong
/// cannot pass on agreement alone, and each class must show.
#[test]
fn mutated_keys_load_as_go_loads_them() {
    let Some(mut oracle) = dcroxide_testutil::oracle_or_skip() else {
        return;
    };
    let every = sweep_every();
    let mut rng = SplitMix64(0x6b65_7973_7765_6570);
    let mut classes: BTreeMap<&str, usize> = BTreeMap::new();
    let mut differ = Vec::new();
    let mut inputs = 0;
    for case in key_corpus::cases() {
        let mutated = mutations(&case.der);
        inputs += mutated.len();
        let sample: Vec<(String, Vec<u8>)> = mutated
            .into_iter()
            .filter(|_| rng.below(every) == 0)
            .collect();
        if sample.is_empty() {
            continue;
        }
        let ours: Vec<SweepAnswer> = sample.iter().map(|(_, der)| sweep_answer(der)).collect();
        let keys: Vec<Vec<u8>> = sample.iter().map(|(_, der)| der.clone()).collect();
        let certs: Vec<Option<Vec<u8>>> = ours
            .iter()
            .map(|ours| ours.as_ref().ok().map(|(_, cert)| cert.clone()))
            .collect();
        let answers = go_key_pairs(&mut oracle, &case.cert, case.pem_label, &keys, &certs);
        for (((name, _), ours), go) in sample.iter().zip(&ours).zip(&answers) {
            match sweep_class(ours, go) {
                Ok(class) => *classes.entry(class).or_default() += 1,
                Err(ours) => differ.push(format!("{}|{name}: {ours}; Go: {go}", case.label)),
            }
        }
    }
    let compared: usize = classes.values().sum::<usize>() + differ.len();
    eprintln!("{compared} of {inputs} inputs compared, one in {every}: {classes:?}");
    assert!(
        differ.is_empty(),
        "{} differ:\n{}",
        differ.len(),
        differ.join("\n")
    );
    assert_eq!(inputs, 385_653, "the sweep's inputs");
    for class in [
        "loaded, the key Go reads",
        "RSA, which Go reads",
        "RSA, which Go refuses",
        "P-224, which Go reads",
        "ML-DSA, which Go reads",
        "refused in Go's words",
    ] {
        assert!(classes.contains_key(class), "no input of the class {class}");
    }
}

/// Ed25519 signs as Go's `ed25519.Sign`, byte for byte, through the
/// oracle's `sig_sign`: the corpus's Ed25519 key and keys from seeds a
/// fixed generator draws, each over messages from empty to longer than a
/// SHA-512 block, the key's public key first held to the corpus's.
#[test]
fn ed25519_signs_as_go_signs() {
    let Some(mut oracle) = dcroxide_testutil::oracle_or_skip() else {
        return;
    };
    let mut keys: Vec<Vec<u8>> = key_corpus::base_keys()
        .into_iter()
        .filter(|base| base.name == "Ed25519")
        .map(|base| {
            let key = sign::load_der(&base.pkcs8).expect("the Ed25519 base key");
            assert_eq!(
                key.public_key().expect("its public key").as_ref(),
                &base.spki[..]
            );
            base.pkcs8
        })
        .collect();
    assert_eq!(keys.len(), 1, "the corpus's Ed25519 key");
    let mut rng = SplitMix64(0x5195_2026_1026);
    for _ in 0..7 {
        let mut seed = [0; 32];
        rng.fill(&mut seed);
        let algorithm = key_corpus::tlv(0x30, &key_corpus::tlv(0x06, &[0x2b, 0x65, 0x70]));
        keys.push(key_corpus::seq(&[
            &key_corpus::tlv(0x02, &[0]),
            &algorithm,
            &key_corpus::tlv(0x04, &key_corpus::tlv(0x04, &seed)),
        ]));
    }
    for pkcs8 in keys {
        let signer = sign::load_der(&pkcs8)
            .expect("an Ed25519 key")
            .choose_scheme(&[rustls::SignatureScheme::ED25519])
            .expect("ED25519");
        for len in [0, 1, 32, 64, 127, 128, 129, 1000] {
            let mut message = vec![0; len];
            rng.fill(&mut message);
            let request = serde_json::json!({
                "key_pkcs8": hex(&pkcs8),
                "scheme": "Ed25519",
                "message": hex(&message),
            });
            let response = oracle.call("sig_sign", request.to_string().as_bytes());
            dcroxide_testutil::require_reference_go(
                response["go_version"].as_str().unwrap_or_default(),
            );
            let go = response["result"]
                .as_str()
                .unwrap_or_else(|| panic!("the oracle answered {response}"));
            assert_eq!(
                hex(&signer.sign(&message).expect("signed")),
                go,
                "a message of {len}"
            );
        }
    }
}

/// Go's `tls.SignatureScheme` name for each scheme of the provider's
/// mapping.
fn go_scheme(scheme: rustls::SignatureScheme) -> &'static str {
    use rustls::SignatureScheme as S;
    match scheme {
        S::ECDSA_NISTP256_SHA256 => "ECDSAWithP256AndSHA256",
        S::ECDSA_NISTP384_SHA384 => "ECDSAWithP384AndSHA384",
        S::ED25519 => "Ed25519",
        S::RSA_PKCS1_SHA256 => "PKCS1WithSHA256",
        S::RSA_PKCS1_SHA384 => "PKCS1WithSHA384",
        S::RSA_PKCS1_SHA512 => "PKCS1WithSHA512",
        S::RSA_PSS_SHA256 => "PSSWithSHA256",
        S::RSA_PSS_SHA384 => "PSSWithSHA384",
        S::RSA_PSS_SHA512 => "PSSWithSHA512",
        other => panic!("no scheme of the mapping: {other:?}"),
    }
}

/// The SubjectPublicKeyInfo of `key` for the algorithm at `algorithm`, as a
/// certificate would carry it, which is how Go is given a key.
fn spki(algorithm: usize, key: &[u8]) -> Vec<u8> {
    rustls::sign::public_key_to_spki(&sig_corpus::ours(algorithm).public_key_alg_id(), key)
        .as_ref()
        .to_vec()
}

/// Go's verdict on a case, through the oracle's `sig_verify`: the key as a
/// SubjectPublicKeyInfo, checked as Go checks a certificate's signature
/// under the algorithm's x509 name.
fn go_verifies(
    oracle: &mut Oracle,
    algorithm: usize,
    key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    let request = serde_json::json!({
        "spki": hex(&spki(algorithm, key)),
        "x509_alg": sig_corpus::ALGORITHMS[algorithm].1,
        "message": hex(message),
        "signature": hex(signature),
    });
    let response = oracle.call("sig_verify", request.to_string().as_bytes());
    dcroxide_testutil::require_reference_go(response["go_version"].as_str().unwrap_or_default());
    match response["result"].as_str() {
        Some("ok") => true,
        Some(refused) if refused.starts_with("refused: ") => false,
        _ => panic!("the oracle answered {response}"),
    }
}

/// Go's verdict on a case as its `crypto/tls` checks a handshake signature
/// under `scheme`, through the oracle's `sig_verify`.
fn go_verifies_handshake(
    oracle: &mut Oracle,
    scheme: rustls::SignatureScheme,
    case: &sig_corpus::Case,
) -> bool {
    let request = serde_json::json!({
        "spki": hex(&spki(case.algorithm, &case.key)),
        "tls_scheme": go_scheme(scheme),
        "message": hex(&case.message),
        "signature": hex(&case.signature),
    });
    let response = oracle.call("sig_verify", request.to_string().as_bytes());
    dcroxide_testutil::require_reference_go(response["go_version"].as_str().unwrap_or_default());
    match response["result"].as_str() {
        Some("ok") => true,
        Some(refused) if refused.starts_with("refused: ") => false,
        _ => panic!("{}: the oracle answered {response}", case.label),
    }
}

/// Each algorithm gives Go's verdict on every generated case of the parity
/// corpus: Go's as it checks a certificate's signature, which is still the
/// verdict the corpus recorded, and Go's as its `crypto/tls` checks a
/// handshake signature under each scheme the provider's mapping serves the
/// algorithm under; but in the classes of `GO_DIFFERS`, each of which has
/// a case where Go's verdict differs, so that an entry no longer needed
/// shows.  The provider gives the recorded Go verdict on Wycheproof's
/// cases too.  The count of cases Go takes is pinned, so that a corpus
/// gone wrong cannot pass on agreement alone.
#[test]
fn signatures_verify_as_go_verifies_them() {
    let Some(mut oracle) = dcroxide_testutil::oracle_or_skip() else {
        return;
    };
    let mapping = dcroxide_tlscrypto::SUPPORTED_SIG_ALGS.mapping;
    let mut differs: BTreeMap<&str, usize> = BTreeMap::new();
    let (mut taken, mut generated, mut handshakes) = (0, 0, 0);
    for case in sig_corpus::cases() {
        let ours = sig_corpus::ours(case.algorithm)
            .verify_signature(&case.key, &case.message, &case.signature)
            .is_ok();
        // Where Go differs, it differs from ring, whose verdict the
        // provider gives (`tests/recorded_parity.rs` holds every case to
        // the verdict recorded from ring).
        assert_eq!(ours, case.ring, "{}: ring's recorded verdict", case.label);
        let allowed = sig_corpus::GO_DIFFERS
            .iter()
            .find(|(class, _)| *class == case.class)
            .map(|(class, _)| *class);
        let label = &case.label;
        if case.class != "wycheproof" {
            let go = go_verifies(
                &mut oracle,
                case.algorithm,
                &case.key,
                &case.message,
                &case.signature,
            );
            assert_eq!(go, case.go, "{label}: Go's verdict, as recorded");
            let name = sig_corpus::ALGORITHMS[case.algorithm].0;
            for (scheme, algorithms) in mapping {
                if algorithms
                    .iter()
                    .any(|algorithm| format!("{algorithm:?}") == name)
                {
                    let handshake = go_verifies_handshake(&mut oracle, *scheme, &case);
                    assert_eq!(handshake, go, "{label}: Go's verdict under {scheme:?}");
                    handshakes += 1;
                }
            }
            generated += 1;
            taken += usize::from(go);
        }
        match allowed {
            Some(class) => *differs.entry(class).or_default() += usize::from(ours != case.go),
            None => assert_eq!(ours, case.go, "{label}: Go's verdict"),
        }
    }
    for (class, _) in sig_corpus::GO_DIFFERS {
        assert!(
            differs.get(class).is_some_and(|&count| count > 0),
            "{class}: no case where Go's verdict differs"
        );
    }
    assert_eq!(
        (generated, taken),
        (1087, 187),
        "generated cases, and those Go takes"
    );
    // Every generated case but those of the three algorithms the mapping
    // does not list, PKCS#1 v1.5 under the identifiers without NULL.
    assert_eq!(handshakes, 929, "handshake verdicts asked of Go");
}

/// An ML-DSA parameter set as these tests take it: the provider's
/// algorithm and scheme, Go's x509 and TLS names, the last byte of its
/// OID, and the layout of its signatures (FIPS 204, table 2): c̃'s bytes,
/// the bits of each of z's coefficients, β = τη, and the hint's ω and k.
struct MlDsaSet {
    algorithm: &'static dyn rustls::pki_types::SignatureVerificationAlgorithm,
    scheme: rustls::SignatureScheme,
    x509: &'static str,
    tls: &'static str,
    oid: u8,
    c_tilde: usize,
    z_bits: usize,
    beta: u32,
    omega: usize,
    k: usize,
}

/// The three sets.
fn ml_dsa_sets() -> [MlDsaSet; 3] {
    use dcroxide_tlscrypto::verify;
    use rustls::SignatureScheme as S;
    [
        MlDsaSet {
            algorithm: verify::ML_DSA_44,
            scheme: S::ML_DSA_44,
            x509: "ML-DSA-44",
            tls: "MLDSA44",
            oid: 0x11,
            c_tilde: 32,
            z_bits: 18,
            beta: 78,
            omega: 80,
            k: 4,
        },
        MlDsaSet {
            algorithm: verify::ML_DSA_65,
            scheme: S::ML_DSA_65,
            x509: "ML-DSA-65",
            tls: "MLDSA65",
            oid: 0x12,
            c_tilde: 48,
            z_bits: 20,
            beta: 196,
            omega: 55,
            k: 6,
        },
        MlDsaSet {
            algorithm: verify::ML_DSA_87,
            scheme: S::ML_DSA_87,
            x509: "ML-DSA-87",
            tls: "MLDSA87",
            oid: 0x13,
            c_tilde: 64,
            z_bits: 20,
            beta: 120,
            omega: 75,
            k: 8,
        },
    ]
}

impl MlDsaSet {
    /// The set's AlgorithmIdentifier, its OID alone.
    fn algorithm_identifier(&self) -> Vec<u8> {
        key_corpus::seq(&[&key_corpus::tlv(
            0x06,
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, self.oid],
        )])
    }

    /// The PKCS#8 seed form of the key from `seed`, as Go writes it.
    fn pkcs8(&self, seed: &[u8; 32]) -> Vec<u8> {
        key_corpus::seq(&[
            &key_corpus::tlv(0x02, &[0]),
            &self.algorithm_identifier(),
            &key_corpus::tlv(0x04, &[&[0x80, 0x20][..], seed].concat()),
        ])
    }

    /// The SubjectPublicKeyInfo of the public key `key`.
    fn spki(&self, key: &[u8]) -> Vec<u8> {
        key_corpus::seq(&[
            &self.algorithm_identifier(),
            &key_corpus::tlv(0x03, &[&[0][..], key].concat()),
        ])
    }

    /// The public key of the seed, and the crate's deterministic signature
    /// of `message` with it, empty context.
    fn crate_signed(&self, seed: &[u8; 32], message: &[u8]) -> (Vec<u8>, Vec<u8>) {
        fn signed<P: ml_dsa::MlDsaParams>(seed: &[u8; 32], message: &[u8]) -> (Vec<u8>, Vec<u8>) {
            let key = ml_dsa::ExpandedSigningKey::<P>::from_seed(&(*seed).into());
            let signature = key.sign_deterministic(message, b"").expect("signed");
            (
                key.verifying_key().encode().to_vec(),
                signature.encode().to_vec(),
            )
        }
        match self.oid {
            0x11 => signed::<ml_dsa::MlDsa44>(seed, message),
            0x12 => signed::<ml_dsa::MlDsa65>(seed, message),
            _ => signed::<ml_dsa::MlDsa87>(seed, message),
        }
    }

    /// `signature` with z's first coefficient written as `encoded`, the
    /// value `BitPack` stores for it, γ1 − z.
    fn with_z0(&self, signature: &[u8], encoded: u32) -> Vec<u8> {
        let mut out = signature.to_vec();
        for bit in 0..self.z_bits {
            let (byte, shift) = (self.c_tilde + bit / 8, bit % 8);
            let value = ((encoded >> bit) & 1) as u8;
            out[byte] = (out[byte] & !(1 << shift)) | (value << shift);
        }
        out
    }

    /// `signature` mutated in each place FIPS 204's `sigDecode` and the
    /// verification check, each named: its length, c̃, z against the
    /// bound γ1 − β on either side, and the hint's index order, its unused
    /// indices and its cuts against ω.  Every one is a signature Go
    /// refuses.
    fn mutations(&self, signature: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
        let gamma1 = 1u32 << (self.z_bits - 1);
        let len = signature.len();
        let hints = len - self.omega - self.k;
        let cuts: Vec<usize> = signature[hints + self.omega..]
            .iter()
            .map(|&cut| usize::from(cut))
            .collect();
        let last = cuts[self.k - 1];
        let mut out = vec![
            ("a byte long", [signature, &[0]].concat()),
            ("a byte short", signature[..len - 1].to_vec()),
            ("empty", Vec::new()),
            ("a bit of c~", {
                let mut s = signature.to_vec();
                s[0] ^= 1;
                s
            }),
            ("a bit of z", {
                let mut s = signature.to_vec();
                s[self.c_tilde + 5] ^= 0x10;
                s
            }),
            ("z at the bound", self.with_z0(signature, self.beta)),
            ("z under the bound", self.with_z0(signature, self.beta + 1)),
            (
                "z at the negative bound",
                self.with_z0(signature, 2 * gamma1 - self.beta),
            ),
            (
                "z under the negative bound",
                self.with_z0(signature, 2 * gamma1 - self.beta - 1),
            ),
            ("a cut above omega", {
                let mut s = signature.to_vec();
                s[len - 1] = (self.omega + 1) as u8;
                s
            }),
            ("no hints", {
                let mut s = signature.to_vec();
                s[hints..].fill(0);
                s
            }),
        ];
        if last < self.omega {
            let mut s = signature.to_vec();
            s[hints + self.omega - 1] = 1;
            out.push(("an index past the hints", s));
            let mut s = signature.to_vec();
            s[len - 2] = (last + 1) as u8;
            out.push(("cuts falling", s));
        }
        // The first polynomial with two hints or more.
        let mut start = 0;
        for &end in &cuts {
            if end >= start + 2 {
                let mut s = signature.to_vec();
                s.swap(hints + start, hints + start + 1);
                out.push(("hints out of order", s));
                let mut s = signature.to_vec();
                s[hints + start + 1] = s[hints + start];
                out.push(("a repeated hint", s));
                break;
            }
            start = end;
        }
        out
    }
}

/// Go's verdict on an ML-DSA signature under `name`, an x509 algorithm when
/// `x509`, else a TLS scheme, through the oracle's `sig_verify`.
fn go_verifies_ml_dsa(
    oracle: &mut Oracle,
    spki: &[u8],
    x509: bool,
    name: &str,
    message: &[u8],
    signature: &[u8],
) -> bool {
    let field = if x509 { "x509_alg" } else { "tls_scheme" };
    let request = serde_json::json!({
        "spki": hex(spki),
        field: name,
        "message": hex(message),
        "signature": hex(signature),
    });
    let response = oracle.call("sig_verify", request.to_string().as_bytes());
    dcroxide_testutil::require_reference_go(response["go_version"].as_str().unwrap_or_default());
    match response["result"].as_str() {
        Some("ok") => true,
        Some(refused) if refused.starts_with("refused: ") => false,
        _ => panic!("{name}: the oracle answered {response}"),
    }
}

/// Each ML-DSA algorithm gives Go's verdict, as Go checks a certificate's
/// signature under the set's x509 name and as its `crypto/tls` checks a
/// TLS 1.3 handshake signature under the set's scheme, which the provider's
/// RPC set maps to the algorithm alone: on Go's signatures, made through
/// the oracle's `sig_sign` with a key in PKCS#8 seed form, which verify
/// under the key the crate derives from the same seed; on the crate's
/// deterministic signatures; on each mutation of a signature in a field
/// the decoding checks; on another set's signature and key; and on
/// signatures of the set's length drawn at random.  The counts are pinned,
/// so that cases gone wrong cannot pass on agreement alone.
#[test]
fn ml_dsa_verifies_as_go_verifies() {
    let Some(mut oracle) = dcroxide_testutil::ml_dsa_oracle_or_skip() else {
        return;
    };
    let sets = ml_dsa_sets();
    let mut rng = SplitMix64(0x3d5a_2026_1113);
    let (mut cases, mut taken) = (0, 0);
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    for (index, set) in sets.iter().enumerate() {
        let mapped = dcroxide_tlscrypto::RPC_SIG_ALGS
            .mapping
            .iter()
            .find(|(scheme, _)| *scheme == set.scheme)
            .map(|(_, algorithms)| {
                algorithms
                    .iter()
                    .map(|a| format!("{a:?}"))
                    .collect::<Vec<_>>()
            });
        assert_eq!(
            mapped,
            Some(vec![format!("{:?}", set.algorithm)]),
            "{}",
            set.x509
        );
        let other = &sets[(index + 1) % 3];
        for _ in 0..2 {
            let mut seed = [0; 32];
            rng.fill(&mut seed);
            let pkcs8 = set.pkcs8(&seed);
            let (key, _) = set.crate_signed(&seed, b"");
            let spki = set.spki(&key);
            let mut check = |oracle: &mut Oracle,
                             algorithm: &dyn rustls::pki_types::SignatureVerificationAlgorithm,
                             what: &str,
                             key: &[u8],
                             spki: &[u8],
                             x509: &str,
                             tls: &str,
                             message: &[u8],
                             signature: &[u8],
                             expected: bool| {
                let ours = algorithm.verify_signature(key, message, signature).is_ok();
                for (is_x509, name) in [(true, x509), (false, tls)] {
                    let go = go_verifies_ml_dsa(oracle, spki, is_x509, name, message, signature);
                    assert_eq!(ours, go, "{}, {what}: Go's verdict under {name}", set.x509);
                }
                assert_eq!(ours, expected, "{}, {what}", set.x509);
                cases += 1;
                taken += usize::from(ours);
            };
            for len in [0, 1, 100, 1000] {
                let mut message = vec![0; len];
                rng.fill(&mut message);
                for name in [set.x509, set.tls] {
                    let field = if name == set.x509 {
                        "x509_alg"
                    } else {
                        "scheme"
                    };
                    let request = serde_json::json!({
                        "key_pkcs8": hex(&pkcs8),
                        field: name,
                        "message": hex(&message),
                    });
                    let response = oracle.call("sig_sign", request.to_string().as_bytes());
                    dcroxide_testutil::require_reference_go(
                        response["go_version"].as_str().unwrap_or_default(),
                    );
                    let go = unhex(
                        response["result"]
                            .as_str()
                            .unwrap_or_else(|| panic!("the oracle answered {response}")),
                    );
                    check(
                        &mut oracle,
                        set.algorithm,
                        "Go's signature",
                        &key,
                        &spki,
                        set.x509,
                        set.tls,
                        &message,
                        &go,
                        true,
                    );
                }
                let (_, ours) = set.crate_signed(&seed, &message);
                check(
                    &mut oracle,
                    set.algorithm,
                    "the crate's signature",
                    &key,
                    &spki,
                    set.x509,
                    set.tls,
                    &message,
                    &ours,
                    true,
                );
            }
            let message = b"a TLS 1.3 CertificateVerify's content";
            let (_, signature) = set.crate_signed(&seed, message);
            for (what, mutated) in set.mutations(&signature) {
                *seen.entry(what).or_default() += 1;
                check(
                    &mut oracle,
                    set.algorithm,
                    what,
                    &key,
                    &spki,
                    set.x509,
                    set.tls,
                    message,
                    &mutated,
                    false,
                );
            }
            check(
                &mut oracle,
                set.algorithm,
                "another message",
                &key,
                &spki,
                set.x509,
                set.tls,
                b"another",
                &signature,
                false,
            );
            // The signature and its key under the next set's algorithm and
            // names: refused by length here, and by Go as a set mismatch.
            check(
                &mut oracle,
                other.algorithm,
                "under another set's names",
                &key,
                &spki,
                other.x509,
                other.tls,
                message,
                &signature,
                false,
            );
            for _ in 0..10 {
                let mut random = vec![0; signature.len()];
                rng.fill(&mut random);
                check(
                    &mut oracle,
                    set.algorithm,
                    "random bytes",
                    &key,
                    &spki,
                    set.x509,
                    set.tls,
                    message,
                    &random,
                    false,
                );
            }
        }
    }
    // Every mutation reached at least once a set, the hint ones included.
    for (what, count) in &seen {
        assert!(*count >= 3, "{what}: {count}");
    }
    assert_eq!(seen.len(), 15, "{seen:?}");
    assert_eq!((cases, taken), (234, 72), "cases, and those taken");
}
