// SPDX-License-Identifier: ISC
//! This crate's verdicts against Go's, through the oracle (ADR-0015 T10):
//! what dcrd's `crypto/tls` would do with the same input.
//!
//! For key exchange, on all four groups: each takes and refuses the shares
//! Go's `crypto/ecdh` takes and refuses, the generated ones of
//! `kx_shares`, and agrees Go's secret over a fresh key share of its own.
//! P-521 is the group these tests matter most for, since ring has none to
//! hold it to; Wycheproof's vectors go through Go too, in the crate's
//! unit tests, where a vector's private key can be set.
//!
//! For key loading: `sign::load_der` reads each key of `key_corpus` as
//! Go's `tls.X509KeyPair` reads it under its PEM label, the key and its
//! type where Go loads it, Go's text where Go refuses it; the RSA and
//! P-224 keys Go loads are refused with this crate's texts.  And Ed25519,
//! which is deterministic, signs as Go's `ed25519.Sign` signs, byte for
//! byte.
//!
//! Without an oracle the tests skip, unless `DCROXIDE_REQUIRE_ORACLE` is
//! set, as in CI, where they also require the reference Go.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

mod key_corpus;
mod kx_shares;

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
/// (`crypto/x509/pkcs1.go:74-79`).  This crate, which signs with no RSA
/// key, reads their structure alone and refuses them with its own text.
/// Go loads the key with an additional prime: a key of more than two
/// primes is checked through N, E and D alone
/// (`crypto/rsa/rsa.go:571-572`, `:610-617`).
const RSA_GO_REFUSES: &[&str] = &[
    "RSA, PKCS#1, a CRT exponent wrong",
    "RSA, PKCS#1, P negative",
];

/// `load_der` reads every key of the corpus as Go's `tls.X509KeyPair`
/// does.  Where it loads a key, Go loads the same key, of the same type,
/// under the key's PEM label against a certificate made for the key
/// `load_der` gave, so a key Go reads with another scalar, on another
/// curve or of another type does not match.  Where it refuses one with
/// Go's text, Go refuses it with that text against the certificate of
/// the key it was mutated from, which Go would load were the refusal
/// wrong.  An RSA key it refuses with its own text is loaded by Go, or
/// refused by Go's `Validate` (`RSA_GO_REFUSES`), and a P-224 key is
/// loaded by Go as P-224.  The count of each verdict is pinned too, so
/// that a corpus gone wrong, a case lost or sent to another verdict,
/// cannot pass on agreement alone.
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
                    if go != "ok RSA 2048" {
                        assert_eq!(go, "refused: tls: failed to parse private key", "{label}");
                        rsa_refused.push(label.clone());
                    }
                    format!("RSA, which Go answers: {go}")
                } else if text == "unsupported private key: ECDSA P-224" {
                    assert_eq!(go, "ok ECDSA P-224", "{label}");
                    text
                } else {
                    assert_eq!(go, format!("refused: {text}"), "{label}");
                    text
                }
            }
            Err(other) => panic!("{label}: {other:?}"),
        };
        *verdicts.entry(verdict).or_default() += 1;
    }
    assert_eq!(rsa_refused, RSA_GO_REFUSES, "the RSA keys Go refuses");
    let expected: BTreeMap<String, usize> = [
        ("ok ECDSA P-256", 100),
        ("ok ECDSA P-384", 55),
        ("ok ECDSA P-521", 57),
        ("ok Ed25519", 9),
        ("unsupported private key: ECDSA P-224", 48),
        ("tls: failed to parse private key", 272),
        ("tls: found unknown private key type in PKCS#8 wrapping", 1),
        ("RSA, which Go answers: ok RSA 2048", 12),
        (
            "RSA, which Go answers: refused: tls: failed to parse private key",
            2,
        ),
    ]
    .into_iter()
    .map(|(verdict, count)| (verdict.to_owned(), count))
    .collect();
    assert_eq!(verdicts, expected, "the count of each verdict");
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
