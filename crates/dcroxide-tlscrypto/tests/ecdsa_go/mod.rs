// SPDX-License-Identifier: ISC
//! Go-made vectors for the nine ECDSA pairs of the RPC set (ADR-0015, T4):
//! P-256, P-384 and P-521, each with SHA-256, SHA-384 and SHA-512, the
//! five pairs ring lacked among them.  Wycheproof's P-521 and SHA-512
//! ECDSA files were not in the tree when these were made, and no copy of
//! them was found on the machine that made them, so the known answers come
//! from the reference Go through the oracle instead, and are frozen in
//! `tests/data/ecdsa-go/cases.json.gz` with their count and hash
//! (`tests/data/ecdsa-go/SOURCE`).  Since 2026-11-20 Wycheproof's files
//! for P-256, P-384 and P-521 with SHA-512 are in the tree as well
//! (`tests/data/wycheproof/SOURCE` lists them), so its files there cover
//! six of the nine pairs; none covers P-256 with SHA-384 or P-521 with
//! SHA-256 or SHA-384, which these vectors alone cover.
//!
//! Each case is a key, a message, a signature and the algorithm it is
//! checked under, by webpki's name, with its class and Go's verdict, as
//! `crypto/x509` checks a certificate's signature under the pair's x509
//! name (`sig_verify`).  For each pair: Go's own signatures (`sig_sign`,
//! `ecdsa.SignASN1`) of messages of three lengths; the same signature for
//! another message, under the curve's other two hashes and under another
//! curve's key; s replaced by n - s, which Go takes, since it does not
//! ask for a low s; r or s at n, zero, with a bit flipped, negative, or
//! with a leading zero it does not need; a byte after the signature, its
//! SEQUENCE length in a longer form than it needs, and no signature; and
//! the key compressed, in the hybrid form, with x at or above p and with a
//! bit of y flipped, off the curve.
//!
//! `tests/ecdsa_go_vectors.rs` holds the provider to the frozen verdicts
//! with no oracle; `tests/go_differential.rs` asks Go for each verdict
//! again, as a certificate's and as a handshake signature's under each
//! scheme the RPC set maps the pair to, checks fresh Go signatures, and
//! regenerates the file (`regenerate_ecdsa_go_vectors`, ignored).

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects, dead_code)]

use std::io::Read;

use dcroxide_testutil::{Oracle, hex, unhex};
use p256::elliptic_curve::sec1::ToSec1Point;
use rustls::pki_types::SignatureVerificationAlgorithm;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// The frozen file, under the crate's directory.
pub const PATH: &str = "tests/data/ecdsa-go/cases.json.gz";

/// The number of cases the file holds.
pub const COUNT: usize = 216;

/// The SHA-256 of the file's JSON, decompressed.
pub const SHA256: &str = "806e98dad4b25d4f2e7dd2f3f7e8e67b5b11aee7c062faca05ab61a660f0b0db";

/// A curve: its name, as Go and `tls_pki` name it, its OID's contents,
/// the length of its field elements, its order's minimal INTEGER bytes,
/// and the key these vectors sign with, as its secret scalar.
pub struct Curve {
    pub name: &'static str,
    oid: &'static [u8],
    pub field: usize,
    order: &'static str,
    scalar: fn() -> Vec<u8>,
}

/// The three curves.
pub const CURVES: [Curve; 3] = [
    Curve {
        name: "P-256",
        oid: &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
        field: 32,
        order: "00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        scalar: || vec![7; 32],
    },
    Curve {
        name: "P-384",
        oid: &[0x2b, 0x81, 0x04, 0x00, 0x22],
        field: 48,
        order: "00ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf\
                581a0db248b0a77aecec196accc52973",
        scalar: || vec![7; 48],
    },
    Curve {
        name: "P-521",
        oid: &[0x2b, 0x81, 0x04, 0x00, 0x23],
        field: 66,
        order: "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
                fa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
        scalar: || {
            let mut scalar = vec![7; 66];
            scalar[0] = 1;
            scalar
        },
    },
];

/// The three hashes, by Go's x509 name for ECDSA with each.
pub const HASHES: [&str; 3] = ["ECDSA-SHA256", "ECDSA-SHA384", "ECDSA-SHA512"];

/// The provider's algorithm for the curve at `curve` and the hash at
/// `hash` of [`CURVES`] and [`HASHES`].
pub fn algorithm(curve: usize, hash: usize) -> &'static dyn SignatureVerificationAlgorithm {
    use dcroxide_tlscrypto::verify::*;
    [
        [ECDSA_P256_SHA256, ECDSA_P256_SHA384, ECDSA_P256_SHA512],
        [ECDSA_P384_SHA256, ECDSA_P384_SHA384, ECDSA_P384_SHA512],
        [ECDSA_P521_SHA256, ECDSA_P521_SHA384, ECDSA_P521_SHA512],
    ][curve][hash]
}

/// The algorithm of the RPC set with webpki's name `name`.
pub fn by_name(name: &str) -> &'static dyn SignatureVerificationAlgorithm {
    *dcroxide_tlscrypto::RPC_SIG_ALGS
        .all
        .iter()
        .find(|algorithm| format!("{algorithm:?}") == name)
        .unwrap_or_else(|| panic!("no algorithm {name}"))
}

/// A DER element of `tag` holding `content`.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match content.len() {
        len @ 0..=127 => out.push(len as u8),
        len @ 128..=255 => out.extend([0x81, len as u8]),
        len => out.extend([0x82, (len >> 8) as u8, len as u8]),
    }
    out.extend_from_slice(content);
    out
}

impl Curve {
    /// id-ecPublicKey with this curve's OID.
    fn algorithm_identifier(&self) -> Vec<u8> {
        tlv(
            0x30,
            &[
                tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]),
                tlv(0x06, self.oid),
            ]
            .concat(),
        )
    }

    /// The SubjectPublicKeyInfo of the point `public`, as a certificate
    /// carries it.
    pub fn spki(&self, public: &[u8]) -> Vec<u8> {
        tlv(
            0x30,
            &[
                self.algorithm_identifier(),
                tlv(0x03, &[&[0][..], public].concat()),
            ]
            .concat(),
        )
    }

    /// The PKCS#8 of the vectors' key, an RFC 5915 ECPrivateKey with no
    /// public key.
    pub fn pkcs8(&self) -> Vec<u8> {
        let sec1 = tlv(
            0x30,
            &[tlv(0x02, &[1]), tlv(0x04, &(self.scalar)())].concat(),
        );
        tlv(
            0x30,
            &[
                tlv(0x02, &[0]),
                self.algorithm_identifier(),
                tlv(0x04, &sec1),
            ]
            .concat(),
        )
    }

    /// The vectors' key's public point, uncompressed.
    pub fn public(&self) -> Vec<u8> {
        let scalar = (self.scalar)();
        match self.field {
            32 => p256::SecretKey::from_slice(&scalar)
                .expect("a key")
                .public_key()
                .to_sec1_point(false)
                .as_bytes()
                .to_vec(),
            48 => p384::SecretKey::from_slice(&scalar)
                .expect("a key")
                .public_key()
                .to_sec1_point(false)
                .as_bytes()
                .to_vec(),
            _ => p521::SecretKey::from_slice(&scalar)
                .expect("a key")
                .public_key()
                .to_sec1_point(false)
                .as_bytes()
                .to_vec(),
        }
    }

    /// The order's minimal INTEGER bytes.
    fn order(&self) -> Vec<u8> {
        unhex(self.order)
    }
}

/// An ECDSA signature's r and s, as their INTEGERs' contents, from a DER
/// SEQUENCE of two INTEGERs.
pub fn split(signature: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let header = if signature[1] == 0x81 { 3 } else { 2 };
    let content = &signature[header..];
    let r_len = usize::from(content[1]);
    let r = content[2..2 + r_len].to_vec();
    let s = content[2 + r_len + 2..].to_vec();
    (r, s)
}

/// The DER SEQUENCE of INTEGERs whose contents are `r` and `s`.
pub fn join(r: &[u8], s: &[u8]) -> Vec<u8> {
    tlv(0x30, &[tlv(0x02, r), tlv(0x02, s)].concat())
}

/// `value`, an unsigned big-endian number, as a minimal positive
/// INTEGER's contents.
fn integer(value: &[u8]) -> Vec<u8> {
    let mut digits: &[u8] = value;
    while digits.len() > 1 && digits[0] == 0 {
        digits = &digits[1..];
    }
    if digits[0] & 0x80 != 0 {
        [&[0][..], digits].concat()
    } else {
        digits.to_vec()
    }
}

/// `a - b` for unsigned big-endian numbers with `a >= b`.
fn subtract(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = a.to_vec();
    let mut borrow = 0i32;
    for i in 0..out.len() {
        let ai = out.len() - 1 - i;
        let bv = if i < b.len() {
            i32::from(b[b.len() - 1 - i])
        } else {
            0
        };
        let mut v = i32::from(out[ai]) - bv - borrow;
        borrow = 0;
        if v < 0 {
            v += 256;
            borrow = 1;
        }
        out[ai] = v as u8;
    }
    assert_eq!(borrow, 0, "a >= b");
    out
}

/// One case of the file.
pub struct Case {
    /// Its class and pair, for messages.
    pub label: String,
    /// Its class.
    pub class: String,
    /// webpki's name for the algorithm it is checked under.
    pub algorithm: String,
    /// The curve its key is given on, by its place in [`CURVES`], which is
    /// the algorithm's curve.
    pub curve: usize,
    /// The key, as a SubjectPublicKeyInfo's BIT STRING holds it.
    pub key: Vec<u8>,
    /// The message.
    pub message: Vec<u8>,
    /// The signature.
    pub signature: Vec<u8>,
    /// Go's verdict, recorded.
    pub go: bool,
}

/// The file's JSON, decompressed, as it is on disk.
pub fn json_text() -> String {
    let path = format!("{}/{PATH}", env!("CARGO_MANIFEST_DIR"));
    let file = std::fs::File::open(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let mut json = String::new();
    flate2::read::GzDecoder::new(file)
        .read_to_string(&mut json)
        .unwrap_or_else(|e| panic!("{path}: {e}"));
    json
}

/// The SHA-256 of `text`, in hex.
pub fn sha256(text: &str) -> String {
    hex(&Sha256::digest(text.as_bytes()))
}

/// Every case of the file, after its hash and count are checked against
/// [`SHA256`] and [`COUNT`].
pub fn cases() -> Vec<Case> {
    let text = json_text();
    assert_eq!(sha256(&text), SHA256, "{PATH}'s hash");
    let file: Value = serde_json::from_str(&text).expect("the file's JSON");
    let field = |case: &Value, name: &str| -> String {
        case[name]
            .as_str()
            .unwrap_or_else(|| panic!("no {name} in {case}"))
            .to_owned()
    };
    let cases: Vec<Case> = file["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .map(|case| Case {
            label: format!("{} ({})", field(case, "class"), field(case, "algorithm")),
            class: field(case, "class"),
            algorithm: field(case, "algorithm"),
            curve: case["curve"].as_u64().expect("curve") as usize,
            key: unhex(&field(case, "key")),
            message: unhex(&field(case, "message")),
            signature: unhex(&field(case, "signature")),
            go: case["go"].as_bool().expect("go"),
        })
        .collect();
    assert_eq!(cases.len(), COUNT, "{PATH}'s count");
    cases
}

/// Go's verdict on a signature through the oracle's `sig_verify`: the key
/// as a SubjectPublicKeyInfo on `curve`, checked under `name`, an x509
/// signature algorithm when `x509`, else a TLS signature scheme.
pub fn go_verifies(
    oracle: &mut Oracle,
    curve: &Curve,
    x509: bool,
    name: &str,
    key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    let field = if x509 { "x509_alg" } else { "tls_scheme" };
    let request = json!({
        "spki": hex(&curve.spki(key)),
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

/// Go's signature of `message` with the vectors' key on `curve` under
/// `name`, an x509 signature algorithm when `x509`, else a TLS signature
/// scheme, through the oracle's `sig_sign`.
pub fn go_signs(
    oracle: &mut Oracle,
    curve: &Curve,
    x509: bool,
    name: &str,
    message: &[u8],
) -> Vec<u8> {
    let field = if x509 { "x509_alg" } else { "scheme" };
    let request = json!({
        "key_pkcs8": hex(&curve.pkcs8()),
        field: name,
        "message": hex(message),
    });
    let response = oracle.call("sig_sign", request.to_string().as_bytes());
    dcroxide_testutil::require_reference_go(response["go_version"].as_str().unwrap_or_default());
    unhex(
        response["result"]
            .as_str()
            .unwrap_or_else(|| panic!("{name}: the oracle answered {response}")),
    )
}

/// The cases, made afresh through `oracle`, each with Go's verdict, in the
/// file's JSON: `{"cases": [{"class", "algorithm", "curve", "key",
/// "message", "signature", "go"}]}`, in a fixed order.
pub fn generate(oracle: &mut Oracle) -> Value {
    let message = b"a TLS 1.3 CertificateVerify's content".to_vec();
    let mut out = Vec::new();
    for (c, curve) in CURVES.iter().enumerate() {
        let key = curve.public();
        assert_eq!(key.len(), 1 + 2 * curve.field, "{}", curve.name);
        let x_end = 1 + curve.field;
        for (h, hash) in HASHES.iter().enumerate() {
            let name = format!("{:?}", algorithm(c, h));
            let mut push = |oracle: &mut Oracle,
                            class: &str,
                            under: usize,
                            curve_index: usize,
                            key: &[u8],
                            message: &[u8],
                            signature: &[u8]| {
                let go = go_verifies(
                    oracle,
                    &CURVES[curve_index],
                    true,
                    HASHES[under],
                    key,
                    message,
                    signature,
                );
                out.push(json!({
                    "class": class,
                    "algorithm": format!("{:?}", algorithm(curve_index, under)),
                    "curve": curve_index,
                    "key": hex(key),
                    "message": hex(message),
                    "signature": hex(signature),
                    "go": go,
                }));
            };
            for len in [0usize, 37, 200] {
                let signed: Vec<u8> = (0..len).map(|i| (i * 7 + c * 3 + h) as u8).collect();
                let signature = go_signs(oracle, curve, true, hash, &signed);
                push(oracle, "go-signature", h, c, &key, &signed, &signature);
            }
            let signature = go_signs(oracle, curve, true, hash, &message);
            push(oracle, "go-signature", h, c, &key, &message, &signature);
            push(
                oracle,
                "another-message",
                h,
                c,
                &key,
                b"another",
                &signature,
            );
            for other in (0..3).filter(|&other| other != h) {
                push(oracle, "another-hash", other, c, &key, &message, &signature);
            }
            let other_curve = (c + 1) % 3;
            push(
                oracle,
                "another-curve",
                h,
                other_curve,
                &CURVES[other_curve].public(),
                &message,
                &signature,
            );
            let (r, s) = split(&signature);
            assert_eq!(join(&r, &s), signature, "{name}: the DER rebuilt");
            let n = curve.order();
            let high_s = integer(&subtract(&n, &s));
            push(oracle, "high-s", h, c, &key, &message, &join(&r, &high_s));
            push(oracle, "r-at-n", h, c, &key, &message, &join(&n, &s));
            push(oracle, "s-at-n", h, c, &key, &message, &join(&r, &n));
            push(oracle, "r-zero", h, c, &key, &message, &join(&[0], &s));
            push(oracle, "s-zero", h, c, &key, &message, &join(&r, &[0]));
            let mut flipped = r.clone();
            let last = flipped.len() - 1;
            flipped[last] ^= 1;
            push(
                oracle,
                "r-bit-flipped",
                h,
                c,
                &key,
                &message,
                &join(&flipped, &s),
            );
            let mut flipped = s.clone();
            let last = flipped.len() - 1;
            flipped[last] ^= 0x80;
            push(
                oracle,
                "s-bit-flipped",
                h,
                c,
                &key,
                &message,
                &join(&r, &flipped),
            );
            let negative = if r[0] == 0 {
                r[1..].to_vec()
            } else {
                let mut negative = r.clone();
                negative[0] |= 0x80;
                negative
            };
            push(
                oracle,
                "r-negative",
                h,
                c,
                &key,
                &message,
                &join(&negative, &s),
            );
            let padded = [&[0][..], &r].concat();
            push(
                oracle,
                "r-leading-zero",
                h,
                c,
                &key,
                &message,
                &join(&padded, &s),
            );
            push(
                oracle,
                "trailing-byte",
                h,
                c,
                &key,
                &message,
                &[signature.clone(), vec![0]].concat(),
            );
            let content = [tlv(0x02, &r), tlv(0x02, &s)].concat();
            let longer = if content.len() > 127 {
                [&[0x30, 0x82, 0x00, content.len() as u8][..], &content].concat()
            } else {
                [&[0x30, 0x81, content.len() as u8][..], &content].concat()
            };
            push(oracle, "length-not-minimal", h, c, &key, &message, &longer);
            push(oracle, "empty-signature", h, c, &key, &message, &[]);
            let mut compressed = vec![0x02 | (key[key.len() - 1] & 1)];
            compressed.extend_from_slice(&key[1..x_end]);
            push(
                oracle,
                "key-compressed",
                h,
                c,
                &compressed,
                &message,
                &signature,
            );
            let mut hybrid = key.clone();
            hybrid[0] = 0x06 | (key[key.len() - 1] & 1);
            push(oracle, "key-hybrid", h, c, &hybrid, &message, &signature);
            let mut x_high = key.clone();
            x_high[1..x_end].fill(0xff);
            push(
                oracle,
                "key-x-at-or-above-p",
                h,
                c,
                &x_high,
                &message,
                &signature,
            );
            let mut off = key.clone();
            let last = off.len() - 1;
            off[last] ^= 0x02;
            push(
                oracle,
                "key-off-the-curve",
                h,
                c,
                &off,
                &message,
                &signature,
            );
        }
    }
    json!({ "cases": out })
}

/// The classes [`generate`] makes, each with whether Go takes its cases.
pub const CLASSES: [(&str, bool); 20] = [
    ("go-signature", true),
    ("another-message", false),
    ("another-hash", false),
    ("another-curve", false),
    ("high-s", true),
    ("r-at-n", false),
    ("s-at-n", false),
    ("r-zero", false),
    ("s-zero", false),
    ("r-bit-flipped", false),
    ("s-bit-flipped", false),
    ("r-negative", false),
    ("r-leading-zero", false),
    ("trailing-byte", false),
    ("length-not-minimal", false),
    ("empty-signature", false),
    ("key-compressed", false),
    ("key-hybrid", false),
    ("key-x-at-or-above-p", false),
    ("key-off-the-curve", false),
];
