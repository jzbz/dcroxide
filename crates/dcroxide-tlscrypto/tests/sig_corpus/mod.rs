// SPDX-License-Identifier: ISC
//! The signature parity corpus that `tests/ring_parity.rs` and
//! `tests/go_differential.rs` hold the fourteen verification algorithms to
//! (ADR-0015, step 1): cases, valid and not, each with ring's verdict and
//! Go's recorded beside it, so that the provider's verdicts can be held to
//! both while ring is in the tree, and to ring's recorded ones after.
//!
//! `tests/data/parity/corpus.json.gz` holds it.  A case is an algorithm,
//! by its place in `SUPPORTED_SIG_ALGS.all`, a key, a message and a
//! signature, with its class, the signer that made the signature, and the
//! two verdicts.  Every key is stored once, in a table the cases refer to
//! by index, and an RSA key of the shared test-key fixture is stored as its
//! name there (`dcroxide_testutil::rsa_test_key`).  Wycheproof's signature
//! cases are references by file and `tcId` into the files committed under
//! `tests/data/wycheproof`, with only the verdicts stored.
//!
//! The generated cases start from valid signatures made by Go, through
//! the oracle's `sig_sign`: `crypto/ecdsa`, `crypto/ed25519` and
//! `crypto/rsa`, or, for an RSA key `crypto/rsa` refuses, the oracle's raw
//! `math/big` signer, which is first held to `crypto/rsa` on every key
//! both take.  From those come, at bounded positions, single-bit flips of
//! the key, the message and the signature (every DER header byte, the
//! first and last byte of each field, and eight positions from a fixed
//! seed); DER variants of the ECDSA signature and of the `RSAPublicKey`
//! (lengths not in their fewest bytes, extra leading zeros, bytes after
//! the end, indefinite lengths, negative and zero values); compressed and
//! hybrid points; Ed25519 keys and R values written with y at or above p
//! or with the sign bit of a zero x, S at or above L, and under keys of
//! order 4 and 2, written canonically and not, signatures that verify
//! exactly when the challenge, hashed over the key as received, is a
//! multiple of the order; RSA moduli of 1024, 2040, 2041, 2048, 3072,
//! 4096, 8192 and 8193 bits and exponents 1, 2, 3, 2^31 - 1, 2^31 + 1,
//! 2^33 - 1 and 2^33 + 1, and under e = 1 signatures that are their own
//! encodings; an `RSAPublicKey` with an element after E and with bytes
//! after the SEQUENCE; signatures a byte short and long, zero and n;
//! PKCS#1 v1.5 encodings without NULL and with short padding; PSS with
//! other salt lengths; and each valid signature under every other
//! algorithm of its key type.
//!
//! `regenerate_parity_corpus`, an ignored test in `tests/ring_parity.rs`,
//! is the corpus's tool, through `sig_corpus_gen`.  Its ring column cannot
//! be made again once the switch removes ring; its Go column can, through
//! the oracle.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::HashMap;
use std::io::Read;

use dcroxide_testutil::{Oracle, hex, rsa_test_key, unhex};
use rustls::pki_types::SignatureVerificationAlgorithm;
use serde_json::{Value, json};

/// The fourteen algorithms in `SUPPORTED_SIG_ALGS.all`'s order, each with
/// webpki's name for it and Go's `x509.SignatureAlgorithm` name for what
/// it checks.
pub const ALGORITHMS: [(&str, &str); 14] = [
    ("ECDSA_P256_SHA256", "ECDSA-SHA256"),
    ("ECDSA_P256_SHA384", "ECDSA-SHA384"),
    ("ECDSA_P384_SHA256", "ECDSA-SHA256"),
    ("ECDSA_P384_SHA384", "ECDSA-SHA384"),
    ("ED25519", "Ed25519"),
    ("RSA_PSS_2048_8192_SHA256_LEGACY_KEY", "SHA256-RSAPSS"),
    ("RSA_PSS_2048_8192_SHA384_LEGACY_KEY", "SHA384-RSAPSS"),
    ("RSA_PSS_2048_8192_SHA512_LEGACY_KEY", "SHA512-RSAPSS"),
    ("RSA_PKCS1_2048_8192_SHA256", "SHA256-RSA"),
    ("RSA_PKCS1_2048_8192_SHA384", "SHA384-RSA"),
    ("RSA_PKCS1_2048_8192_SHA512", "SHA512-RSA"),
    ("RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS", "SHA256-RSA"),
    ("RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS", "SHA384-RSA"),
    ("RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS", "SHA512-RSA"),
];

/// The classes whose cases Go may judge otherwise than ring and the
/// provider, each with the reason: differences from Go that ring has today
/// wherever it verifies a chain or a handshake signature, and that the
/// switch keeps.  PARITY.md records only part of them so far: its
/// client-certificate entry ("Under `--authtype=clientcert` webpki and ring
/// still decide part of a client chain") records RSA keys outside ring's
/// modulus range in a client's chain, and that the replay refuses a parent
/// key's exponent above 2^31 - 1 as Go does.  The rest, that exponent in a
/// client's own key, which signs its CertificateVerify, such keys in a
/// seeder's chain, and an `RSAPublicKey` with bytes after its values, is
/// not recorded yet, and is to be recorded with the switch.  Each closes
/// when Go's RSA rules come with Go's client-certificate set (ADR-0015,
/// T4).
pub const GO_DIFFERS: [(&str, &str); 5] = [
    (
        "rsa-modulus-1024",
        "Go takes RSA keys from 1024 bits (`crypto/rsa/rsa.go:284-300`); ring's least is \
         256 whole bytes",
    ),
    (
        "rsa-modulus-2040",
        "Go takes a 2040-bit key; ring's 256-byte least, rounded up, refuses 2040 bits \
         and takes 2041",
    ),
    (
        "rsa-modulus-8193",
        "Go's crypto/rsa has no greatest length; ring stops at 8192 bits",
    ),
    (
        "rsa-exponent-above-go",
        "Go refuses an exponent above 2^31 - 1 \
         (`crypto/internal/fips140/rsa/rsa.go:360-362`); ring takes up to 2^33 - 1",
    ),
    (
        "rsa-key-trailing-data",
        "Go reads the RSAPublicKey's SEQUENCE and its two INTEGERs and ignores what \
         follows each (`crypto/x509/parser.go:261-271`); ring refuses anything after them",
    ),
];

/// The corpus's file, under the crate's directory.
pub const PATH: &str = "tests/data/parity/corpus.json.gz";

/// Wycheproof's signature files under `tests/data/wycheproof`, each with
/// the algorithm its cases run under, by its place in [`ALGORITHMS`], or
/// `None` for a PSS file, whose groups each run under the PSS algorithm
/// of their hash ([`wycheproof_algorithm`]).  The corpus refers to every
/// case of every one, but those of a group no algorithm takes.
pub const WYCHEPROOF_FILES: [(&str, Option<usize>); 17] = [
    ("ecdsa_secp256r1_sha256_test.json", Some(0)),
    ("ecdsa_secp384r1_sha256_test.json", Some(2)),
    ("ecdsa_secp384r1_sha384_test.json", Some(3)),
    ("ed25519_test.json", Some(4)),
    ("rsa_signature_2048_sha256_test.json", Some(8)),
    ("rsa_signature_2048_sha384_test.json", Some(9)),
    ("rsa_signature_2048_sha512_test.json", Some(10)),
    ("rsa_signature_3072_sha256_test.json", Some(8)),
    ("rsa_signature_3072_sha384_test.json", Some(9)),
    ("rsa_signature_3072_sha512_test.json", Some(10)),
    ("rsa_signature_4096_sha384_test.json", Some(9)),
    ("rsa_signature_4096_sha512_test.json", Some(10)),
    ("rsa_pss_2048_sha256_mgf1_32_test.json", None),
    ("rsa_pss_3072_sha256_mgf1_32_test.json", None),
    ("rsa_pss_4096_sha256_mgf1_32_test.json", None),
    ("rsa_pss_4096_sha512_mgf1_64_test.json", None),
    ("rsa_pss_misc_test.json", None),
];

/// A key, a message and a signature.
pub type Triple = (Vec<u8>, Vec<u8>, Vec<u8>);

/// A Wycheproof case: its key, message and signature, and the algorithm
/// it runs under, if any.
type WycheproofCase = (Triple, Option<usize>);

/// One case of the corpus.
pub struct Case {
    /// What it is, for messages: its class, or its Wycheproof file and
    /// `tcId`, and its place.
    pub label: String,
    /// Its class; `wycheproof` for a Wycheproof case.
    pub class: String,
    /// Its algorithm, by its place in `SUPPORTED_SIG_ALGS.all`.
    pub algorithm: usize,
    /// The public key, as a SubjectPublicKeyInfo's BIT STRING holds it.
    pub key: Vec<u8>,
    /// The message.
    pub message: Vec<u8>,
    /// The signature.
    pub signature: Vec<u8>,
    /// ring's verdict, recorded.
    pub ring: bool,
    /// Go's verdict, recorded.
    pub go: bool,
}

/// The algorithm at `index` of this crate's list.
pub fn ours(index: usize) -> &'static dyn SignatureVerificationAlgorithm {
    dcroxide_tlscrypto::SUPPORTED_SIG_ALGS.all[index]
}

/// The corpus file's parsed JSON.
pub fn read() -> Value {
    let path = format!("{}/{PATH}", env!("CARGO_MANIFEST_DIR"));
    let file = std::fs::File::open(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let mut json = String::new();
    flate2::read::GzDecoder::new(file)
        .read_to_string(&mut json)
        .unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&json).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// Every case of the corpus, the generated ones first, keys resolved and
/// Wycheproof's cases read from their files.  Each Wycheproof reference
/// must name the algorithm its group runs under, and every case of each
/// file in [`WYCHEPROOF_FILES`] that runs under one must be referred to,
/// so that a regeneration that loses references fails here.
pub fn cases() -> Vec<Case> {
    let corpus = read();
    let keys: Vec<Vec<u8>> = corpus["keys"]
        .as_array()
        .expect("keys")
        .iter()
        .map(|key| {
            let key = key.as_str().expect("a key");
            match key.strip_prefix("rsa:") {
                Some(name) => rsa_test_key(name).rsa_public_key(),
                None => unhex(key),
            }
        })
        .collect();
    let mut out = Vec::new();
    for (index, case) in corpus["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .enumerate()
    {
        let field = |i: usize| &case[i];
        let class = field(0).as_str().expect("a class").to_owned();
        out.push(Case {
            label: format!("{class} #{index}"),
            class,
            algorithm: usize::try_from(field(1).as_u64().expect("an algorithm")).expect("small"),
            key: keys[usize::try_from(field(2).as_u64().expect("a key")).expect("small")].clone(),
            message: unhex(field(3).as_str().expect("a message")),
            signature: unhex(field(4).as_str().expect("a signature")),
            ring: field(6).as_bool().expect("ring's verdict"),
            go: field(7).as_bool().expect("Go's verdict"),
        });
    }
    let mut files: HashMap<String, HashMap<u64, WycheproofCase>> = HashMap::new();
    for reference in corpus["wycheproof"].as_array().expect("wycheproof") {
        let file = reference[0].as_str().expect("a file").to_owned();
        let id = reference[1].as_u64().expect("a tcId");
        let algorithm =
            usize::try_from(reference[2].as_u64().expect("an algorithm")).expect("small");
        let cases = files
            .entry(file.clone())
            .or_insert_with(|| wycheproof_cases(&file));
        let ((key, message, signature), runs_under) = cases
            .remove(&id)
            .unwrap_or_else(|| panic!("{file} has no tcId {id}, or it is listed twice"));
        assert_eq!(
            Some(algorithm),
            runs_under,
            "{file} tcId {id}: the algorithm its group runs under"
        );
        out.push(Case {
            label: format!("{file} tcId {id}"),
            class: "wycheproof".to_owned(),
            algorithm,
            key,
            message,
            signature,
            ring: reference[3].as_bool().expect("ring's verdict"),
            go: reference[4].as_bool().expect("Go's verdict"),
        });
    }
    for (file, _) in WYCHEPROOF_FILES {
        let left = files
            .get(file)
            .unwrap_or_else(|| panic!("{file}: no case referred to"));
        let mut missing: Vec<u64> = left
            .iter()
            .filter(|(_, (_, runs_under))| runs_under.is_some())
            .map(|(id, _)| *id)
            .collect();
        missing.sort_unstable();
        assert!(
            missing.is_empty(),
            "{file}: tcIds {missing:?} not referred to"
        );
    }
    out
}

/// A Wycheproof signature file's parsed JSON.
pub fn wycheproof_file(file: &str) -> Value {
    let path = format!(
        "{}/tests/data/wycheproof/{file}.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut json = String::new();
    flate2::read::GzDecoder::new(std::fs::File::open(&path).expect("the file"))
        .read_to_string(&mut json)
        .expect("the file decompressed");
    serde_json::from_str(&json).expect("JSON")
}

/// The key a Wycheproof group of `file` holds, as webpki hands it to an
/// algorithm: an ECDSA group's uncompressed point, an Ed25519 group's 32
/// bytes, an RSA group's `RSAPublicKey`.
pub fn wycheproof_key(file: &str, group: &Value) -> Vec<u8> {
    let field = if file.starts_with("ecdsa") {
        &group["publicKey"]["uncompressed"]
    } else if file.starts_with("ed25519") {
        &group["publicKey"]["pk"]
    } else {
        &group["publicKeyAsn"]
    };
    unhex(field.as_str().expect("a key"))
}

/// The algorithm, by its place, the cases of a Wycheproof group of `file`
/// run under, as the crate's harness runs them: a PSS group under the PSS
/// algorithm of its hash, and none for the groups of SHA-1 and SHA-224 in
/// `rsa_pss_misc_test.json`, which no algorithm takes.
pub fn wycheproof_algorithm(file: &str, group: &Value) -> Option<usize> {
    let (_, fixed) = WYCHEPROOF_FILES
        .iter()
        .find(|(name, _)| *name == file)
        .unwrap_or_else(|| panic!("{file}: not a signature file of the corpus"));
    if fixed.is_some() {
        return *fixed;
    }
    match group["sha"].as_str() {
        Some("SHA-256") => Some(5),
        Some("SHA-384") => Some(6),
        Some("SHA-512") => Some(7),
        Some("SHA-1" | "SHA-224") if file == "rsa_pss_misc_test.json" => None,
        other => panic!("{file}: a PSS group of {other:?}"),
    }
}

/// Every case of a Wycheproof signature file, by `tcId`.
fn wycheproof_cases(file: &str) -> HashMap<u64, WycheproofCase> {
    let vectors = wycheproof_file(file);
    let mut out = HashMap::new();
    for group in vectors["testGroups"].as_array().expect("testGroups") {
        let key = wycheproof_key(file, group);
        let runs_under = wycheproof_algorithm(file, group);
        for case in group["tests"].as_array().expect("tests") {
            let field = |name: &str| unhex(case[name].as_str().expect("a hex field"));
            out.insert(
                case["tcId"].as_u64().expect("a tcId"),
                ((key.clone(), field("msg"), field("sig")), runs_under),
            );
        }
    }
    out
}

/// The SubjectPublicKeyInfo of `key` for the algorithm at `algorithm`, as a
/// certificate would carry it, which is how Go is given a key.
pub fn spki(algorithm: usize, key: &[u8]) -> Vec<u8> {
    rustls::sign::public_key_to_spki(&ours(algorithm).public_key_alg_id(), key)
        .as_ref()
        .to_vec()
}

/// Go's verdict on a case, through the oracle's `sig_verify`: the key as a
/// SubjectPublicKeyInfo, checked as Go checks a certificate's signature
/// under the algorithm's x509 name.
pub fn go_verifies(
    oracle: &mut Oracle,
    algorithm: usize,
    key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    let request = json!({
        "spki": hex(&spki(algorithm, key)),
        "x509_alg": ALGORITHMS[algorithm].1,
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
