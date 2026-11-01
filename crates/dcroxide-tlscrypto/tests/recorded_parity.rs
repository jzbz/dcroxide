// SPDX-License-Identifier: ISC
//! The provider's verification verdicts held to ring's, as recorded while
//! ring was in the tree (ADR-0015).
//!
//! Until the switch this file, then `tests/ring_parity.rs`, proved the
//! provider's parity with rustls's ring provider by running ring beside
//! it: the cipher suites, hashes, key schedules and records, the key
//! exchange groups and the shares each takes, the signing keys and their
//! loading, the verification set, and handshakes between the two, both
//! ways.  The switch removed ring, and those comparisons with it.  What
//! stays is the record: the parity corpus (`sig_corpus`), each case with
//! ring's verdict, recorded from ring 0.17.14 through rustls 0.23.46,
//! which the provider must give, and Go's, which it must give but in the
//! classes of `GO_DIFFERS`.  ring's column cannot be made again, and the
//! regeneration that made it went with ring; Go's is checked again
//! through the oracle by `tests/go_differential.rs`.  Beside it, the
//! verification set's identifiers and its mapping to signature schemes
//! are held to ring's, recorded here from the sources of the rustls,
//! webpki and pki-types that ring's provider was built from.  The
//! provider's suites, groups and signature schemes, ring's lists, stay
//! held to ring's ClientHello, as recorded, by the node's TLS interop
//! matrix (`crates/dcroxide-node/tests/data/seeder-client-hello.json`).

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

mod sig_corpus;

use std::collections::BTreeMap;

use dcroxide_testutil::unhex;
use rustls::SignatureScheme;
use rustls::pki_types::SignatureVerificationAlgorithm;

/// The bounds the corpus was made within, so that it stays a file to
/// commit: its cases.
const MAX_CASES: usize = 20_000;
/// The same, on the compressed file's bytes.
const MAX_BYTES: u64 = 2_000_000;

/// What the provider makes of a class of the corpus.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Verdicts {
    /// Every case taken.
    Taken,
    /// Every case refused.
    Refused,
    /// Some cases each way.
    Both,
}

/// Each generated class of the corpus with what the provider, and ring,
/// make of it: the valid signatures, the other signature of the same r,
/// and an exponent Go refuses taken; the identity's encodings among
/// Ed25519's keys and R values, the messages whose challenge is a
/// multiple of a small-order key's order, and the PKCS#1 v1.5 signatures
/// under the identifiers without NULL, taken among refusals; everything
/// else refused, a key outside ring's bounds included.
const CLASS_VERDICTS: [(&str, Verdicts); 37] = [
    ("ecdsa-valid", Verdicts::Taken),
    ("ecdsa-high-s", Verdicts::Taken),
    ("ecdsa-other-algorithm", Verdicts::Refused),
    ("ecdsa-flip-key", Verdicts::Refused),
    ("ecdsa-flip-message", Verdicts::Refused),
    ("ecdsa-flip-signature", Verdicts::Refused),
    ("ecdsa-der", Verdicts::Refused),
    ("ecdsa-range", Verdicts::Refused),
    ("ecdsa-point-form", Verdicts::Refused),
    ("ed25519-valid", Verdicts::Taken),
    ("ed25519-flip-key", Verdicts::Refused),
    ("ed25519-flip-message", Verdicts::Refused),
    ("ed25519-flip-signature", Verdicts::Refused),
    ("ed25519-s-range", Verdicts::Refused),
    ("ed25519-length", Verdicts::Refused),
    ("ed25519-key-encoding", Verdicts::Both),
    ("ed25519-r-encoding", Verdicts::Both),
    ("ed25519-key-hash", Verdicts::Both),
    ("rsa-valid", Verdicts::Taken),
    ("rsa-exponent-above-go", Verdicts::Taken),
    ("rsa-modulus-1024", Verdicts::Refused),
    ("rsa-modulus-2040", Verdicts::Refused),
    ("rsa-modulus-8193", Verdicts::Refused),
    ("rsa-exponent-above-ring", Verdicts::Refused),
    ("rsa-exponent-refused", Verdicts::Refused),
    ("rsa-other-algorithm", Verdicts::Both),
    ("rsa-flip-key", Verdicts::Refused),
    ("rsa-flip-message", Verdicts::Refused),
    ("rsa-flip-signature", Verdicts::Refused),
    ("rsa-key-der", Verdicts::Refused),
    ("rsa-key-trailing-data", Verdicts::Refused),
    ("rsa-signature-range", Verdicts::Refused),
    ("rsa-pkcs1-encoding", Verdicts::Refused),
    ("rsa-pss-salt", Verdicts::Refused),
    ("wycheproof", Verdicts::Both),
    // Not classes of their own but checked the same way: every case of the
    // corpus, and its generated ones.
    ("all", Verdicts::Both),
    ("generated", Verdicts::Both),
];

/// Every case of the parity corpus gets the verdict recorded from ring
/// from the provider, and Go's recorded verdict, but in the classes of
/// `GO_DIFFERS`, each of which has a case where Go's differs.  Each class
/// goes the way `CLASS_VERDICTS` says.  The header is the corpus's own:
/// its algorithms, in the order of the provider's verification set, the
/// ring that gave its verdicts, the count of each class and of the
/// Wycheproof cases, and its compressed size, both within the bounds it
/// was made within; and the Wycheproof cases are 4,335, every case of the
/// 17 files but the 60 of PSS over SHA-1 and SHA-224 (`sig_corpus::cases`
/// holds each file to it).
#[test]
fn the_verifiers_give_the_recorded_verdicts_on_the_corpus() {
    let header = sig_corpus::read();
    let names: Vec<&str> = sig_corpus::ALGORITHMS
        .iter()
        .map(|(name, _)| *name)
        .collect();
    assert_eq!(header["algorithms"], serde_json::json!(names));
    let all = dcroxide_tlscrypto::SUPPORTED_SIG_ALGS.all;
    assert_eq!(all.len(), names.len());
    for (index, name) in names.iter().enumerate() {
        assert_eq!(format!("{:?}", all[index]), *name, "at {index}");
    }
    assert_eq!(header["ring"], "0.17.14");
    let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), sig_corpus::PATH);
    let size = std::fs::metadata(&path).expect("the corpus").len();
    assert_eq!(header["compressed_bytes"].as_u64(), Some(size));
    assert!(size <= MAX_BYTES, "{size} bytes");
    let cases = sig_corpus::cases();
    assert!(cases.len() <= MAX_CASES, "{} cases", cases.len());
    let mut classes: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut go_differs: BTreeMap<&str, usize> = BTreeMap::new();
    for case in &cases {
        let ours = sig_corpus::ours(case.algorithm)
            .verify_signature(&case.key, &case.message, &case.signature)
            .is_ok();
        assert_eq!(ours, case.ring, "{}: ring's recorded verdict", case.label);
        match sig_corpus::GO_DIFFERS
            .iter()
            .find(|(class, _)| *class == case.class)
        {
            Some((class, _)) => {
                *go_differs.entry(class).or_default() += usize::from(ours != case.go)
            }
            None => assert_eq!(ours, case.go, "{}: Go's recorded verdict", case.label),
        }
        let generated = (case.class != "wycheproof").then_some("generated");
        for class in [Some(case.class.as_str()), Some("all"), generated]
            .into_iter()
            .flatten()
        {
            let counts = classes.entry(class.to_owned()).or_default();
            if ours {
                counts.0 += 1;
            } else {
                counts.1 += 1;
            }
        }
    }
    for (class, _) in sig_corpus::GO_DIFFERS {
        assert!(
            go_differs.get(class).is_some_and(|&differs| differs > 0),
            "{class}: a case where Go's verdict differs, or no need for its entry"
        );
    }
    let observed: BTreeMap<String, Verdicts> = classes
        .iter()
        .map(|(class, &(taken, refused))| {
            let verdicts = match (taken, refused) {
                (_, 0) => Verdicts::Taken,
                (0, _) => Verdicts::Refused,
                _ => Verdicts::Both,
            };
            (class.clone(), verdicts)
        })
        .collect();
    let expected: BTreeMap<String, Verdicts> = CLASS_VERDICTS
        .iter()
        .map(|&(class, verdicts)| (class.to_owned(), verdicts))
        .collect();
    assert_eq!(observed, expected, "what the provider makes of each class");
    let recorded: BTreeMap<String, usize> =
        serde_json::from_value(header["classes"].clone()).expect("the classes");
    let counted: BTreeMap<String, usize> = classes
        .iter()
        .filter(|(class, _)| !matches!(class.as_str(), "wycheproof" | "all" | "generated"))
        .map(|(class, (taken, refused))| (class.clone(), taken + refused))
        .collect();
    assert_eq!(counted, recorded, "the count of each class");
    let wycheproof = classes["wycheproof"];
    assert_eq!(
        header["wycheproof_cases"].as_u64(),
        u64::try_from(wycheproof.0 + wycheproof.1).ok()
    );
    assert_eq!(
        wycheproof.0 + wycheproof.1,
        1460 + 210 + 2072 + 593,
        "Wycheproof's ECDSA, Ed25519, PKCS#1 v1.5 and PSS cases"
    );
}

/// The `AlgorithmIdentifier` contents ring's algorithms carry, in hex:
/// rustls-pki-types 1.15.1's `alg_id` constants, which webpki 0.103.16's
/// ring algorithms name (`rustls-pki-types-1.15.1/src/alg_id.rs:70-321`,
/// each from its `src/data/alg-*.der`), and webpki's own three PKCS#1
/// signature identifiers without the NULL parameters
/// (`rustls-webpki-0.103.16/src/ring_algs.rs:111-160`, from its
/// `src/data/alg-rsa-pkcs1-sha*-absent-params.der`).  Recorded from those
/// crates' sources when ring left the tree.
mod ring_ids {
    /// id-ecPublicKey with the secp256r1 parameters.
    pub const EC_P256: &str = "06072a8648ce3d020106082a8648ce3d030107";
    /// id-ecPublicKey with the secp384r1 parameters.
    pub const EC_P384: &str = "06072a8648ce3d020106052b81040022";
    /// ecdsa-with-SHA256.
    pub const ECDSA_SHA256: &str = "06082a8648ce3d040302";
    /// ecdsa-with-SHA384.
    pub const ECDSA_SHA384: &str = "06082a8648ce3d040303";
    /// id-Ed25519, for the key and the signature alike.
    pub const ED25519: &str = "06032b6570";
    /// rsaEncryption with NULL parameters.
    pub const RSA_ENCRYPTION: &str = "06092a864886f70d0101010500";
    /// sha256WithRSAEncryption with NULL parameters.
    pub const RSA_PKCS1_SHA256: &str = "06092a864886f70d01010b0500";
    /// sha384WithRSAEncryption with NULL parameters.
    pub const RSA_PKCS1_SHA384: &str = "06092a864886f70d01010c0500";
    /// sha512WithRSAEncryption with NULL parameters.
    pub const RSA_PKCS1_SHA512: &str = "06092a864886f70d01010d0500";
    /// sha256WithRSAEncryption without parameters.
    pub const RSA_PKCS1_SHA256_ABSENT: &str = "06092a864886f70d01010b";
    /// sha384WithRSAEncryption without parameters.
    pub const RSA_PKCS1_SHA384_ABSENT: &str = "06092a864886f70d01010c";
    /// sha512WithRSAEncryption without parameters.
    pub const RSA_PKCS1_SHA512_ABSENT: &str = "06092a864886f70d01010d";
    /// id-RSASSA-PSS with SHA-256, MGF1 over SHA-256 and a 32-byte salt.
    pub const RSA_PSS_SHA256: &str = "06092a864886f70d01010a3034a00f300d06096086480165030402010500\
                                      a11c301a06092a864886f70d010108300d06096086480165030402010500\
                                      a203020120";
    /// id-RSASSA-PSS with SHA-384, MGF1 over SHA-384 and a 48-byte salt.
    pub const RSA_PSS_SHA384: &str = "06092a864886f70d01010a3034a00f300d06096086480165030402020500\
                                      a11c301a06092a864886f70d010108300d06096086480165030402020500\
                                      a203020130";
    /// id-RSASSA-PSS with SHA-512, MGF1 over SHA-512 and a 64-byte salt.
    pub const RSA_PSS_SHA512: &str = "06092a864886f70d01010a3034a00f300d06096086480165030402030500\
                                      a11c301a06092a864886f70d010108300d06096086480165030402030500\
                                      a203020140";
}

/// ring's fourteen verification algorithms, by webpki's names, in the
/// order of rustls 0.23.46's ring provider, each with the public key and
/// signature identifiers webpki 0.103.16 gives its ring algorithm
/// (`rustls-0.23.46/src/crypto/ring/mod.rs:107-123`;
/// `rustls-webpki-0.103.16/src/ring_algs.rs:48-211`).
const RING_ALGORITHMS: [(&str, &str, &str); 14] = [
    (
        "ECDSA_P256_SHA256",
        ring_ids::EC_P256,
        ring_ids::ECDSA_SHA256,
    ),
    (
        "ECDSA_P256_SHA384",
        ring_ids::EC_P256,
        ring_ids::ECDSA_SHA384,
    ),
    (
        "ECDSA_P384_SHA256",
        ring_ids::EC_P384,
        ring_ids::ECDSA_SHA256,
    ),
    (
        "ECDSA_P384_SHA384",
        ring_ids::EC_P384,
        ring_ids::ECDSA_SHA384,
    ),
    ("ED25519", ring_ids::ED25519, ring_ids::ED25519),
    (
        "RSA_PSS_2048_8192_SHA256_LEGACY_KEY",
        ring_ids::RSA_ENCRYPTION,
        ring_ids::RSA_PSS_SHA256,
    ),
    (
        "RSA_PSS_2048_8192_SHA384_LEGACY_KEY",
        ring_ids::RSA_ENCRYPTION,
        ring_ids::RSA_PSS_SHA384,
    ),
    (
        "RSA_PSS_2048_8192_SHA512_LEGACY_KEY",
        ring_ids::RSA_ENCRYPTION,
        ring_ids::RSA_PSS_SHA512,
    ),
    (
        "RSA_PKCS1_2048_8192_SHA256",
        ring_ids::RSA_ENCRYPTION,
        ring_ids::RSA_PKCS1_SHA256,
    ),
    (
        "RSA_PKCS1_2048_8192_SHA384",
        ring_ids::RSA_ENCRYPTION,
        ring_ids::RSA_PKCS1_SHA384,
    ),
    (
        "RSA_PKCS1_2048_8192_SHA512",
        ring_ids::RSA_ENCRYPTION,
        ring_ids::RSA_PKCS1_SHA512,
    ),
    (
        "RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS",
        ring_ids::RSA_ENCRYPTION,
        ring_ids::RSA_PKCS1_SHA256_ABSENT,
    ),
    (
        "RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS",
        ring_ids::RSA_ENCRYPTION,
        ring_ids::RSA_PKCS1_SHA384_ABSENT,
    ),
    (
        "RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS",
        ring_ids::RSA_ENCRYPTION,
        ring_ids::RSA_PKCS1_SHA512_ABSENT,
    ),
];

/// ring's mapping of TLS signature schemes to those algorithms, by name:
/// the order rustls 0.23.46 offers the schemes in, and within each the
/// order it tries the algorithms in, TLS 1.3 only the first
/// (`rustls-0.23.46/src/crypto/ring/mod.rs:124-165`).
const RING_MAPPING: [(SignatureScheme, &[&str]); 9] = [
    (
        SignatureScheme::ECDSA_NISTP384_SHA384,
        &["ECDSA_P384_SHA384", "ECDSA_P256_SHA384"],
    ),
    (
        SignatureScheme::ECDSA_NISTP256_SHA256,
        &["ECDSA_P256_SHA256", "ECDSA_P384_SHA256"],
    ),
    (SignatureScheme::ED25519, &["ED25519"]),
    (
        SignatureScheme::RSA_PSS_SHA512,
        &["RSA_PSS_2048_8192_SHA512_LEGACY_KEY"],
    ),
    (
        SignatureScheme::RSA_PSS_SHA384,
        &["RSA_PSS_2048_8192_SHA384_LEGACY_KEY"],
    ),
    (
        SignatureScheme::RSA_PSS_SHA256,
        &["RSA_PSS_2048_8192_SHA256_LEGACY_KEY"],
    ),
    (
        SignatureScheme::RSA_PKCS1_SHA512,
        &["RSA_PKCS1_2048_8192_SHA512"],
    ),
    (
        SignatureScheme::RSA_PKCS1_SHA384,
        &["RSA_PKCS1_2048_8192_SHA384"],
    ),
    (
        SignatureScheme::RSA_PKCS1_SHA256,
        &["RSA_PKCS1_2048_8192_SHA256"],
    ),
];

/// An algorithm's name and its public key and signature identifiers.
fn identified(algorithm: &dyn SignatureVerificationAlgorithm) -> (String, Vec<u8>, Vec<u8>) {
    (
        format!("{algorithm:?}"),
        algorithm.public_key_alg_id().as_ref().to_vec(),
        algorithm.signature_alg_id().as_ref().to_vec(),
    )
}

/// A recorded algorithm's name and identifiers, as [`identified`] gives
/// them.
fn recorded(name: &str) -> (String, Vec<u8>, Vec<u8>) {
    let (_, public_key, signature) = RING_ALGORITHMS
        .iter()
        .find(|(listed, _, _)| *listed == name)
        .unwrap_or_else(|| panic!("{name}: one of ring's algorithms"));
    (name.to_owned(), unhex(public_key), unhex(signature))
}

/// The verification set is ring's as recorded, as `tests/ring_parity.rs`
/// held it to ring's live until the switch: the fourteen algorithms in
/// ring's order, each with ring's identifiers, each pair of them once; and
/// the mapping's nine schemes in ring's order, each with ring's algorithms
/// in ring's order, by name and by identifiers.  So a scheme moved, an
/// algorithm moved within a scheme or in the set, or an identifier
/// changed fails here, and not only where a handshake would notice.
#[test]
fn the_verification_set_is_rings_as_recorded() {
    let set = dcroxide_tlscrypto::SUPPORTED_SIG_ALGS;
    let ours: Vec<_> = set
        .all
        .iter()
        .map(|algorithm| identified(*algorithm))
        .collect();
    let rings: Vec<_> = RING_ALGORITHMS
        .iter()
        .map(|(name, _, _)| recorded(name))
        .collect();
    assert_eq!(ours, rings, "the fourteen algorithms and their identifiers");
    let mut pairs = std::collections::BTreeSet::new();
    for (name, public_key, signature) in &ours {
        assert!(
            pairs.insert((public_key, signature)),
            "{name}: a pair of its own"
        );
    }
    assert_eq!(
        set.supported_schemes(),
        RING_MAPPING
            .iter()
            .map(|(scheme, _)| *scheme)
            .collect::<Vec<_>>(),
        "the schemes in ring's order"
    );
    assert_eq!(set.mapping.len(), RING_MAPPING.len());
    for ((scheme, algorithms), (ring_scheme, ring_names)) in set.mapping.iter().zip(RING_MAPPING) {
        assert_eq!(*scheme, ring_scheme);
        let ours: Vec<_> = algorithms
            .iter()
            .map(|algorithm| identified(*algorithm))
            .collect();
        let rings: Vec<_> = ring_names.iter().map(|name| recorded(name)).collect();
        assert_eq!(ours, rings, "{scheme:?}: ring's algorithms in ring's order");
    }
}
