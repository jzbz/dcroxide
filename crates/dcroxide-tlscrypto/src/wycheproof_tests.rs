// SPDX-License-Identifier: ISC
//! Wycheproof's vectors for the crate's record protection, HMAC, HKDF, key
//! exchange and signature verification (ADR-0015 T10), run through the
//! crate's own code: the AEADs the suites instantiate, through the `seal`
//! and `open` every record goes through; HMAC as rustls asks for a tag;
//! HKDF as rustls builds it on that HMAC; each key exchange group's
//! `complete`, from the case's private key; and the verification
//! algorithms of `SUPPORTED_SIG_ALGS`, on the key as a certificate's
//! SubjectPublicKeyInfo carries it.  The files, their commit and their
//! hashes are in `tests/data/wycheproof/SOURCE`.
//!
//! A unit-test module rather than an integration test, because the AEADs
//! and a key exchange with a fixed private key are reached through
//! crate-private functions.  The harness checks each file's `algorithm`
//! and `schema` before it reads the groups, and counts what it runs and
//! what it skips against fixed totals, so a truncated or replaced file
//! fails rather than passing on fewer cases.  A `valid` case must succeed
//! with Wycheproof's answer and an `invalid` one must fail.  The key
//! exchange and signature files have `acceptable` cases, and each is
//! decided by its flags under [`ACCEPTABLE_KX`] or [`ACCEPTABLE_SIG`],
//! which give the reason for each verdict; a case none of their entries
//! covers fails the test until one is written down, and any `acceptable`
//! case in the other files fails it too.  A PSS group whose parameters
//! TLS does not sign with is run as must-refuse, valid cases and all
//! ([`pss_policy`]).  Every key exchange and signature case, whatever its
//! result, is also held to Go through the oracle, `crypto/ecdh` for the
//! one and `crypto/x509`'s signature check for the other, which is how
//! the tables are checked against Go: where there is no oracle that
//! comparison is skipped, unless `DCROXIDE_REQUIRE_ORACLE` is set, as in
//! CI, where it also requires the reference Go.

use std::io::Read;

use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use dcroxide_testutil::{Oracle, hex, unhex};
use rustls::crypto::hmac::Hmac;
use rustls::crypto::tls13::{Hkdf, OutputLengthError};
use rustls::pki_types::SignatureVerificationAlgorithm;
use rustls::{Error, NamedGroup, PeerMisbehaved};
use serde_json::Value;

use crate::aead::{self, RecordAead};
use crate::hmac::{HKDF_SHA256, HKDF_SHA384, HMAC_SHA256, HMAC_SHA384};
use crate::kx::exchange_with;
use crate::verify;

/// The parsed vector file `name`, from `tests/data/wycheproof`.
fn load(name: &str) -> Value {
    let path = format!(
        "{}/tests/data/wycheproof/{name}.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let file = std::fs::File::open(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let mut json = String::new();
    flate2::read::GzDecoder::new(file)
        .read_to_string(&mut json)
        .unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&json).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// A string field of a file, group or case.
fn text<'a>(v: &'a Value, field: &str) -> &'a str {
    v[field]
        .as_str()
        .unwrap_or_else(|| panic!("no string {field} in {v}"))
}

/// A hex field of a case, decoded.
fn bytes(v: &Value, field: &str) -> Vec<u8> {
    unhex(text(v, field))
}

/// A number field of a file, group or case.
fn number(v: &Value, field: &str) -> u64 {
    v[field]
        .as_u64()
        .unwrap_or_else(|| panic!("no number {field} in {v}"))
}

/// The cases of a group.
fn cases(group: &Value) -> &[Value] {
    group["tests"]
        .as_array()
        .unwrap_or_else(|| panic!("no tests in {group}"))
}

/// What a case expects.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Expect {
    /// The operation succeeds, with the answer given.
    Valid,
    /// The operation fails.
    Invalid,
}

/// What `case` expects; an `acceptable` result has no policy for these
/// files, and fails.
fn expect(case: &Value) -> Expect {
    match text(case, "result") {
        "valid" => Expect::Valid,
        "invalid" => Expect::Invalid,
        other => panic!(
            "tcId {}: no policy for a result of {other:?}",
            number(case, "tcId")
        ),
    }
}

/// How many cases of each kind a file's run met.
#[derive(Default, PartialEq, Debug)]
struct Tally {
    /// Valid cases run.
    valid: usize,
    /// Invalid cases run.
    invalid: usize,
    /// Acceptable cases run, each as its policy decides.
    acceptable: usize,
    /// Cases in groups of a shape no suite uses, not run.
    skipped: usize,
}

impl Tally {
    /// Count a case that was run.
    fn ran(&mut self, expect: Expect) {
        match expect {
            Expect::Valid => self.valid = self.valid.saturating_add(1),
            Expect::Invalid => self.invalid = self.invalid.saturating_add(1),
        }
    }

    /// Count an acceptable case that was run.
    fn ran_acceptable(&mut self) {
        self.acceptable = self.acceptable.saturating_add(1);
    }

    /// Count a group's cases as skipped.
    fn skip(&mut self, group: &Value) {
        self.skipped = self.skipped.saturating_add(cases(group).len());
    }

    /// Every case counted, which must be the file's `numberOfTests`.
    fn total(&self) -> usize {
        self.valid
            .saturating_add(self.invalid)
            .saturating_add(self.acceptable)
            .saturating_add(self.skipped)
    }
}

/// Run every group of `file`, which must be of `algorithm` under `schema`,
/// through `run_group`, and check the tally against `expected`.
fn run_file(
    file: &str,
    algorithm: &str,
    schema: &str,
    expected: Tally,
    mut run_group: impl FnMut(&Value, &mut Tally),
) {
    let vectors = load(file);
    assert_eq!(text(&vectors, "algorithm"), algorithm, "{file}");
    assert_eq!(text(&vectors, "schema"), schema, "{file}");
    let mut tally = Tally::default();
    let groups = vectors["testGroups"]
        .as_array()
        .unwrap_or_else(|| panic!("{file}: no testGroups"));
    for group in groups {
        run_group(group, &mut tally);
    }
    assert_eq!(
        u64::try_from(tally.total()).ok(),
        Some(number(&vectors, "numberOfTests")),
        "{file}: every case counted"
    );
    assert_eq!(tally, expected, "{file}");
}

/// One AEAD case.
struct AeadCase {
    /// Wycheproof's case number.
    id: u64,
    /// The key.
    key: Vec<u8>,
    /// The nonce.
    nonce: [u8; 12],
    /// The additional data.
    aad: Vec<u8>,
    /// The plaintext.
    msg: Vec<u8>,
    /// The ciphertext and its tag.
    sealed: Vec<u8>,
    /// Whether the ciphertext is authentic.
    expect: Expect,
}

/// The cases of an AEAD group, or `None` when the group's sizes are not a
/// TLS suite's: a 96-bit nonce, a 128-bit tag and a key of one of
/// `key_bits`.
fn tls_aead_group(group: &Value, key_bits: &[u64]) -> Option<Vec<AeadCase>> {
    let tls_shape = number(group, "ivSize") == 96
        && number(group, "tagSize") == 128
        && key_bits.contains(&number(group, "keySize"));
    if !tls_shape {
        return None;
    }
    Some(
        cases(group)
            .iter()
            .map(|case| AeadCase {
                id: number(case, "tcId"),
                key: bytes(case, "key"),
                nonce: <[u8; 12]>::try_from(bytes(case, "iv")).expect("a 96-bit nonce"),
                aad: bytes(case, "aad"),
                msg: bytes(case, "msg"),
                sealed: [bytes(case, "ct"), bytes(case, "tag")].concat(),
                expect: expect(case),
            })
            .collect(),
    )
}

/// Run one AEAD case on `A`: a valid case seals to Wycheproof's ciphertext
/// and tag and opens back to the plaintext; an invalid one fails to open,
/// and leaves its buffer as it was.
fn run_aead<A: RecordAead>(case: &AeadCase) {
    let id = case.id;
    let aead = A::new_from_slice(&case.key).expect("a key of the group's size");
    if case.expect == Expect::Valid {
        let mut body = case.msg.clone();
        let tag = aead::seal(&aead, case.nonce, &case.aad, &mut body).expect("sealed");
        body.extend_from_slice(&tag);
        assert_eq!(body, case.sealed, "tcId {id}: sealed");
    }
    let mut body = case.sealed.clone();
    let opened = aead::open(&aead, case.nonce, &case.aad, &mut body);
    match case.expect {
        Expect::Valid => {
            assert_eq!(opened, Ok(case.msg.len()), "tcId {id}: opened");
            assert_eq!(body.get(..case.msg.len()), Some(&case.msg[..]), "tcId {id}");
        }
        Expect::Invalid => {
            assert_eq!(opened, Err(Error::DecryptError), "tcId {id}: refused");
            assert_eq!(body, case.sealed, "tcId {id}: left as it was");
        }
    }
}

#[test]
fn aes_gcm_answers_wycheproof() {
    // The run takes the 128- and 256-bit keys with 96-bit nonces; the rest
    // of the file is AES-192 and other nonce lengths, which no suite uses.
    let expected = Tally {
        valid: 79,
        invalid: 54,
        acceptable: 0,
        skipped: 183,
    };
    run_file(
        "aes_gcm_test.json",
        "AES-GCM",
        "aead_test_schema_v1.json",
        expected,
        |group, tally| match tls_aead_group(group, &[128, 256]) {
            Some(cases) => {
                for case in &cases {
                    if case.key.len() == 16 {
                        run_aead::<Aes128Gcm>(case);
                    } else {
                        run_aead::<Aes256Gcm>(case);
                    }
                    tally.ran(case.expect);
                }
            }
            None => tally.skip(group),
        },
    );
}

#[test]
fn chacha20_poly1305_answers_wycheproof() {
    // The nine skipped are the nonce lengths other than 96 bits, which
    // RFC 8439's construction does not take.
    let expected = Tally {
        valid: 256,
        invalid: 60,
        acceptable: 0,
        skipped: 9,
    };
    run_file(
        "chacha20_poly1305_test.json",
        "CHACHA20-POLY1305",
        "aead_test_schema_v1.json",
        expected,
        |group, tally| match tls_aead_group(group, &[256]) {
            Some(cases) => {
                for case in &cases {
                    run_aead::<ChaCha20Poly1305>(case);
                    tally.ran(case.expect);
                }
            }
            None => tally.skip(group),
        },
    );
}

/// Run an HMAC file: the tag of each case's message under its key, cut to
/// the group's tag size, must equal Wycheproof's for a valid case and
/// differ from it for an invalid one.
fn hmac_answers_wycheproof(file: &str, algorithm: &str, hmac: &dyn Hmac) {
    let expected = Tally {
        valid: 66,
        invalid: 108,
        acceptable: 0,
        skipped: 0,
    };
    run_file(
        file,
        algorithm,
        "mac_test_schema_v1.json",
        expected,
        |group, tally| {
            let tag_len = usize::try_from(number(group, "tagSize") / 8).expect("a tag size");
            for case in cases(group) {
                let id = number(case, "tcId");
                let tag = hmac
                    .with_key(&bytes(case, "key"))
                    .sign(&[&bytes(case, "msg")]);
                let cut = tag
                    .as_ref()
                    .get(..tag_len)
                    .expect("a tag size the hash has");
                let expect = expect(case);
                assert_eq!(
                    cut == bytes(case, "tag"),
                    expect == Expect::Valid,
                    "{file} tcId {id}"
                );
                tally.ran(expect);
            }
        },
    );
}

#[test]
fn hmac_sha256_answers_wycheproof() {
    hmac_answers_wycheproof("hmac_sha256_test.json", "HMACSHA256", &HMAC_SHA256);
}

#[test]
fn hmac_sha384_answers_wycheproof() {
    hmac_answers_wycheproof("hmac_sha384_test.json", "HMACSHA384", &HMAC_SHA384);
}

/// Run an HKDF file: extracting from each case's input keying material and
/// salt and expanding with its info must give Wycheproof's output for a
/// valid case; the invalid ones ask for more than 255 hash blocks, which
/// must be refused.
fn hkdf_answers_wycheproof(file: &str, algorithm: &str, hkdf: &dyn Hkdf, valid: usize) {
    let expected = Tally {
        valid,
        invalid: 3,
        acceptable: 0,
        skipped: 0,
    };
    run_file(
        file,
        algorithm,
        "hkdf_test_schema_v1.json",
        expected,
        |group, tally| {
            for case in cases(group) {
                let id = number(case, "tcId");
                let size = usize::try_from(number(case, "size")).expect("a size");
                let expander =
                    hkdf.extract_from_secret(Some(&bytes(case, "salt")), &bytes(case, "ikm"));
                let mut okm = vec![0; size];
                let expanded = expander.expand_slice(&[&bytes(case, "info")], &mut okm);
                let expect = expect(case);
                match expect {
                    Expect::Valid => {
                        assert!(expanded.is_ok(), "{file} tcId {id}");
                        assert_eq!(okm, bytes(case, "okm"), "{file} tcId {id}");
                    }
                    Expect::Invalid => {
                        assert!(
                            matches!(expanded, Err(OutputLengthError)),
                            "{file} tcId {id}"
                        );
                        assert!(
                            size > expander.hash_len().saturating_mul(255),
                            "{file} tcId {id}: invalid for its size alone"
                        );
                    }
                }
                tally.ran(expect);
            }
        },
    );
}

#[test]
fn hkdf_sha256_answers_wycheproof() {
    hkdf_answers_wycheproof("hkdf_sha256_test.json", "HKDF-SHA-256", &HKDF_SHA256, 83);
}

#[test]
fn hkdf_sha384_answers_wycheproof() {
    hkdf_answers_wycheproof("hkdf_sha384_test.json", "HKDF-SHA-384", &HKDF_SHA384, 80);
}

/// What the provider must do with an `acceptable` key exchange case: the
/// verdict of the first entry whose flag the case carries, for the reason
/// the entry gives.  The order matters only for an X25519 share of small
/// order that is also on the twist or written at or above p, which the
/// first entry refuses.
const ACCEPTABLE_KX: [(&str, Expect, &str); 4] = [
    (
        "ZeroSharedSecret",
        Expect::Invalid,
        "an X25519 share of small order gives an all-zero secret, which Go and \
         ring refuse (`crypto/ecdh/x25519.go:85-87`, \
         `ring-0.17.14/src/ec/curve25519/x25519.rs:158-162`)",
    ),
    (
        "CompressedPoint",
        Expect::Invalid,
        "a TLS key share is an uncompressed point (RFC 8446 §4.2.8.2), and Go \
         refuses every other form (`crypto/ecdh/nist.go:120-125`)",
    ),
    (
        "Twist",
        Expect::Valid,
        "X25519 takes a u-coordinate on the twist, as it takes any 32 bytes \
         (RFC 7748 §5, `crypto/ecdh/x25519.go:69-80`)",
    ),
    (
        "NonCanonicalPublic",
        Expect::Valid,
        "X25519 reduces a u-coordinate at or above p, as RFC 7748 §5 and Go \
         read it",
    ),
];

/// What a key exchange case expects, and why: Wycheproof's own word for a
/// valid or invalid case, and for an acceptable one the verdict
/// [`ACCEPTABLE_KX`] gives it.
fn kx_expect(case: &Value) -> (Expect, &'static str) {
    match text(case, "result") {
        "valid" => (Expect::Valid, "valid"),
        "invalid" => (Expect::Invalid, "invalid"),
        "acceptable" => {
            let flags = case["flags"]
                .as_array()
                .unwrap_or_else(|| panic!("no flags in {case}"));
            ACCEPTABLE_KX
                .iter()
                .find(|(flag, ..)| flags.iter().any(|f| f == flag))
                .map(|&(_, expect, why)| (expect, why))
                .unwrap_or_else(|| {
                    panic!(
                        "tcId {}: no policy for an acceptable case flagged {flags:?}",
                        number(case, "tcId")
                    )
                })
        }
        other => panic!(
            "tcId {}: no policy for a result of {other:?}",
            number(case, "tcId")
        ),
    }
}

/// A key exchange vector file and what the harness needs to run it.
struct KxFile {
    /// The file's name.
    name: &'static str,
    /// The group its cases are run on.
    group: NamedGroup,
    /// The curve as the file's groups name it.
    curve: &'static str,
    /// The curve as the oracle's `ecdh` command names it.
    go_curve: &'static str,
    /// The length of a private key: a NIST curve's field, or X25519's 32.
    private_len: usize,
}

/// The four key exchange files.
const KX_FILES: [KxFile; 4] = [
    KxFile {
        name: "x25519_test.json",
        group: NamedGroup::X25519,
        curve: "curve25519",
        go_curve: "X25519",
        private_len: 32,
    },
    KxFile {
        name: "ecdh_secp256r1_ecpoint_test.json",
        group: NamedGroup::secp256r1,
        curve: "secp256r1",
        go_curve: "P-256",
        private_len: 32,
    },
    KxFile {
        name: "ecdh_secp384r1_ecpoint_test.json",
        group: NamedGroup::secp384r1,
        curve: "secp384r1",
        go_curve: "P-384",
        private_len: 48,
    },
    KxFile {
        name: "ecdh_secp521r1_ecpoint_test.json",
        group: NamedGroup::secp521r1,
        curve: "secp521r1",
        go_curve: "P-521",
        private_len: 66,
    },
];

impl KxFile {
    /// A case's private key at the length the group takes.  X25519's is
    /// its 32 bytes as they stand.  Wycheproof writes a NIST key as ASN.1
    /// writes the integer, with a leading zero byte when its top bit is
    /// set and without the leading zeros a smaller value has, so it is cut
    /// to its digits and padded back to the field's length.
    fn private(&self, case: &Value) -> Vec<u8> {
        let private = bytes(case, "private");
        if self.group == NamedGroup::X25519 {
            return private;
        }
        let start = private
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(private.len());
        let digits = &private[start..];
        let pad = self
            .private_len
            .checked_sub(digits.len())
            .unwrap_or_else(|| {
                panic!(
                    "{} tcId {}: a private key longer than the field",
                    self.name,
                    number(case, "tcId")
                )
            });
        [vec![0; pad], digits.to_vec()].concat()
    }

    /// The group's answer to a case: the secret its exchange from the
    /// case's private key agrees with the case's public key, or the error
    /// it refuses the public key with.
    fn ours(&self, case: &Value) -> Result<Vec<u8>, Error> {
        exchange_with(self.group, &self.private(case))
            .unwrap_or_else(|| {
                panic!(
                    "{} tcId {}: a private key the group takes",
                    self.name,
                    number(case, "tcId")
                )
            })
            .complete(&bytes(case, "public"))
            .map(|shared| shared.secret_bytes().to_vec())
    }

    /// Go's answer to a case, through the oracle's `ecdh`: the secret, or
    /// `None` where Go refuses the public key.
    fn go(&self, oracle: &mut Oracle, case: &Value) -> Option<Vec<u8>> {
        let request = serde_json::json!({
            "curve": self.go_curve,
            "private": hex(&self.private(case)),
            "public": text(case, "public"),
        });
        let response = oracle.call("ecdh", request.to_string().as_bytes());
        dcroxide_testutil::require_reference_go(
            response["go_version"].as_str().unwrap_or_default(),
        );
        match response["result"].as_str() {
            Some(refused) if refused.starts_with("refused: ") => None,
            Some(secret) => Some(unhex(secret)),
            None => panic!(
                "{} tcId {}: the oracle answered {response}",
                self.name,
                number(case, "tcId")
            ),
        }
    }
}

/// Run a key exchange file: a valid case, and an acceptable one its
/// policy accepts, must agree Wycheproof's secret; an invalid one, and an
/// acceptable one its policy refuses, must be refused as an invalid key
/// share; and every case must get Go's answer, the same secret or a
/// refusal, where there is an oracle.
fn kx_answers_wycheproof(file: &KxFile, algorithm: &str, schema: &str, expected: Tally) {
    let mut oracle = dcroxide_testutil::oracle_or_skip();
    run_file(file.name, algorithm, schema, expected, |group, tally| {
        assert_eq!(text(group, "curve"), file.curve, "{}", file.name);
        for case in cases(group) {
            let id = number(case, "tcId");
            let (expect, why) = kx_expect(case);
            let ours = file.ours(case);
            if let Some(oracle) = oracle.as_mut() {
                assert_eq!(
                    ours.as_ref().ok(),
                    file.go(oracle, case).as_ref(),
                    "{} tcId {id}: Go's answer",
                    file.name
                );
            }
            match expect {
                Expect::Valid => {
                    assert_eq!(
                        ours,
                        Ok(bytes(case, "shared")),
                        "{} tcId {id}: {why}",
                        file.name
                    );
                }
                Expect::Invalid => assert_eq!(
                    ours,
                    Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare)),
                    "{} tcId {id}: {why}",
                    file.name
                ),
            }
            if text(case, "result") == "acceptable" {
                tally.ran_acceptable();
            } else {
                tally.ran(expect);
            }
        }
    });
}

#[test]
fn x25519_answers_wycheproof() {
    // The acceptable cases are the shares of small order, refused, and the
    // twist's and the non-canonical u-coordinates, taken.
    let expected = Tally {
        valid: 264,
        invalid: 0,
        acceptable: 254,
        skipped: 0,
    };
    kx_answers_wycheproof(&KX_FILES[0], "XDH", "xdh_comp_schema_v1.json", expected);
}

#[test]
fn p256_ecdh_answers_wycheproof() {
    // The one acceptable case is a compressed share, refused.
    let expected = Tally {
        valid: 330,
        invalid: 24,
        acceptable: 1,
        skipped: 0,
    };
    let schema = "ecdh_ecpoint_test_schema_v1.json";
    kx_answers_wycheproof(&KX_FILES[1], "ECDH", schema, expected);
}

#[test]
fn p384_ecdh_answers_wycheproof() {
    let expected = Tally {
        valid: 771,
        invalid: 18,
        acceptable: 1,
        skipped: 0,
    };
    let schema = "ecdh_ecpoint_test_schema_v1.json";
    kx_answers_wycheproof(&KX_FILES[2], "ECDH", schema, expected);
}

#[test]
fn p521_ecdh_answers_wycheproof() {
    let expected = Tally {
        valid: 632,
        invalid: 28,
        acceptable: 1,
        skipped: 0,
    };
    let schema = "ecdh_ecpoint_test_schema_v1.json";
    kx_answers_wycheproof(&KX_FILES[3], "ECDH", schema, expected);
}

/// What the provider must do with an `acceptable` signature case: the
/// verdict of the first entry whose flag the case carries, for the reason
/// the entry gives.
const ACCEPTABLE_SIG: [(&str, Expect, &str); 3] = [
    (
        "MissingNull",
        Expect::Invalid,
        "the DigestInfo of PKCS#1 v1.5 carries NULL parameters, and ring and Go \
         build the whole encoding with them and compare it \
         (`ring-0.17.14/src/rsa/padding/pkcs1.rs:51-93`, \
         `crypto/internal/fips140/rsa/pkcs1v15.go:120-126`)",
    ),
    (
        "SmallOrderPublicKey",
        Expect::Valid,
        "Go and ring take a key of small order, checking no order, and these \
         signatures meet the cofactorless equation they check as well as the \
         cofactored one (`crypto/internal/fips140/ed25519/ed25519.go:290-327`)",
    ),
    (
        "MixedOrderPublicKey",
        Expect::Valid,
        "Go and ring take a key with a torsion component, checking no \
         subgroup, and these signatures meet the cofactorless equation",
    ),
];

/// What a signature case expects, and why: Wycheproof's own word for a
/// valid or invalid case, `refused` in place of a valid case's verdict
/// where the group's parameters are not TLS's, and for an acceptable one
/// what [`ACCEPTABLE_SIG`] gives it.
fn sig_expect(case: &Value, refused: Option<&'static str>) -> (Expect, &'static str) {
    match (text(case, "result"), refused) {
        ("valid", None) => (Expect::Valid, "valid"),
        ("valid", Some(why)) => (Expect::Invalid, why),
        ("invalid", _) => (Expect::Invalid, "invalid"),
        ("acceptable", _) => {
            let flags = case["flags"]
                .as_array()
                .unwrap_or_else(|| panic!("no flags in {case}"));
            ACCEPTABLE_SIG
                .iter()
                .find(|(flag, ..)| flags.iter().any(|f| f == flag))
                .map(|&(_, expect, why)| (expect, why))
                .unwrap_or_else(|| {
                    panic!(
                        "tcId {}: no policy for an acceptable case flagged {flags:?}",
                        number(case, "tcId")
                    )
                })
        }
        (other, _) => panic!(
            "tcId {}: no policy for a result of {other:?}",
            number(case, "tcId")
        ),
    }
}

/// How a group of a signature file is run: the algorithm, its name as Go's
/// `x509.SignatureAlgorithm` gives it, and the reason a valid case must
/// still be refused, when the group's parameters are not TLS's.
type SigGroup = (
    &'static dyn SignatureVerificationAlgorithm,
    &'static str,
    Option<&'static str>,
);

/// Go's verdict on a signature case, through the oracle's `sig_verify`:
/// the group's SubjectPublicKeyInfo, as Wycheproof gives it, checked as Go
/// checks a certificate's signature under `x509_alg`.
fn go_verifies(oracle: &mut Oracle, spki: &str, x509_alg: &str, case: &Value) -> bool {
    let request = serde_json::json!({
        "spki": spki,
        "x509_alg": x509_alg,
        "message": text(case, "msg"),
        "signature": text(case, "sig"),
    });
    let response = oracle.call("sig_verify", request.to_string().as_bytes());
    dcroxide_testutil::require_reference_go(response["go_version"].as_str().unwrap_or_default());
    match response["result"].as_str() {
        Some("ok") => true,
        Some(refused) if refused.starts_with("refused: ") => false,
        _ => panic!(
            "tcId {}: the oracle answered {response}",
            number(case, "tcId")
        ),
    }
}

/// Run a signature file: each case of each group `run` picks, on the key
/// `key` takes from the group, must get its expected verdict, and Go's,
/// where there is an oracle; the groups `run` passes over are counted as
/// skipped.
fn sig_answers_wycheproof(
    file: &str,
    algorithm: &str,
    schema: &str,
    expected: Tally,
    run: impl Fn(&Value) -> Option<SigGroup>,
    key: impl Fn(&Value) -> Vec<u8>,
) {
    let mut oracle = dcroxide_testutil::oracle_or_skip();
    run_file(file, algorithm, schema, expected, |group, tally| {
        let Some((algorithm, x509_alg, refused)) = run(group) else {
            tally.skip(group);
            return;
        };
        let public_key = key(group);
        for case in cases(group) {
            let id = number(case, "tcId");
            let (expect, why) = sig_expect(case, refused);
            let ours = algorithm
                .verify_signature(&public_key, &bytes(case, "msg"), &bytes(case, "sig"))
                .is_ok();
            if let Some(oracle) = oracle.as_mut() {
                let spki = text(group, "publicKeyDer");
                assert_eq!(
                    ours,
                    go_verifies(oracle, spki, x509_alg, case),
                    "{file} tcId {id}: Go's verdict"
                );
            }
            assert_eq!(ours, expect == Expect::Valid, "{file} tcId {id}: {why}");
            if text(case, "result") == "acceptable" {
                tally.ran_acceptable();
            } else {
                tally.ran(expect);
            }
        }
    });
}

/// The uncompressed point of an ECDSA group's key.
fn ecdsa_key(group: &Value) -> Vec<u8> {
    bytes(&group["publicKey"], "uncompressed")
}

/// The `RSAPublicKey` of an RSA group's key.
fn rsa_key(group: &Value) -> Vec<u8> {
    bytes(group, "publicKeyAsn")
}

/// Run an ECDSA file, whose groups are all on `curve` with `sha`, under
/// `run`'s algorithm.
fn ecdsa_answers_wycheproof(file: &str, curve: &str, sha: &str, run: SigGroup, expected: Tally) {
    sig_answers_wycheproof(
        file,
        "ECDSA",
        "ecdsa_verify_schema_v1.json",
        expected,
        |group| {
            assert_eq!(text(&group["publicKey"], "curve"), curve, "{file}");
            assert_eq!(text(group, "sha"), sha, "{file}");
            Some(run)
        },
        ecdsa_key,
    );
}

#[test]
fn ecdsa_p256_sha256_answers_wycheproof() {
    let expected = Tally {
        valid: 174,
        invalid: 310,
        acceptable: 0,
        skipped: 0,
    };
    let run = (verify::ECDSA_P256_SHA256, "ECDSA-SHA256", None);
    let file = "ecdsa_secp256r1_sha256_test.json";
    ecdsa_answers_wycheproof(file, "secp256r1", "SHA-256", run, expected);
}

#[test]
fn ecdsa_p384_sha256_answers_wycheproof() {
    let expected = Tally {
        valid: 162,
        invalid: 310,
        acceptable: 0,
        skipped: 0,
    };
    let run = (verify::ECDSA_P384_SHA256, "ECDSA-SHA256", None);
    let file = "ecdsa_secp384r1_sha256_test.json";
    ecdsa_answers_wycheproof(file, "secp384r1", "SHA-256", run, expected);
}

#[test]
fn ecdsa_p384_sha384_answers_wycheproof() {
    let expected = Tally {
        valid: 194,
        invalid: 310,
        acceptable: 0,
        skipped: 0,
    };
    let run = (verify::ECDSA_P384_SHA384, "ECDSA-SHA384", None);
    let file = "ecdsa_secp384r1_sha384_test.json";
    ecdsa_answers_wycheproof(file, "secp384r1", "SHA-384", run, expected);
}

#[test]
fn ed25519_answers_wycheproof() {
    // The acceptable cases are keys of small order and keys with a torsion
    // component, all taken.
    let expected = Tally {
        valid: 117,
        invalid: 64,
        acceptable: 29,
        skipped: 0,
    };
    sig_answers_wycheproof(
        "ed25519_test.json",
        "EDDSA",
        "eddsa_verify_schema_v1.json",
        expected,
        |group| {
            assert_eq!(text(&group["publicKey"], "curve"), "edwards25519");
            Some((verify::ED25519, "Ed25519", None))
        },
        |group| bytes(&group["publicKey"], "pk"),
    );
}

/// The PKCS#1 v1.5 algorithm of a hash as Wycheproof names it, with Go's
/// name for it.
fn pkcs1_for(sha: &str) -> (&'static dyn SignatureVerificationAlgorithm, &'static str) {
    match sha {
        "SHA-256" => (verify::RSA_PKCS1_2048_8192_SHA256, "SHA256-RSA"),
        "SHA-384" => (verify::RSA_PKCS1_2048_8192_SHA384, "SHA384-RSA"),
        "SHA-512" => (verify::RSA_PKCS1_2048_8192_SHA512, "SHA512-RSA"),
        other => panic!("no PKCS#1 v1.5 algorithm for {other}"),
    }
}

#[test]
fn rsa_pkcs1_answers_wycheproof() {
    // Each file's one acceptable case is a DigestInfo missing its NULL,
    // refused.
    for (file, sha, valid, invalid) in [
        ("rsa_signature_2048_sha256_test.json", "SHA-256", 9, 249),
        ("rsa_signature_2048_sha384_test.json", "SHA-384", 7, 250),
        ("rsa_signature_2048_sha512_test.json", "SHA-512", 8, 250),
        ("rsa_signature_3072_sha256_test.json", "SHA-256", 8, 250),
        ("rsa_signature_3072_sha384_test.json", "SHA-384", 7, 251),
        ("rsa_signature_3072_sha512_test.json", "SHA-512", 8, 251),
        ("rsa_signature_4096_sha384_test.json", "SHA-384", 7, 251),
        ("rsa_signature_4096_sha512_test.json", "SHA-512", 7, 251),
    ] {
        let expected = Tally {
            valid,
            invalid,
            acceptable: 1,
            skipped: 0,
        };
        sig_answers_wycheproof(
            file,
            "RSASSA-PKCS1-v1_5",
            "rsassa_pkcs1_verify_schema_v1.json",
            expected,
            |group| {
                assert_eq!(text(group, "sha"), sha, "{file}");
                let (algorithm, go) = pkcs1_for(sha);
                Some((algorithm, go, None))
            },
            rsa_key,
        );
    }
}

/// How a PSS group runs: under the PSS algorithm of its hash, when the
/// provider has one, and as must-refuse when its MGF1 hash or salt length
/// is not what TLS signs with (RFC 8446 §4.2.3: the message's hash, and a
/// salt the hash's length), which ring and Go's `crypto/tls` alike
/// require; `None`, to be skipped, for a hash no algorithm takes.
fn pss_policy(group: &Value) -> Option<SigGroup> {
    let (algorithm, go, len): (&'static dyn SignatureVerificationAlgorithm, _, _) =
        match text(group, "sha") {
            "SHA-256" => (
                verify::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
                "SHA256-RSAPSS",
                32,
            ),
            "SHA-384" => (
                verify::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
                "SHA384-RSAPSS",
                48,
            ),
            "SHA-512" => (
                verify::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
                "SHA512-RSAPSS",
                64,
            ),
            _ => return None,
        };
    assert_eq!(text(group, "mgf"), "MGF1");
    let tls = text(group, "mgfSha") == text(group, "sha") && number(group, "sLen") == len;
    let refused = (!tls).then_some(
        "TLS signs with MGF1 over the message's hash and a salt the hash's length, \
         and ring and Go's crypto/tls take nothing else",
    );
    Some((algorithm, go, refused))
}

#[test]
fn rsa_pss_answers_wycheproof() {
    for (file, valid, invalid, skipped) in [
        ("rsa_pss_2048_sha256_mgf1_32_test.json", 63, 45, 0),
        ("rsa_pss_3072_sha256_mgf1_32_test.json", 63, 45, 0),
        ("rsa_pss_4096_sha256_mgf1_32_test.json", 63, 45, 0),
        ("rsa_pss_4096_sha512_mgf1_64_test.json", 132, 47, 0),
        // Every case is valid for its parameters: the three groups of a
        // hash TLS signs PSS with, its MGF1 and its salt length run as
        // valid, the 87 others of those hashes as must-refuse, and the 60
        // of SHA-1 and SHA-224 are skipped.
        ("rsa_pss_misc_test.json", 3, 87, 60),
    ] {
        let expected = Tally {
            valid,
            invalid,
            acceptable: 0,
            skipped,
        };
        sig_answers_wycheproof(
            file,
            "RSASSA-PSS",
            "rsassa_pss_verify_schema_v1.json",
            expected,
            pss_policy,
            rsa_key,
        );
    }
}
