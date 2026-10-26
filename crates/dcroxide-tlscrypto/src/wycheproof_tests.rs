// SPDX-License-Identifier: ISC
//! Wycheproof's vectors for the crate's record protection, HMAC, HKDF and
//! key exchange (ADR-0015 T10), run through the crate's own code: the
//! AEADs the suites instantiate, through the `seal` and `open` every
//! record goes through; HMAC as rustls asks for a tag; HKDF as rustls
//! builds it on that HMAC; and each key exchange group's `complete`, from
//! the case's private key.  The files, their commit and their hashes are
//! in `tests/data/wycheproof/SOURCE`.
//!
//! A unit-test module rather than an integration test, because the AEADs
//! and a key exchange with a fixed private key are reached through
//! crate-private functions.  The harness checks each file's `algorithm`
//! and `schema` before it reads the groups, and counts what it runs and
//! what it skips against fixed totals, so a truncated or replaced file
//! fails rather than passing on fewer cases.  A `valid` case must succeed
//! with Wycheproof's answer and an `invalid` one must fail.  Only the key
//! exchange files have `acceptable` cases, and each is decided by its
//! flags under [`ACCEPTABLE_KX`], which gives the reason for each verdict;
//! a case none of its entries covers fails the test until one is written
//! down, and any `acceptable` case in the other files fails it too.
//! Every key exchange case, whatever its result, is also held to Go's
//! `crypto/ecdh` through the oracle, which is how the table is checked
//! against Go: where there is no oracle that comparison is skipped, unless
//! `DCROXIDE_REQUIRE_ORACLE` is set, as in CI, where it also requires the
//! reference Go.

use std::io::Read;

use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use dcroxide_testutil::{Oracle, hex, unhex};
use rustls::crypto::hmac::Hmac;
use rustls::crypto::tls13::{Hkdf, OutputLengthError};
use rustls::{Error, NamedGroup, PeerMisbehaved};
use serde_json::Value;

use crate::aead::{self, RecordAead};
use crate::hmac::{HKDF_SHA256, HKDF_SHA384, HMAC_SHA256, HMAC_SHA384};
use crate::kx::exchange_with;

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
