// SPDX-License-Identifier: ISC
//! Checks for the gencerts machinery: authority and issued
//! certificates round-trip through the CA loader across the
//! algorithms, the issuance checks match dcrd's, and the template
//! rules (validity clamp, elapsed error) hold.

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

    // A mismatched pair is refused with Go's error.
    let err = load_ca_pair(&ca.pem, &leaf_key_pem)
        .map(|_| ())
        .expect_err("mismatch");
    assert_eq!(err, "tls: private key does not match public key");
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

/// The RSA key marshaling and loading round-trips (a small key keeps
/// the debug-build generation fast; the tool itself generates 4096).
#[test]
fn rsa_pair_round_trips() {
    let mut rng = rsa::rand_core::OsRng;
    let key = ToolKeyPair::Rsa(Box::new(
        rsa::RsaPrivateKey::new(&mut rng, 1024).expect("rsa keygen"),
    ));
    let ca = generate_authority(&mut env(), &key, &["localhost".to_string()], "org", 5, true)
        .expect("rsa authority");
    let key_pem = pem_private_key(&key.marshal_pkcs8().expect("marshal"));
    let (loaded, loaded_key) = load_ca_pair(&ca.pem, &key_pem).expect("load rsa pair");
    assert!(loaded.cert_sign);
    assert_eq!(loaded_key.public_bytes(), key.public_bytes());
}
