// SPDX-License-Identifier: ISC
//! Differential tests: our EC-Schnorr-DCRv0 vs. dcrd's
//! `dcrec/secp256k1/v4/schnorr`, live — signatures byte-for-byte, verify
//! verdicts across tampering variants and the rejection paths signing never
//! reaches (R at infinity, zero s, odd R, arbitrary bytes), and parse
//! verdicts with exact error kinds. This also cross-validates the k256
//! arithmetic backend against dcrd's own field/scalar implementation
//! (ADR-0006 constraint).

use dcroxide_dcrec::secp256k1::schnorr::{Error, Signature, parse_pub_key, parse_signature, sign};
use dcroxide_dcrec::secp256k1::{FIELD_PRIME_BYTES, GROUP_ORDER_BYTES, PrivateKey, PublicKey};
use dcroxide_testutil::{Oracle, SplitMix64, hex, oracle_or_skip};
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::{ProjectivePoint, Scalar};

fn random_priv_key(rng: &mut SplitMix64) -> ([u8; 32], PrivateKey) {
    loop {
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        if let Some(key) = PrivateKey::from_bytes(&bytes) {
            return (bytes, key);
        }
    }
}

#[test]
fn schnorr_sign_matches_dcrd_oracle() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("schnorr sign differential");

    for i in 0..400 {
        let (key_bytes, key) = random_priv_key(&mut rng);
        let mut hash = [0u8; 32];
        rng.fill(&mut hash);

        let sig = sign(&key, &hash).expect("sign");

        let mut req = Vec::with_capacity(64);
        req.extend_from_slice(&key_bytes);
        req.extend_from_slice(&hash);
        let theirs = oracle.call_ok("schnorr_sign", &req);
        assert_eq!(
            hex(&sig.serialize()),
            theirs,
            "case {i}: signature for key {} hash {}",
            hex(&key_bytes),
            hex(&hash)
        );
        assert!(sig.verify(&hash, &key.public_key()), "case {i}: verifies");
    }
}

#[test]
fn schnorr_verify_matches_dcrd_oracle() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("schnorr verify differential");

    for i in 0..300 {
        let (_, key) = random_priv_key(&mut rng);
        let pub_key = key.public_key();
        let mut hash = [0u8; 32];
        rng.fill(&mut hash);
        let sig = sign(&key, &hash).expect("sign");
        let (_, other_key) = random_priv_key(&mut rng);

        // Tampering variants; every candidate stays parseable so both
        // sides reach actual verification.
        let mut tampered_r = *sig.r_bytes();
        tampered_r[31] ^= 0x01;
        let mut tampered_s = *sig.s_bytes();
        tampered_s[31] ^= 0x01;
        let mut other_hash = hash;
        other_hash[0] ^= 0x01;

        type Case = (
            &'static str,
            dcroxide_dcrec::secp256k1::PublicKey,
            [u8; 32],
            Option<Signature>,
        );
        let cases: Vec<Case> = vec![
            ("valid", pub_key, hash, Some(sig)),
            (
                "tampered r",
                pub_key,
                hash,
                Signature::new(tampered_r, *sig.s_bytes()),
            ),
            (
                "tampered s",
                pub_key,
                hash,
                Signature::new(*sig.r_bytes(), tampered_s),
            ),
            ("wrong hash", pub_key, other_hash, Some(sig)),
            ("wrong key", other_key.public_key(), hash, Some(sig)),
        ];

        for (name, pk, h, candidate) in cases {
            let Some(candidate) = candidate else {
                continue; // tampering left the range; parse differential covers that
            };
            let ours = candidate.verify(&h, &pk);

            let mut req = Vec::with_capacity(129);
            req.extend_from_slice(&pk.serialize_compressed());
            req.extend_from_slice(&h);
            req.extend_from_slice(&candidate.serialize());
            let theirs = oracle.call_ok("schnorr_verify", &req) == "true";
            assert_eq!(ours, theirs, "case {i} ({name}): verify verdict");
        }
    }
}

#[test]
fn schnorr_parse_matches_dcrd_oracle() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("schnorr parse differential");

    for i in 0..2_000 {
        // Random blobs with boundary bias: sometimes plant field-prime or
        // group-order prefixes to straddle the range checks, and sometimes
        // use a wrong length.
        let len = match rng.below(10) {
            0 => rng.below(64) as usize,
            1 => 65 + rng.below(16) as usize,
            _ => 64,
        };
        let mut blob = vec![0u8; len];
        rng.fill(&mut blob);
        if len == 64 {
            match rng.below(4) {
                0 => {
                    // r near/at the field prime.
                    blob[..32].copy_from_slice(&FIELD_PRIME_BYTES);
                    if rng.below(2) == 0 {
                        blob[31] = blob[31].wrapping_sub(rng.below(3) as u8);
                    }
                }
                1 => {
                    // s near/at the group order.
                    blob[32..].copy_from_slice(&GROUP_ORDER_BYTES);
                    if rng.below(2) == 0 {
                        blob[63] = blob[63].wrapping_sub(rng.below(3) as u8);
                    }
                }
                _ => {}
            }
        }

        let ours = parse_signature(&blob);
        let resp = oracle.call("schnorr_parse", &blob);
        match (&ours, resp.get("error").and_then(|e| e.as_str())) {
            (Ok(sig), None) => {
                assert_eq!(
                    hex(&sig.serialize()),
                    resp["result"].as_str().expect("result"),
                    "case {i}: round-trip for {}",
                    hex(&blob)
                );
            }
            (Err(err), Some(_)) => {
                let kind = resp["kind"].as_str().expect("kind present");
                assert_eq!(err.kind_name(), kind, "case {i}: kind for {}", hex(&blob));
            }
            (ours, oracle_err) => panic!(
                "case {i}: verdict mismatch for {}: ours {ours:?}, oracle {oracle_err:?}",
                hex(&blob)
            ),
        }
    }
}

#[test]
fn schnorr_pubkey_parse_matches_dcrd_oracle() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("schnorr pubkey parse differential");

    for i in 0..500 {
        let (_, key) = random_priv_key(&mut rng);
        let pk = key.public_key();

        // Valid compressed, rejected uncompressed, mutated bytes.
        let mut candidates: Vec<Vec<u8>> = vec![
            pk.serialize_compressed().to_vec(),
            pk.serialize_uncompressed().to_vec(),
        ];
        let mut mutated = pk.serialize_compressed().to_vec();
        match rng.below(3) {
            0 => mutated[0] = rng.next_u64() as u8,
            1 => {
                let pos = rng.below(mutated.len() as u64) as usize;
                mutated[pos] ^= rng.next_u64() as u8;
            }
            _ => {
                let cut = rng.below(mutated.len() as u64 + 1) as usize;
                mutated.truncate(cut);
            }
        }
        candidates.push(mutated);

        for bytes in candidates {
            let ours = parse_pub_key(&bytes);
            let resp = oracle.call("schnorr_pubkey_parse", &bytes);
            match (&ours, resp.get("error").and_then(|e| e.as_str())) {
                (Ok(parsed), None) => {
                    assert_eq!(
                        hex(&parsed.serialize_compressed()),
                        resp["result"].as_str().expect("result"),
                        "case {i}: reserialize for {}",
                        hex(&bytes)
                    );
                }
                // dcrd's schnorr.ParsePubKey uses plain errors (no kinds),
                // so only the verdict is compared here.
                (Err(_), Some(_)) => {}
                (ours, oracle_err) => panic!(
                    "case {i}: verdict mismatch for {}: ours {ours:?}, oracle {oracle_err:?}",
                    hex(&bytes)
                ),
            }
        }
    }
}

/// dcrd's verdict for the key, hash and raw 64-byte signature.
fn oracle_verify(oracle: &mut Oracle, pk: &PublicKey, hash: &[u8; 32], sig: &[u8; 64]) -> bool {
    let mut req = Vec::with_capacity(129);
    req.extend_from_slice(&pk.serialize_compressed());
    req.extend_from_slice(hash);
    req.extend_from_slice(sig);
    oracle.call_ok("schnorr_verify", &req) == "true"
}

/// `BLAKE-256(r || m)` as a scalar, `None` past the group order.
fn challenge(r: &[u8; 32], hash: &[u8; 32]) -> Option<Scalar> {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(r);
    input[32..].copy_from_slice(hash);
    Option::from(Scalar::from_repr(
        dcroxide_crypto::blake256::sum256(&input).into(),
    ))
}

fn signature_bytes(r: &[u8; 32], s: &Scalar) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(r);
    out[32..].copy_from_slice(&s.to_bytes());
    out
}

/// Verification's rejection paths that signing never produces, against
/// dcrd: R at the point at infinity (s = -e*d), a zero s, an R with an
/// odd y whose x the signature commits to, and arbitrary parsed bytes.
/// The first three also pin the port's reason, which dcrd's
/// TestVerifyErrors does for its fixed vectors.
#[test]
fn schnorr_verify_rejection_paths_match_dcrd_oracle() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("schnorr verify rejection paths");

    for i in 0..300 {
        let (key_bytes, key) = random_priv_key(&mut rng);
        let pub_key = key.public_key();
        let d = Scalar::from_repr(key_bytes.into()).expect("private key is a scalar");
        let mut hash = [0u8; 32];
        rng.fill(&mut hash);
        let sig = sign(&key, &hash).expect("sign");
        let r = *sig.r_bytes();
        let e = challenge(&r, &hash).expect("sign only emits in-range challenges");

        // s = -e*d puts R = s*G + e*Q at infinity.
        let at_infinity = signature_bytes(&r, &-(e * d));
        let parsed = parse_signature(&at_infinity).expect("parses");
        assert_eq!(
            parsed.verify_detailed(&hash, &pub_key),
            Err(Error::SigRNotOnCurve),
            "case {i}: R at infinity"
        );
        assert!(!oracle_verify(&mut oracle, &pub_key, &hash, &at_infinity));

        // s = 0 leaves R = e*Q.
        let zero_s = signature_bytes(&r, &Scalar::ZERO);
        let parsed = parse_signature(&zero_s).expect("parses");
        assert!(parsed.verify_detailed(&hash, &pub_key).is_err());
        assert!(!oracle_verify(&mut oracle, &pub_key, &hash, &zero_s));

        // An odd R the signature does commit to: pick a nonce whose kG
        // has an odd y (negating it otherwise) and sign without the
        // even-y negation.
        let mut k_bytes = [0u8; 32];
        rng.fill(&mut k_bytes);
        let mut k: Scalar = Option::from(Scalar::from_repr(k_bytes.into())).unwrap_or(Scalar::ONE);
        let point = |k: &Scalar| {
            (ProjectivePoint::GENERATOR * *k)
                .to_affine()
                .to_sec1_point(false)
        };
        if point(&k).y().expect("y")[31] & 1 == 0 {
            k = -k;
        }
        let encoded = point(&k);
        let mut odd_r = [0u8; 32];
        odd_r.copy_from_slice(encoded.x().expect("x"));
        if let Some(e) = challenge(&odd_r, &hash) {
            let odd = signature_bytes(&odd_r, &(k - e * d));
            let parsed = parse_signature(&odd).expect("parses");
            assert_eq!(
                parsed.verify_detailed(&hash, &pub_key),
                Err(Error::SigRYIsOdd),
                "case {i}: odd R"
            );
            assert!(!oracle_verify(&mut oracle, &pub_key, &hash, &odd));
        }

        // Arbitrary bytes that parse: the verdicts agree.
        let mut blob = [0u8; 64];
        rng.fill(&mut blob);
        if let Ok(parsed) = parse_signature(&blob) {
            assert_eq!(
                parsed.verify(&hash, &pub_key),
                oracle_verify(&mut oracle, &pub_key, &hash, &blob),
                "case {i}: arbitrary {}",
                hex(&blob)
            );
        }
    }
}
