// SPDX-License-Identifier: ISC
//! Differential tests: our Ed25519 (edwards) vs. dcrd's `dcrec/edwards/v2`,
//! live. Historic verifier differences (canonicality, malleability, point
//! decoding edges) are exactly where Ed25519 reimplementations fork chains
//! (project brief risk R4), so inputs are biased hard toward those edges:
//! non-canonical y encodings, x = 0 sign-bit cases, S at and around the
//! group order, and the raw verify layer that bypasses parse validation.

use dcroxide_dcrec::edwards::{SecretKey, parse_pub_key, parse_signature, sign, verify_raw};
use dcroxide_testutil::{SplitMix64, hex, oracle_or_skip};

/// The Ed25519 group order L as 32 little-endian bytes.
const ELL_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// A boundary-biased 32-byte blob: random, near the group order, near the
/// field prime (non-canonical y territory), or a small value with random
/// sign bit.
fn edgy_32(rng: &mut SplitMix64) -> [u8; 32] {
    let mut out = [0u8; 32];
    match rng.below(5) {
        // Fully random.
        0 | 1 => rng.fill(&mut out),
        // Near/at the group order (little-endian).
        2 => {
            out = ELL_LE;
            let tweak = rng.below(5) as u8;
            out[0] = out[0].wrapping_add(tweak).wrapping_sub(2);
            if rng.below(2) == 0 {
                out[31] |= 0x80;
            }
        }
        // Near/above the field prime: y in [p-2, 2^255-1], sign bit random.
        3 => {
            out = [0xff; 32];
            out[0] = 0xed_u8.wrapping_add(rng.below(5) as u8).wrapping_sub(2);
            out[31] = 0x7f;
            if rng.below(2) == 0 {
                out[31] |= 0x80;
            }
        }
        // Tiny y values (0, 1, 2...) with random sign bit — hits the
        // identity and x = 0 cases.
        _ => {
            out[0] = rng.below(3) as u8;
            if rng.below(2) == 0 {
                out[31] |= 0x80;
            }
        }
    }
    out
}

#[test]
fn ed25519_sign_matches_dcrd_oracle() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("ed25519 sign differential");

    for i in 0..300 {
        let mut seed = [0u8; 32];
        rng.fill(&mut seed);
        let msg = rng.bytes(64);

        let secret = SecretKey::from_seed(seed);
        let sig = sign(&secret, &msg);

        let mut req = Vec::with_capacity(32 + msg.len());
        req.extend_from_slice(&seed);
        req.extend_from_slice(&msg);
        let resp = oracle.call("ed25519_sign", &req);
        assert!(
            resp.get("error").is_none(),
            "case {i}: oracle sign error: {resp}"
        );
        assert_eq!(
            hex(&sig.serialize()),
            resp["result"].as_str().expect("result"),
            "case {i}: signature for seed {}",
            hex(&seed)
        );
        assert_eq!(
            hex(&secret.public_key().serialize()),
            resp["compressed"].as_str().expect("compressed"),
            "case {i}: derived public key"
        );
        assert!(sig.verify(&msg, &secret.public_key()), "case {i}: verifies");
    }
}

#[test]
fn ed25519_pubkey_parse_matches_dcrd_oracle() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("ed25519 pubkey parse differential");

    for i in 0..2_000 {
        // Mix edge-biased 32-byte blobs with valid keys and wrong lengths.
        let bytes: Vec<u8> = match rng.below(6) {
            0 => {
                let mut seed = [0u8; 32];
                rng.fill(&mut seed);
                SecretKey::from_seed(seed).public_key().serialize().to_vec()
            }
            1 => rng.bytes(40),
            _ => edgy_32(&mut rng).to_vec(),
        };

        let ours = parse_pub_key(&bytes);
        let resp = oracle.call("ed25519_pubkey_parse", &bytes);
        match (&ours, resp.get("error").and_then(|e| e.as_str())) {
            (Ok(pk), None) => {
                // Canonical re-serialization must agree (non-canonical
                // inputs normalize identically).
                assert_eq!(
                    hex(&pk.serialize()),
                    resp["result"].as_str().expect("result"),
                    "case {i}: canonical form of {}",
                    hex(&bytes)
                );
            }
            (Err(_), Some(_)) => {} // both reject (dcrd has no error kinds here)
            (ours, oracle_err) => panic!(
                "case {i}: verdict mismatch for {}: ours {ours:?}, oracle {oracle_err:?}",
                hex(&bytes)
            ),
        }
    }
}

#[test]
fn ed25519_sig_parse_matches_dcrd_oracle() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("ed25519 sig parse differential");

    for i in 0..2_000 {
        let bytes: Vec<u8> = match rng.below(6) {
            0 => {
                let mut seed = [0u8; 32];
                rng.fill(&mut seed);
                sign(&SecretKey::from_seed(seed), b"msg")
                    .serialize()
                    .to_vec()
            }
            1 => rng.bytes(70),
            _ => {
                let mut sig = [0u8; 64];
                sig[..32].copy_from_slice(&edgy_32(&mut rng));
                sig[32..].copy_from_slice(&edgy_32(&mut rng));
                sig.to_vec()
            }
        };

        let ours = parse_signature(&bytes);
        let resp = oracle.call("ed25519_parse", &bytes);
        match (&ours, resp.get("error").and_then(|e| e.as_str())) {
            (Ok(sig), None) => {
                assert_eq!(
                    hex(&sig.serialize()),
                    resp["result"].as_str().expect("result"),
                    "case {i}: round trip of {}",
                    hex(&bytes)
                );
            }
            (Err(_), Some(_)) => {}
            (ours, oracle_err) => panic!(
                "case {i}: verdict mismatch for {}: ours {ours:?}, oracle {oracle_err:?}",
                hex(&bytes)
            ),
        }
    }
}

#[test]
fn ed25519_verify_matches_dcrd_oracle() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("ed25519 verify differential");

    for i in 0..250 {
        let mut seed = [0u8; 32];
        rng.fill(&mut seed);
        let secret = SecretKey::from_seed(seed);
        let pub_key = secret.public_key();
        let msg = rng.bytes(48);
        let sig = sign(&secret, &msg);

        // Raw-layer variants (the oracle takes R/S without ParseSignature,
        // exposing the 2017-agl verify semantics):
        let mut variants: Vec<(&str, [u8; 64], Vec<u8>)> = vec![
            ("valid", sig.serialize(), msg.clone()),
            ("wrong msg", sig.serialize(), rng.bytes(48)),
        ];
        // s + L malleation: parse-invalid, but the raw layer accepts it
        // when the top three bits stay clear.
        let mut s_plus_ell = [0u8; 32];
        let mut carry = 0u16;
        for j in 0..32 {
            let sum = u16::from(sig.s_bytes()[j]) + u16::from(ELL_LE[j]) + carry;
            s_plus_ell[j] = sum as u8;
            carry = sum >> 8;
        }
        if carry == 0 {
            let mut malleated = sig.serialize();
            malleated[32..].copy_from_slice(&s_plus_ell);
            variants.push(("s plus L", malleated, msg.clone()));
        }
        // Top-bits-set S.
        let mut top_bits = sig.serialize();
        top_bits[63] |= 0xE0;
        variants.push(("s top bits", top_bits, msg.clone()));
        // Tampered R and random garbage S.
        let mut bad_r = sig.serialize();
        bad_r[0] ^= 1;
        variants.push(("tampered r", bad_r, msg.clone()));
        let mut rand_s = sig.serialize();
        let mut s32 = [0u8; 32];
        rng.fill(&mut s32);
        rand_s[32..].copy_from_slice(&s32);
        variants.push(("random s", rand_s, msg.clone()));

        for (name, sig_bytes, m) in variants {
            let ours = verify_raw(&pub_key, &m, &sig_bytes);

            let mut req = Vec::with_capacity(96 + m.len());
            req.extend_from_slice(&pub_key.serialize());
            req.extend_from_slice(&sig_bytes);
            req.extend_from_slice(&m);
            let resp = oracle.call("ed25519_verify", &req);
            assert!(
                resp.get("error").is_none(),
                "case {i} ({name}): oracle error: {resp}"
            );
            let theirs = resp["result"].as_str().expect("result") == "true";
            assert_eq!(ours, theirs, "case {i} ({name}): verify verdict");
        }
    }
}
