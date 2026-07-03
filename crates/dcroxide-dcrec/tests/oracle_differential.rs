// SPDX-License-Identifier: ISC
//! Differential tests: our ECDSA/pubkey acceptance layers vs. dcrd's
//! `dcrec/secp256k1/v4` (+ `ecdsa`), live.
//!
//! Signature parsing/verification acceptance differences are exactly where
//! reimplementations have historically forked chains (project brief risk
//! R4), so verdicts, error *kinds*, parsed values, and produced signatures
//! are all compared byte-for-byte.

// Test-harness arithmetic (bounded DER lengths, borrow subtraction).
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_dcrec::secp256k1::ecdsa::{Signature, parse_der_signature, sign};
use dcroxide_dcrec::secp256k1::{PrivateKey, PublicKey};
use dcroxide_testutil::{Oracle, SplitMix64, hex, oracle_or_skip};

/// A random private key (rejection-sampled into [1, N-1], which libsecp
/// enforces for us).
fn random_priv_key(rng: &mut SplitMix64) -> ([u8; 32], PrivateKey) {
    loop {
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        if let Some(key) = PrivateKey::from_bytes(&bytes) {
            return (bytes, key);
        }
    }
}

/// Encode (r, s) as minimal DER *without* low-S normalization, so high-S
/// signatures can be fed to both verifiers (serialize() would normalize).
fn raw_der(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
    fn int_bytes(v: &[u8; 32]) -> Vec<u8> {
        let mut stripped: &[u8] = v;
        while stripped.len() > 1 && stripped[0] == 0 {
            stripped = &stripped[1..];
        }
        let mut out = Vec::new();
        if stripped[0] & 0x80 != 0 {
            out.push(0x00);
        }
        out.extend_from_slice(stripped);
        out
    }
    let ri = int_bytes(r);
    let si = int_bytes(s);
    let mut out = vec![0x30, (4 + ri.len() + si.len()) as u8, 0x02, ri.len() as u8];
    out.extend_from_slice(&ri);
    out.push(0x02);
    out.push(si.len() as u8);
    out.extend_from_slice(&si);
    out
}

/// Both sides parse `der`; verdicts, error kinds, and (r, s) must agree.
fn check_der_parse(oracle: &mut Oracle, der: &[u8], ctx: &str) {
    let ours = parse_der_signature(der);
    let resp = oracle.call("ecdsa_parse_der", der);
    match (&ours, resp.get("error").and_then(|e| e.as_str())) {
        (Ok(sig), None) => {
            let want = resp["result"].as_str().expect("result present");
            let got = format!("{}{}", hex(sig.r_bytes()), hex(sig.s_bytes()));
            assert_eq!(got, want, "{ctx}: parsed R||S for {}", hex(der));
        }
        (Err(err), Some(_)) => {
            let kind = resp["kind"].as_str().expect("kind present");
            assert_eq!(err.kind_name(), kind, "{ctx}: error kind for {}", hex(der));
        }
        (ours, oracle_err) => panic!(
            "{ctx}: verdict mismatch for {}: ours {ours:?}, oracle error {oracle_err:?}",
            hex(der)
        ),
    }
}

#[test]
fn der_parse_matches_dcrd_oracle() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("ecdsa der parse differential");

    // Valid signatures and byte-level corruptions of them.
    for i in 0..1_500 {
        let (_, key) = random_priv_key(&mut rng);
        let mut hash = [0u8; 32];
        rng.fill(&mut hash);
        let mut der = sign(&key, &hash).serialize();
        check_der_parse(&mut oracle, &der, &format!("valid case {i}"));

        match rng.below(3) {
            0 => {
                let cut = rng.below(der.len() as u64 + 1) as usize;
                der.truncate(cut);
            }
            1 => {
                let pos = rng.below(der.len() as u64) as usize;
                der[pos] ^= rng.next_u64() as u8;
            }
            _ => {
                der.push(rng.next_u64() as u8);
            }
        }
        check_der_parse(&mut oracle, &der, &format!("mutated case {i}"));
    }

    // Structured DER-ish garbage: plausible markers with random lengths and
    // integer bodies, hitting the deep error paths (padding, negative,
    // range) far more often than pure noise would.
    for i in 0..2_500 {
        let r_len = rng.below(36) as usize;
        let s_len = rng.below(36) as usize;
        let mut der = Vec::new();
        der.push(if rng.below(20) == 0 {
            rng.next_u64() as u8
        } else {
            0x30
        });
        // Occasionally lie about the total length.
        let total = 4 + r_len + s_len;
        der.push(if rng.below(10) == 0 {
            rng.next_u64() as u8
        } else {
            total as u8
        });
        der.push(if rng.below(20) == 0 {
            rng.next_u64() as u8
        } else {
            0x02
        });
        der.push(if rng.below(10) == 0 {
            rng.next_u64() as u8
        } else {
            r_len as u8
        });
        for _ in 0..r_len {
            // Bias toward 0x00/0xff/small values to hit padding and sign
            // checks.
            der.push(match rng.below(4) {
                0 => 0x00,
                1 => 0xff,
                _ => rng.next_u64() as u8,
            });
        }
        der.push(if rng.below(20) == 0 {
            rng.next_u64() as u8
        } else {
            0x02
        });
        der.push(if rng.below(10) == 0 {
            rng.next_u64() as u8
        } else {
            s_len as u8
        });
        for _ in 0..s_len {
            der.push(match rng.below(4) {
                0 => 0x00,
                1 => 0xff,
                _ => rng.next_u64() as u8,
            });
        }
        check_der_parse(&mut oracle, &der, &format!("structured case {i}"));
    }
}

#[test]
fn sign_matches_dcrd_oracle() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("ecdsa sign differential");

    for i in 0..400 {
        let (key_bytes, key) = random_priv_key(&mut rng);
        let mut hash = [0u8; 32];
        rng.fill(&mut hash);

        let ours = sign(&key, &hash).serialize();

        let mut req = Vec::with_capacity(64);
        req.extend_from_slice(&key_bytes);
        req.extend_from_slice(&hash);
        let theirs = oracle.call_ok("ecdsa_sign", &req);
        assert_eq!(
            hex(&ours),
            theirs,
            "case {i}: RFC6979 signature for key {} hash {}",
            hex(&key_bytes),
            hex(&hash)
        );
    }
}

#[test]
fn verify_matches_dcrd_oracle() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("ecdsa verify differential");

    for i in 0..300 {
        let (_, key) = random_priv_key(&mut rng);
        let pub_key = key.public_key();
        let mut hash = [0u8; 32];
        rng.fill(&mut hash);
        let sig = sign(&key, &hash);

        // Variants: valid; high-S malleated (dcrd accepts); wrong hash;
        // wrong key; tampered R.
        let neg_s = {
            let mut n = dcroxide_dcrec::secp256k1::GROUP_ORDER_BYTES;
            let mut borrow = 0i32;
            for j in (0..32).rev() {
                let mut diff = i32::from(n[j]) - i32::from(sig.s_bytes()[j]) - borrow;
                borrow = i32::from(diff < 0);
                if diff < 0 {
                    diff += 256;
                }
                n[j] = diff as u8;
            }
            n
        };
        let (_, other_key) = random_priv_key(&mut rng);
        let mut other_hash = hash;
        other_hash[0] ^= 0x01;
        let mut tampered_r = *sig.r_bytes();
        tampered_r[31] ^= 0x01;

        type VerifyCase = (&'static str, PublicKey, [u8; 32], [u8; 32], [u8; 32]);
        let cases: Vec<VerifyCase> = vec![
            ("valid", pub_key, hash, *sig.r_bytes(), *sig.s_bytes()),
            ("high-s", pub_key, hash, *sig.r_bytes(), neg_s),
            (
                "wrong hash",
                pub_key,
                other_hash,
                *sig.r_bytes(),
                *sig.s_bytes(),
            ),
            (
                "wrong key",
                other_key.public_key(),
                hash,
                *sig.r_bytes(),
                *sig.s_bytes(),
            ),
            ("tampered r", pub_key, hash, tampered_r, *sig.s_bytes()),
        ];

        for (name, pk, h, r, s) in cases {
            let Some(candidate) = Signature::new(r, s) else {
                // Tampering pushed a scalar out of range; skip (the parse
                // differential covers range rejection).
                continue;
            };
            let ours = candidate.verify(&h, &pk);

            let mut req = Vec::new();
            req.extend_from_slice(&pk.serialize_compressed());
            req.extend_from_slice(&h);
            req.extend_from_slice(&raw_der(&r, &s));
            let theirs = oracle.call_ok("ecdsa_verify", &req) == "true";
            assert_eq!(ours, theirs, "case {i} ({name}): verify verdict");
        }
    }
}

/// Both sides parse pubkey bytes; verdicts, kinds, and both serializations
/// must agree.
fn check_pubkey_parse(oracle: &mut Oracle, bytes: &[u8], ctx: &str) {
    let ours = PublicKey::parse(bytes);
    let resp = oracle.call("pubkey_parse", bytes);
    match (&ours, resp.get("error").and_then(|e| e.as_str())) {
        (Ok(pk), None) => {
            assert_eq!(
                hex(&pk.serialize_uncompressed()),
                resp["result"].as_str().expect("result"),
                "{ctx}: uncompressed for {}",
                hex(bytes)
            );
            assert_eq!(
                hex(&pk.serialize_compressed()),
                resp["compressed"].as_str().expect("compressed"),
                "{ctx}: compressed for {}",
                hex(bytes)
            );
        }
        (Err(err), Some(_)) => {
            let kind = resp["kind"].as_str().expect("kind present");
            assert_eq!(err.kind_name(), kind, "{ctx}: kind for {}", hex(bytes));
        }
        (ours, oracle_err) => panic!(
            "{ctx}: verdict mismatch for {}: ours {ours:?}, oracle error {oracle_err:?}",
            hex(bytes)
        ),
    }
}

#[test]
fn pubkey_parse_matches_dcrd_oracle() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("pubkey parse differential");

    for i in 0..800 {
        let (_, key) = random_priv_key(&mut rng);
        let pk = key.public_key();
        let compressed = pk.serialize_compressed();
        let uncompressed = pk.serialize_uncompressed();

        // Valid encodings, including both hybrid variants (one of which has
        // mismatched oddness).
        let mut hybrid_even = uncompressed;
        hybrid_even[0] = 0x06;
        let mut hybrid_odd = uncompressed;
        hybrid_odd[0] = 0x07;
        check_pubkey_parse(&mut oracle, &compressed, &format!("compressed {i}"));
        check_pubkey_parse(&mut oracle, &uncompressed, &format!("uncompressed {i}"));
        check_pubkey_parse(&mut oracle, &hybrid_even, &format!("hybrid-even {i}"));
        check_pubkey_parse(&mut oracle, &hybrid_odd, &format!("hybrid-odd {i}"));

        // Mutations: random format byte, coordinate tampering, random
        // lengths.
        let mut mutated = if rng.below(2) == 0 {
            compressed.to_vec()
        } else {
            uncompressed.to_vec()
        };
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
        check_pubkey_parse(&mut oracle, &mutated, &format!("mutated {i}"));
    }
}
