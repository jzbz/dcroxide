// SPDX-License-Identifier: ISC
//! Differential tests: our Ed25519 (edwards) vs. dcrd's `dcrec/edwards/v2`,
//! live. Historic verifier differences (canonicality, malleability, point
//! decoding edges) are exactly where Ed25519 reimplementations fork chains
//! (project brief risk R4), so inputs are biased hard toward those edges:
//! non-canonical y encodings, x = 0 sign-bit cases, S at and around the
//! group order, public keys carrying a small-order torsion component, and
//! the raw verify layer that bypasses parse validation.

// Scalar and group arithmetic in the torsion rows is modular.
#![allow(clippy::arithmetic_side_effects)]

use curve25519_dalek::constants::EIGHT_TORSION;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use dcroxide_dcrec::edwards::{SecretKey, parse_pub_key, parse_signature, sign, verify_raw};
use dcroxide_testutil::{SplitMix64, hex, oracle_or_skip};
use sha2::{Digest, Sha512};

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

/// A uniformly drawn scalar.
fn random_scalar(rng: &mut SplitMix64) -> Scalar {
    let mut wide = [0u8; 64];
    rng.fill(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// The Ed25519 challenge `k = SHA-512(R || A || m) mod L` over the
/// encodings as given.
fn challenge(r: &[u8; 32], a: &[u8; 32], msg: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    h.update(r);
    h.update(a);
    h.update(msg);
    Scalar::from_bytes_mod_order_wide(&h.finalize().into())
}

/// `k mod 8`, which fixes `k*T` for a point `T` of order dividing 8.
fn challenge_mod_8(k: &Scalar) -> u8 {
    k.as_bytes()[0] & 7
}

/// A signature by the key with secret scalar `a` and public point `A`,
/// over a message ground until the challenge is `want` modulo 8, so
/// that `k*T` for the torsion component `T` of `A` is chosen.  Returns
/// the message, the signature and the challenge.
fn ground_signature(
    rng: &mut SplitMix64,
    a: &Scalar,
    pub_bytes: &[u8; 32],
    want: u8,
) -> (Vec<u8>, [u8; 64], Scalar) {
    let r = random_scalar(rng);
    let r_bytes = EdwardsPoint::mul_base(&r).compress().to_bytes();
    loop {
        let mut msg = vec![0u8; 32];
        rng.fill(&mut msg);
        let k = challenge(&r_bytes, pub_bytes, &msg);
        if challenge_mod_8(&k) != want {
            continue;
        }
        let s = r + k * a;
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r_bytes);
        sig[32..].copy_from_slice(s.as_bytes());
        return (msg, sig, k);
    }
}

/// The verification equation with the negation on the scalar,
/// `R' = s*B + (L-k)*A`: the form `verify_raw` must not use, since it
/// agrees with agl's `s*B + k*(-A)` only on the prime-order subgroup.
fn scalar_negation_verifies(pub_point: &EdwardsPoint, sig: &[u8; 64], k: &Scalar) -> bool {
    let s_bytes: [u8; 32] = sig[32..].try_into().expect("32 bytes");
    let s = Scalar::from_bytes_mod_order(s_bytes);
    let r_prime = EdwardsPoint::vartime_double_scalar_mul_basepoint(&(-k), pub_point, &s);
    r_prime.compress().as_bytes() == &sig[..32]
}

/// The torsion guard for `verify_raw` (the RVW-004 fix): a pubkey
/// `A = a*B + T` with `T` of order 8 verifies exactly when `k*T` is
/// the identity, i.e. `k = 0 mod 8`, because agl negates the point
/// (`ed25519.go:106-107`) and computes `s*B - k*A`.  Negating the
/// scalar instead leaves `(L-k)*T`, and `L = 5 mod 8`, so that form
/// accepts at `k = 5 mod 8` and rejects at `k = 0 mod 8`.  Both
/// witnesses are built here and checked against both forms, so a
/// return to the scalar form fails this test without the oracle.
#[test]
fn ed25519_torsion_key_verifies_as_agl_does() {
    let mut rng = SplitMix64(0x7045_1054);
    // T has order exactly 8: 8*T is the identity and 4*T is not.
    let torsion = EIGHT_TORSION[1];
    assert!(torsion.is_small_order());
    assert_ne!(
        Scalar::from(4u8) * torsion,
        EdwardsPoint::default(),
        "the generator of the 8-torsion"
    );
    for _ in 0..8 {
        let a = random_scalar(&mut rng);
        let pub_point = EdwardsPoint::mul_base(&a) + torsion;
        let pub_bytes = pub_point.compress().to_bytes();
        let pub_key = parse_pub_key(&pub_bytes).expect("torsion-carrying keys parse");

        // k = 0 mod 8: agl accepts, the scalar form rejects.
        let (msg, sig, k) = ground_signature(&mut rng, &a, &pub_bytes, 0);
        assert!(verify_raw(&pub_key, &msg, &sig), "k = 0 mod 8 must verify");
        assert!(!scalar_negation_verifies(&pub_point, &sig, &k));

        // k = 5 mod 8: agl rejects, the scalar form accepts.
        let (msg, sig, k) = ground_signature(&mut rng, &a, &pub_bytes, 5);
        assert!(
            !verify_raw(&pub_key, &msg, &sig),
            "k = 5 mod 8 must not verify"
        );
        assert!(scalar_negation_verifies(&pub_point, &sig, &k));
    }
}

/// Torsion-carrying pubkeys through the dcrd oracle: the eight
/// small-order points themselves (whose discrete log is zero, so any
/// `R = r*B, S = r` signs for them when `k*T` vanishes) and composites
/// `a*B + T` for each of them, with challenges ground to every residue
/// modulo 8.
#[test]
fn ed25519_verify_torsion_keys_match_dcrd_oracle() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("ed25519 torsion verify differential");

    let mut accepted = 0;
    for (i, torsion) in EIGHT_TORSION.iter().enumerate() {
        for composite in [false, true] {
            let a = if composite {
                random_scalar(&mut rng)
            } else {
                Scalar::ZERO
            };
            let pub_point = EdwardsPoint::mul_base(&a) + torsion;
            let pub_bytes = pub_point.compress().to_bytes();
            for want in 0..8u8 {
                let (msg, sig, _) = ground_signature(&mut rng, &a, &pub_bytes, want);
                let name = format!("T{i} composite={composite} k={want} mod 8");

                let mut req = Vec::with_capacity(96 + msg.len());
                req.extend_from_slice(&pub_bytes);
                req.extend_from_slice(&sig);
                req.extend_from_slice(&msg);
                let resp = oracle.call("ed25519_verify", &req);
                let ours = parse_pub_key(&pub_bytes).map(|pk| verify_raw(&pk, &msg, &sig));
                match (ours, resp.get("error")) {
                    (Ok(ours), None) => {
                        let theirs = resp["result"].as_str().expect("result") == "true";
                        assert_eq!(ours, theirs, "{name}: verify verdict");
                        accepted += usize::from(ours);
                    }
                    (Err(_), Some(_)) => {}
                    (ours, err) => {
                        panic!("{name}: parse verdict mismatch: ours {ours:?}, oracle {err:?}")
                    }
                }
            }
        }
    }
    // Every key accepts at k = 0 mod 8, so the rows are not vacuous.
    assert!(accepted >= 16, "only {accepted} torsion rows verified");
}

/// A sweep over random torsion-carrying keys, the key class
/// `fuzz/fuzz_targets/dcrec_ed25519.rs` cannot build (that crate has no
/// group arithmetic to add a torsion point with).  For a key
/// `A = a*B + T`, any of the eight small-order `T` and random `a`, zero
/// included, an honest signature `(r*B, r + k*a)` over a random message
/// satisfies agl's `s*B - k*A = R - k*T`, so `verify_raw` must accept it
/// exactly when `k*T` is the identity; the scalar-negation form instead
/// accepts exactly when `(L-k)*T` is, and the two verdicts must be seen
/// to differ.
#[test]
fn ed25519_random_torsion_keys_verify_as_agl_does() {
    let mut rng = SplitMix64::from_entropy("ed25519 torsion key sweep");
    let identity = EdwardsPoint::default();

    let (mut accepted, mut rejected, mut forms_differ) = (0, 0, 0);
    // About 31% of the cases accept (all of the identity's, half of the
    // order-2 point's, a quarter of the order-4 points' and an eighth of
    // the order-8 points'), and the forms differ on about 37%.
    for i in 0..400 {
        let torsion = EIGHT_TORSION[rng.below(8) as usize];
        let a = if rng.below(8) == 0 {
            Scalar::ZERO
        } else {
            random_scalar(&mut rng)
        };
        let pub_point = EdwardsPoint::mul_base(&a) + torsion;
        let pub_bytes = pub_point.compress().to_bytes();
        let Ok(pub_key) = parse_pub_key(&pub_bytes) else {
            continue;
        };

        let r = random_scalar(&mut rng);
        let r_bytes = EdwardsPoint::mul_base(&r).compress().to_bytes();
        let mut msg = vec![0u8; rng.below(64) as usize];
        rng.fill(&mut msg);
        let k = challenge(&r_bytes, &pub_bytes, &msg);
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r_bytes);
        sig[32..].copy_from_slice((r + k * a).as_bytes());

        // `8*T` is the identity, so `k*T` is `T` added `k mod 8` times.
        let k_torsion = (0..challenge_mod_8(&k)).fold(identity, |acc, _| acc + torsion);
        let agl = k_torsion == identity;
        assert_eq!(
            verify_raw(&pub_key, &msg, &sig),
            agl,
            "case {i}: key {}, message {}, signature {}",
            hex(&pub_bytes),
            hex(&msg),
            hex(&sig)
        );
        let scalar_form = scalar_negation_verifies(&pub_point, &sig, &k);
        if agl {
            accepted += 1;
        } else {
            rejected += 1;
        }
        forms_differ += usize::from(agl != scalar_form);
    }
    assert!(
        accepted > 40 && rejected > 40 && forms_differ > 40,
        "accepted {accepted}, rejected {rejected}, forms differ {forms_differ}"
    );
}
