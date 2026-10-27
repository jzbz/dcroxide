// SPDX-License-Identifier: ISC
//! The tool that makes the signature parity corpus `sig_corpus` reads
//! (ADR-0015, step 1), for `regenerate_parity_corpus` in
//! `tests/ring_parity.rs`, the one test binary with ring to give ring's
//! verdicts.  `sig_corpus` says what the corpus holds; this builds it.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::{BTreeMap, HashMap};
use std::io::Write;

use dcroxide_testutil::{Oracle, RSA_TEST_KEYS, SplitMix64, hex, rsa_test_key, unhex};
use serde_json::{Value, json};

use crate::sig_corpus::{
    ALGORITHMS, PATH, WYCHEPROOF_FILES, go_verifies, wycheproof_algorithm, wycheproof_file,
    wycheproof_key,
};

/// The bounds the corpus is held to, so that it stays a file to commit:
/// its cases.
pub const MAX_CASES: usize = 20_000;
/// The same, on the compressed file's bytes.
pub const MAX_BYTES: usize = 2_000_000;

/// ring's verdict on an algorithm, by its place, a key, a message and a
/// signature.
pub type RingVerdict<'a> = &'a dyn Fn(usize, &[u8], &[u8], &[u8]) -> bool;

/// A DER element: `tag`, its length in the fewest bytes, and `content`.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let len = content.len();
    let mut out = vec![tag];
    match len {
        0..0x80 => out.push(len as u8),
        0x80..0x100 => out.extend([0x81, len as u8]),
        _ => out.extend([0x82, (len >> 8) as u8, len as u8]),
    }
    out.extend_from_slice(content);
    out
}

/// The length of a DER element's header, and of its content, for the short
/// form and the long form of up to two bytes.
fn header(element: &[u8]) -> (usize, usize) {
    match element[1] {
        len @ 0..=0x7f => (2, usize::from(len)),
        0x81 => (3, usize::from(element[2])),
        0x82 => (4, usize::from(element[2]) << 8 | usize::from(element[3])),
        other => panic!("a length form the corpus does not write: {other:#04x}"),
    }
}

/// The elements of a DER element's content, each whole.
fn elements(element: &[u8]) -> Vec<Vec<u8>> {
    let (start, len) = header(element);
    let mut rest = &element[start..start + len];
    let mut out = Vec::new();
    while !rest.is_empty() {
        let (h, l) = header(rest);
        out.push(rest[..h + l].to_vec());
        rest = &rest[h + l..];
    }
    out
}

/// An element's content.
fn content(element: &[u8]) -> &[u8] {
    let (start, len) = header(element);
    &element[start..start + len]
}

/// The positions of a DER element's header bytes, and of the first and
/// last byte of each primitive element's content, recursing into each
/// SEQUENCE within: where a bit flip of a DER structure goes.
fn der_positions(element: &[u8], offset: usize, out: &mut Vec<usize>) {
    let (h, len) = header(element);
    out.extend(offset..offset + h);
    if element[0] == 0x30 {
        let mut at = h;
        while at < h + len {
            let (eh, el) = header(&element[at..]);
            der_positions(&element[at..at + eh + el], offset + at, out);
            at += eh + el;
        }
    } else if len > 0 {
        out.push(offset + h);
        out.push(offset + h + len - 1);
    }
}

/// `positions`, then eight drawn from `rng` below `len`, each once.
fn with_drawn(mut positions: Vec<usize>, len: usize, rng: &mut SplitMix64) -> Vec<usize> {
    if len > 0 {
        for _ in 0..8 {
            positions.push(usize::try_from(rng.below(len as u64)).expect("small"));
        }
    }
    positions.sort_unstable();
    positions.dedup();
    positions
}

/// `bytes` with bit `bit` of the byte at `at` flipped.
fn flipped(bytes: &[u8], at: usize, bit: u32) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[at] ^= 1 << bit;
    out
}

/// A signature made by Go: the oracle's `sig_sign` answer.
fn go_sign(oracle: &mut Oracle, request: Value) -> Option<Vec<u8>> {
    let response = oracle.call("sig_sign", request.to_string().as_bytes());
    if response.get("error").is_some() {
        return None;
    }
    dcroxide_testutil::require_reference_go(response["go_version"].as_str().unwrap_or_default());
    Some(unhex(response["result"].as_str().expect("a signature")))
}

/// The corpus being built.
struct Builder<'a> {
    /// The oracle, for Go's signatures and verdicts.
    oracle: &'a mut Oracle,
    /// ring's verdict on an algorithm, a key, a message and a signature.
    ring: RingVerdict<'a>,
    /// The key table.
    keys: Vec<String>,
    /// Each key's place in the table.
    key_index: HashMap<Vec<u8>, usize>,
    /// The fixture's RSA keys, by their `RSAPublicKey`.
    rsa_names: HashMap<Vec<u8>, &'static str>,
    /// The generated cases.
    cases: Vec<Value>,
    /// How many cases each class has.
    classes: BTreeMap<String, usize>,
    /// How many signatures each signer made.
    signers: BTreeMap<String, usize>,
}

impl Builder<'_> {
    /// `key`'s place in the table, adding it the first time.
    fn key(&mut self, key: &[u8]) -> usize {
        if let Some(&index) = self.key_index.get(key) {
            return index;
        }
        let entry = match self.rsa_names.get(key) {
            Some(name) => format!("rsa:{name}"),
            None => hex(key),
        };
        self.keys.push(entry);
        self.key_index.insert(key.to_vec(), self.keys.len() - 1);
        self.keys.len() - 1
    }

    /// Add a case, with ring's verdict and Go's.
    fn add(
        &mut self,
        class: &str,
        algorithm: usize,
        key: &[u8],
        message: &[u8],
        signature: &[u8],
        signer: &str,
    ) {
        let ring = (self.ring)(algorithm, key, message, signature);
        let go = go_verifies(self.oracle, algorithm, key, message, signature);
        let key = self.key(key);
        self.cases.push(json!([
            class,
            algorithm,
            key,
            hex(message),
            hex(signature),
            signer,
            ring,
            go
        ]));
        *self.classes.entry(class.to_owned()).or_default() += 1;
        *self.signers.entry(signer.to_owned()).or_default() += 1;
    }

    /// Add a case for each single-bit flip of the key, the message and the
    /// signature at their positions: `key_positions` and `signature_positions`
    /// (each structure's header and field ends) and the message's ends, each
    /// with eight drawn from `rng`.
    #[allow(clippy::too_many_arguments)]
    fn flips(
        &mut self,
        prefix: &str,
        algorithm: usize,
        (key, message, signature): (&[u8], &[u8], &[u8]),
        key_positions: Vec<usize>,
        signature_positions: Vec<usize>,
        signer: &str,
        rng: &mut SplitMix64,
    ) {
        let ends = |len: usize| if len == 0 { vec![] } else { vec![0, len - 1] };
        for at in with_drawn(key_positions, key.len(), rng) {
            let bit = u32::try_from(rng.below(8)).expect("a bit");
            let class = format!("{prefix}-flip-key");
            self.add(
                &class,
                algorithm,
                &flipped(key, at, bit),
                message,
                signature,
                signer,
            );
        }
        for at in with_drawn(ends(message.len()), message.len(), rng) {
            let bit = u32::try_from(rng.below(8)).expect("a bit");
            let class = format!("{prefix}-flip-message");
            self.add(
                &class,
                algorithm,
                key,
                &flipped(message, at, bit),
                signature,
                signer,
            );
        }
        for at in with_drawn(signature_positions, signature.len(), rng) {
            let bit = u32::try_from(rng.below(8)).expect("a bit");
            let class = format!("{prefix}-flip-signature");
            self.add(
                &class,
                algorithm,
                key,
                message,
                &flipped(signature, at, bit),
                signer,
            );
        }
    }
}

/// An EC key of `curve`'s OID with `scalar`, in PKCS#8 holding a SEC 1 key
/// without its public key, which Go's `ParsePKCS8PrivateKey` reads.
fn ec_pkcs8(curve: &[u8], scalar: &[u8]) -> Vec<u8> {
    let algorithm = tlv(
        0x30,
        &[
            tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]),
            tlv(0x06, curve),
        ]
        .concat(),
    );
    let sec1 = tlv(0x30, &[tlv(0x02, &[1]), tlv(0x04, scalar)].concat());
    tlv(
        0x30,
        &[tlv(0x02, &[0]), algorithm, tlv(0x04, &sec1)].concat(),
    )
}

/// An Ed25519 key with `seed`, in PKCS#8.
fn ed25519_pkcs8(seed: &[u8; 32]) -> Vec<u8> {
    tlv(
        0x30,
        &[
            tlv(0x02, &[0]),
            tlv(0x30, &tlv(0x06, &[0x2b, 0x65, 0x70])),
            tlv(0x04, &tlv(0x04, seed)),
        ]
        .concat(),
    )
}

/// An ECDSA key of the corpus.
struct EcdsaKey {
    /// Its curve's name.
    curve: &'static str,
    /// The key in PKCS#8, for Go to sign with.
    pkcs8: Vec<u8>,
    /// Its uncompressed point.
    public: Vec<u8>,
    /// Its curve's order, big-endian.
    order: Vec<u8>,
}

/// The ECDSA keys: three on each curve, each scalar from a fixed seed.
fn ecdsa_keys() -> Vec<EcdsaKey> {
    use p256::elliptic_curve::sec1::ToSec1Point;
    let mut rng = SplitMix64(0x5ec0_2026_1027);
    let mut out = Vec::new();
    for _ in 0..3 {
        let mut scalar = [0u8; 32];
        rng.fill(&mut scalar);
        scalar[0] &= 0x7f;
        let public = p256::SecretKey::from_slice(&scalar)
            .expect("a scalar")
            .public_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        let order = unhex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
        let pkcs8 = ec_pkcs8(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07], &scalar);
        out.push(EcdsaKey {
            curve: "P-256",
            pkcs8,
            public,
            order,
        });
    }
    for _ in 0..3 {
        let mut scalar = [0u8; 48];
        rng.fill(&mut scalar);
        scalar[0] &= 0x7f;
        let public = p384::SecretKey::from_slice(&scalar)
            .expect("a scalar")
            .public_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        let order = unhex(
            "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf\
             581a0db248b0a77aecec196accc52973",
        );
        let pkcs8 = ec_pkcs8(&[0x2b, 0x81, 0x04, 0x00, 0x22], &scalar);
        out.push(EcdsaKey {
            curve: "P-384",
            pkcs8,
            public,
            order,
        });
    }
    out
}

/// `value` plus `add`, both big-endian of one length, the carry dropped.
fn plus(value: &[u8], add: &[u8]) -> Vec<u8> {
    let mut out = value.to_vec();
    let mut carry = 0u16;
    for (byte, add) in out.iter_mut().rev().zip(add.iter().rev()) {
        let sum = u16::from(*byte) + u16::from(*add) + carry;
        *byte = sum as u8;
        carry = sum >> 8;
    }
    out
}

/// An unsigned big-endian value as a minimal DER INTEGER's content.
fn integer_content(value: &[u8]) -> Vec<u8> {
    let start = value
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(value.len() - 1);
    let value = &value[start..];
    if value[0] & 0x80 != 0 {
        [&[0][..], value].concat()
    } else {
        value.to_vec()
    }
}

/// The ECDSA cases.
fn ecdsa(builder: &mut Builder<'_>, rng: &mut SplitMix64) {
    let messages: Vec<Vec<u8>> = [0, 33, 200]
        .iter()
        .map(|&len| {
            let mut message = vec![0; len];
            rng.fill(&mut message);
            message
        })
        .collect();
    for (key_index, key) in ecdsa_keys().iter().enumerate() {
        let EcdsaKey {
            curve,
            pkcs8,
            public,
            order,
        } = key;
        let algorithms: [usize; 2] = if *curve == "P-256" { [0, 1] } else { [2, 3] };
        for algorithm in algorithms {
            for (message_index, message) in messages.iter().enumerate() {
                let signature = go_sign(
                    builder.oracle,
                    json!({
                        "key_pkcs8": hex(pkcs8),
                        "x509_alg": ALGORITHMS[algorithm].1,
                        "message": hex(message),
                    }),
                )
                .expect("Go signs with its own key");
                builder.add(
                    "ecdsa-valid",
                    algorithm,
                    public,
                    message,
                    &signature,
                    "go:crypto/ecdsa",
                );
                if message_index != 1 {
                    continue;
                }
                for other in 0..4 {
                    if other != algorithm {
                        builder.add(
                            "ecdsa-other-algorithm",
                            other,
                            public,
                            message,
                            &signature,
                            "go:crypto/ecdsa",
                        );
                    }
                }
                if key_index % 3 != 0 {
                    continue;
                }
                // The full set of variants, on the first key of each curve.
                let mut signature_positions = Vec::new();
                der_positions(&signature, 0, &mut signature_positions);
                let field = (public.len() - 1) / 2;
                let key_positions = vec![0, 1, field, field + 1, public.len() - 1];
                builder.flips(
                    "ecdsa",
                    algorithm,
                    (public, message, &signature),
                    key_positions,
                    signature_positions,
                    "go:crypto/ecdsa",
                    rng,
                );
                let parts = elements(&signature);
                let (r, s) = (content(&parts[0]).to_vec(), content(&parts[1]).to_vec());
                let seq = |inner: &[Vec<u8>]| tlv(0x30, &inner.concat());
                let int = |value: &[u8]| tlv(0x02, value);
                let body = [parts[0].clone(), parts[1].clone()].concat();
                let mut negative_r = r.clone();
                if negative_r[0] == 0 {
                    negative_r.remove(0);
                } else {
                    negative_r[0] |= 0x80;
                }
                let order_len = order.len();
                let fixed = |value: &[u8]| {
                    let value = &value[value.len().saturating_sub(order_len)..];
                    [vec![0; order_len - value.len()], value.to_vec()].concat()
                };
                let high_s = {
                    // n - s, the other signature with the same r.
                    let s_fixed = fixed(&s);
                    let mut out = order.clone();
                    let mut borrow = 0i16;
                    for (byte, sub) in out.iter_mut().rev().zip(s_fixed.iter().rev()) {
                        let diff = i16::from(*byte) - i16::from(*sub) - borrow;
                        borrow = i16::from(diff < 0);
                        *byte = (diff + 256 * borrow) as u8;
                    }
                    integer_content(&out)
                };
                // r + n, a byte longer than the order so nothing carries out.
                let r_plus_n = plus(
                    &[&[0][..], &fixed(&r)].concat(),
                    &[&[0][..], order].concat(),
                );
                let variants: Vec<(&str, Vec<u8>)> = vec![
                    (
                        "ecdsa-der",
                        [vec![0x30, 0x81, body.len() as u8], body.clone()].concat(),
                    ),
                    (
                        "ecdsa-der",
                        seq(&[
                            [vec![0x02, 0x81, r.len() as u8], r.clone()].concat(),
                            parts[1].clone(),
                        ]),
                    ),
                    (
                        "ecdsa-der",
                        seq(&[int(&[&[0][..], &r].concat()), parts[1].clone()]),
                    ),
                    (
                        "ecdsa-der",
                        seq(&[parts[0].clone(), int(&[&[0][..], &s].concat())]),
                    ),
                    ("ecdsa-der", [signature.clone(), vec![0x00]].concat()),
                    (
                        "ecdsa-der",
                        seq(&[parts[0].clone(), parts[1].clone(), vec![0x00]]),
                    ),
                    (
                        "ecdsa-der",
                        seq(&[parts[0].clone(), parts[1].clone(), int(&[1])]),
                    ),
                    (
                        "ecdsa-der",
                        [vec![0x30, 0x80], body.clone(), vec![0x00, 0x00]].concat(),
                    ),
                    ("ecdsa-der", seq(&[int(&negative_r), parts[1].clone()])),
                    ("ecdsa-der", tlv(0x31, &body)),
                    ("ecdsa-der", seq(&[parts[0].clone()])),
                    ("ecdsa-der", Vec::new()),
                    ("ecdsa-der", [fixed(&r), fixed(&s)].concat()),
                    ("ecdsa-range", seq(&[int(&[0]), parts[1].clone()])),
                    ("ecdsa-range", seq(&[parts[0].clone(), int(&[0])])),
                    (
                        "ecdsa-range",
                        seq(&[int(&integer_content(order)), parts[1].clone()]),
                    ),
                    (
                        "ecdsa-range",
                        seq(&[parts[0].clone(), int(&integer_content(order))]),
                    ),
                    (
                        "ecdsa-range",
                        seq(&[int(&integer_content(&r_plus_n)), parts[1].clone()]),
                    ),
                    ("ecdsa-range", seq(&[parts[1].clone(), parts[0].clone()])),
                    ("ecdsa-high-s", seq(&[parts[0].clone(), int(&high_s)])),
                ];
                for (class, variant) in variants {
                    builder.add(
                        class,
                        algorithm,
                        public,
                        message,
                        &variant,
                        "go:crypto/ecdsa",
                    );
                }
                let mut compressed = public[..1 + field].to_vec();
                compressed[0] = 0x02 | (public[public.len() - 1] & 1);
                let mut wrong_parity = compressed.clone();
                wrong_parity[0] ^= 1;
                let mut hybrid = public.clone();
                hybrid[0] = 0x06 | (public[public.len() - 1] & 1);
                let p = if *curve == "P-256" {
                    unhex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff")
                } else {
                    unhex(
                        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
                         ffffffff0000000000000000ffffffff",
                    )
                };
                let x_plus_p = plus(&public[1..1 + field], &p);
                let forms: Vec<Vec<u8>> = vec![
                    compressed,
                    wrong_parity,
                    hybrid,
                    public[..public.len() - 1].to_vec(),
                    [public.clone(), vec![0]].concat(),
                    vec![0x00],
                    [&[0x04][..], &p, &public[1 + field..]].concat(),
                    [&[0x04][..], &x_plus_p, &public[1 + field..]].concat(),
                    [&[0x04][..], &public[1..1 + field], &p].concat(),
                ];
                for form in forms {
                    builder.add(
                        "ecdsa-point-form",
                        algorithm,
                        &form,
                        message,
                        &signature,
                        "go:crypto/ecdsa",
                    );
                }
            }
        }
    }
}

/// The Ed25519 cases.
fn ed25519(builder: &mut Builder<'_>, rng: &mut SplitMix64) {
    use curve25519_dalek::edwards::EdwardsPoint;
    use curve25519_dalek::scalar::Scalar;
    let messages: Vec<Vec<u8>> = [0, 64, 129]
        .iter()
        .map(|&len| {
            let mut message = vec![0; len];
            rng.fill(&mut message);
            message
        })
        .collect();
    for key_index in 0..4 {
        let mut seed = [0u8; 32];
        rng.fill(&mut seed);
        let pkcs8 = ed25519_pkcs8(&seed);
        let public = dcroxide_tlscrypto::sign::load_der(&pkcs8)
            .expect("an Ed25519 key")
            .public_key()
            .expect("its public key")
            .as_ref()
            .to_vec();
        let public = public[public.len() - 32..].to_vec();
        for (message_index, message) in messages.iter().enumerate() {
            let signature = go_sign(
                builder.oracle,
                json!({"key_pkcs8": hex(&pkcs8), "x509_alg": "Ed25519", "message": hex(message)}),
            )
            .expect("Go signs with its own key");
            builder.add(
                "ed25519-valid",
                4,
                &public,
                message,
                &signature,
                "go:crypto/ed25519",
            );
            if key_index != 0 || message_index != 1 {
                continue;
            }
            builder.flips(
                "ed25519",
                4,
                (&public, message, &signature),
                vec![0, 31],
                vec![0, 31, 32, 63],
                "go:crypto/ed25519",
                rng,
            );
            let l = unhex("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed");
            let s_be: Vec<u8> = signature[32..].iter().rev().copied().collect();
            let le = |be: &[u8]| be.iter().rev().copied().collect::<Vec<u8>>();
            let mut top = signature.clone();
            top[63] |= 0x80;
            for (class, variant) in [
                (
                    "ed25519-s-range",
                    [&signature[..32], &le(&plus(&s_be, &l))].concat(),
                ),
                (
                    "ed25519-s-range",
                    [&signature[..32], &le(&plus(&plus(&s_be, &l), &l))].concat(),
                ),
                ("ed25519-s-range", [&signature[..32], &le(&l)].concat()),
                ("ed25519-s-range", top),
                ("ed25519-s-range", [&signature[..32], &[0; 32]].concat()),
                ("ed25519-length", signature[..63].to_vec()),
                ("ed25519-length", [signature.clone(), vec![0]].concat()),
            ] {
                builder.add(class, 4, &public, message, &variant, "go:crypto/ed25519");
            }
            for variant in [public[..31].to_vec(), [public.clone(), vec![0]].concat()] {
                builder.add(
                    "ed25519-length",
                    4,
                    &variant,
                    message,
                    &signature,
                    "go:crypto/ed25519",
                );
            }
        }
    }
    // Keys written with y below 19, canonically and as y + p, with the sign
    // bit clear and set, under a signature [S]B, S: the identity among
    // them, the order-2 and order-4 points, and encodings that decode to
    // no point.
    let s = Scalar::from_bytes_mod_order([0x2b; 32]);
    let forged = [
        &EdwardsPoint::mul_base(&s).compress().to_bytes()[..],
        s.as_bytes(),
    ]
    .concat();
    let p = unhex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");
    let message = b"any message at all".to_vec();
    let minus_one: Vec<u8> = {
        let mut be = p.clone();
        let last = be.len() - 1;
        be[last] -= 1;
        be.iter().rev().copied().collect()
    };
    let mut keys: Vec<Vec<u8>> = Vec::new();
    for y in 0u8..19 {
        let mut be = vec![0; 32];
        be[31] = y;
        for value in [be.clone(), plus(&be, &p)] {
            let le: Vec<u8> = value.iter().rev().copied().collect();
            keys.push(le.clone());
            let mut signed = le;
            signed[31] |= 0x80;
            keys.push(signed);
        }
    }
    let mut signed_minus_one = minus_one.clone();
    signed_minus_one[31] |= 0x80;
    keys.extend([minus_one, signed_minus_one]);
    for key in &keys {
        builder.add(
            "ed25519-key-encoding",
            4,
            key,
            &message,
            &forged,
            "constructed",
        );
    }
    // The challenge is hashed over the key as received.  Under a key of
    // order 4 or 2, [S]B, S verifies exactly when k so hashed is a multiple
    // of the order, so the encodings of one point, canonical and not,
    // verify different messages: the points of order 4, y = 0, written as
    // 0 and as p, and the point of order 2, y = -1, each with the sign bit
    // clear and set, over eight messages.
    let y_is_p: Vec<u8> = p.iter().rev().copied().collect();
    let order_2 = keys[keys.len() - 2].clone();
    let mut hashed_keys = Vec::new();
    for key in [vec![0u8; 32], y_is_p, order_2] {
        let mut signed = key.clone();
        signed[31] |= 0x80;
        hashed_keys.extend([key, signed]);
    }
    for key in &hashed_keys {
        for i in 0u8..8 {
            let message = [b'k', i];
            builder.add("ed25519-key-hash", 4, key, &message, &forged, "constructed");
        }
    }
    // R written otherwise than canonically: the identity's encodings under
    // the identity key and S = 0, which makes R' the identity.
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut identity_signed = identity;
    identity_signed[31] |= 0x80;
    let mut identity_p_plus_1 = [0xffu8; 32];
    identity_p_plus_1[0] = 0xee;
    identity_p_plus_1[31] = 0x7f;
    for r in [identity, identity_signed, identity_p_plus_1] {
        let signature = [&r[..], &[0; 32]].concat();
        builder.add(
            "ed25519-r-encoding",
            4,
            &identity,
            &message,
            &signature,
            "constructed",
        );
    }
}

/// The class of a fixture key's valid signatures: whether it lies within
/// ring's bounds and Go's.
fn rsa_class(name: &str) -> &'static str {
    match name {
        "rsa1024" => "rsa-modulus-1024",
        "rsa2040" => "rsa-modulus-2040",
        "rsa8193" => "rsa-modulus-8193",
        "rsa2048-e2147483649" | "rsa2048-e8589934591" => "rsa-exponent-above-go",
        "rsa2048-e8589934593" => "rsa-exponent-above-ring",
        _ => "rsa-valid",
    }
}

/// The RSA cases.
fn rsa(builder: &mut Builder<'_>, rng: &mut SplitMix64) {
    let message = |rng: &mut SplitMix64, len: usize| {
        let mut message = vec![0; len];
        rng.fill(&mut message);
        message
    };
    // The raw signer, held to crypto/rsa on every key both take: PKCS#1
    // v1.5 signatures byte for byte, and its PSS signatures verified by
    // crypto/rsa's VerifyPSS through `sig_verify`.
    for &(name, ..) in RSA_TEST_KEYS {
        let key = rsa_test_key(name);
        let checked = message(rng, 40);
        let request = |raw: bool, x509_alg: &str| json!({"rsa": key.oracle_json(), "x509_alg": x509_alg, "message": hex(&checked), "raw": raw});
        let Some(through_rsa) = go_sign(builder.oracle, request(false, "SHA256-RSA")) else {
            continue;
        };
        let raw = go_sign(builder.oracle, request(true, "SHA256-RSA")).expect("the raw signer");
        assert_eq!(raw, through_rsa, "{name}: the raw signer is crypto/rsa's");
        let raw_pss =
            go_sign(builder.oracle, request(true, "SHA256-RSAPSS")).expect("the raw signer");
        assert!(
            go_verifies(builder.oracle, 5, &key.rsa_public_key(), &checked, &raw_pss),
            "{name}: crypto/rsa verifies the raw signer's PSS"
        );
    }

    let rsa2048 = rsa_test_key("rsa2048");
    let public2048 = rsa2048.rsa_public_key();
    let mut kept: HashMap<usize, (Vec<u8>, Vec<u8>, String)> = HashMap::new();
    for &(name, ..) in RSA_TEST_KEYS {
        let key = rsa_test_key(name);
        let public = key.rsa_public_key();
        for (algorithm, (_, x509_alg)) in ALGORITHMS.iter().enumerate().skip(5) {
            let messages = if name == "rsa2048" { 2 } else { 1 };
            for _ in 0..messages {
                let signed = message(rng, 70);
                let request = |raw: bool| {
                    json!({
                        "rsa": key.oracle_json(),
                        "x509_alg": x509_alg,
                        "message": hex(&signed),
                        "raw": raw,
                    })
                };
                let (signature, signer) = match go_sign(builder.oracle, request(false)) {
                    Some(signature) => (signature, "go:crypto/rsa"),
                    None => match go_sign(builder.oracle, request(true)) {
                        Some(signature) => (signature, "go:raw"),
                        // PSS with SHA-512 does not fit a 1024-bit key.
                        None => continue,
                    },
                };
                builder.add(
                    rsa_class(name),
                    algorithm,
                    &public,
                    &signed,
                    &signature,
                    signer,
                );
                if name == "rsa2048" {
                    kept.insert(
                        algorithm,
                        (signed.clone(), signature.clone(), signer.to_owned()),
                    );
                }
            }
        }
    }
    // Exponents ring and Go both refuse, 1, 2 and 0, on rsa2048's modulus
    // with its signatures; and under e = 1 signatures from the raw signer
    // with d = 1, each of which is its own encoding and would verify were
    // the exponent taken.
    let n_int = tlv(0x02, &integer_content(&rsa2048.n));
    for e in [vec![0x01], vec![0x02], vec![0x00]] {
        let key = tlv(0x30, &[n_int.clone(), tlv(0x02, &e)].concat());
        for algorithm in [5, 8] {
            let (signed, signature, signer) = &kept[&algorithm];
            builder.add(
                "rsa-exponent-refused",
                algorithm,
                &key,
                signed,
                signature,
                signer,
            );
        }
    }
    let e_1 = tlv(0x30, &[n_int.clone(), tlv(0x02, &[0x01])].concat());
    let mut d_1 = rsa2048.oracle_json();
    d_1["e"] = json!("01");
    d_1["d"] = json!("01");
    for algorithm in [5, 8] {
        let signed = message(rng, 30);
        let request = json!({
            "rsa": d_1,
            "x509_alg": ALGORITHMS[algorithm].1,
            "message": hex(&signed),
            "raw": true,
        });
        let encoding = go_sign(builder.oracle, request).expect("the raw signer");
        builder.add(
            "rsa-exponent-refused",
            algorithm,
            &e_1,
            &signed,
            &encoding,
            "go:raw",
        );
    }
    for algorithm in 5..14 {
        let (signed, signature, signer) = kept[&algorithm].clone();
        for other in 5..14 {
            if other != algorithm {
                builder.add(
                    "rsa-other-algorithm",
                    other,
                    &public2048,
                    &signed,
                    &signature,
                    &signer,
                );
            }
        }
        let mut key_positions = Vec::new();
        der_positions(&public2048, 0, &mut key_positions);
        let k = signature.len();
        let key_positions = if matches!(algorithm, 5 | 8) {
            key_positions
        } else {
            Vec::new()
        };
        builder.flips(
            "rsa",
            algorithm,
            (&public2048, &signed, &signature),
            key_positions,
            vec![0, k - 1],
            &signer,
            rng,
        );
        if !matches!(algorithm, 5 | 8) {
            continue;
        }
        // The key's DER, otherwise written.
        let parts = elements(&public2048);
        let (n, e) = (parts[0].clone(), parts[1].clone());
        let body = [n.clone(), e.clone()].concat();
        let seq = |inner: &[Vec<u8>]| tlv(0x30, &inner.concat());
        let n_content = content(&n).to_vec();
        let e_content = content(&e).to_vec();
        let negative_n = tlv(0x02, &n_content[1..]);
        let mut even = n_content.clone();
        let last = even.len() - 1;
        even[last] &= 0xfe;
        for (class, key) in [
            (
                "rsa-key-der",
                [
                    vec![0x30, 0x83, 0x00, (body.len() >> 8) as u8, body.len() as u8],
                    body.clone(),
                ]
                .concat(),
            ),
            (
                "rsa-key-der",
                seq(&[
                    n.clone(),
                    [vec![0x02, 0x81, e_content.len() as u8], e_content.clone()].concat(),
                ]),
            ),
            (
                "rsa-key-der",
                seq(&[tlv(0x02, &[&[0][..], &n_content].concat()), e.clone()]),
            ),
            (
                "rsa-key-der",
                seq(&[n.clone(), tlv(0x02, &[&[0][..], &e_content].concat())]),
            ),
            ("rsa-key-der", seq(&[negative_n, e.clone()])),
            (
                "rsa-key-der",
                [vec![0x30, 0x80], body.clone(), vec![0x00, 0x00]].concat(),
            ),
            ("rsa-key-der", seq(std::slice::from_ref(&n))),
            ("rsa-key-der", seq(&[e.clone(), n.clone()])),
            ("rsa-key-der", tlv(0x31, &body)),
            ("rsa-key-der", seq(&[tlv(0x02, &even), e.clone()])),
            ("rsa-key-der", body.clone()),
            (
                "rsa-key-trailing-data",
                seq(&[n.clone(), e.clone(), tlv(0x02, &[0])]),
            ),
            (
                "rsa-key-trailing-data",
                seq(&[n.clone(), e.clone(), vec![0x00]]),
            ),
            (
                "rsa-key-trailing-data",
                [public2048.clone(), vec![0x00]].concat(),
            ),
            (
                "rsa-key-trailing-data",
                [public2048.clone(), tlv(0x02, &[1])].concat(),
            ),
        ] {
            builder.add(class, algorithm, &key, &signed, &signature, &signer);
        }
        // Signatures of the wrong length, zero, n and n + 1.
        let n_bytes = &rsa2048.n;
        for wrong in [
            signature[1..].to_vec(),
            [vec![0], signature.clone()].concat(),
            vec![0; k],
            n_bytes.clone(),
            plus(n_bytes, &[1]),
            Vec::new(),
        ] {
            builder.add(
                "rsa-signature-range",
                algorithm,
                &public2048,
                &signed,
                &wrong,
                &signer,
            );
        }
    }
    // PKCS#1 v1.5 encodings without NULL and with short padding, and PSS
    // salts of other lengths, from the raw signer, on keys of 2048 and 2041
    // bits.
    for name in ["rsa2048", "rsa2041"] {
        let key = rsa_test_key(name);
        let public = key.rsa_public_key();
        for algorithm in 5..14 {
            let signed = message(rng, 50);
            let mut variants: Vec<Value> = Vec::new();
            if algorithm >= 8 {
                for encoding in ["no_null", "short_padding"] {
                    variants.push(json!({"encoding": encoding}));
                }
            } else {
                let h_len = [32, 48, 64][algorithm - 5];
                for salt_len in [0, h_len - 1, h_len + 1, 2 * h_len] {
                    variants.push(json!({"salt_len": salt_len}));
                }
            }
            for variant in variants {
                let mut request = json!({
                    "rsa": key.oracle_json(),
                    "x509_alg": ALGORITHMS[algorithm].1,
                    "message": hex(&signed),
                    "raw": true,
                });
                for (field, value) in variant.as_object().expect("an object") {
                    request[field] = value.clone();
                }
                let signature = go_sign(builder.oracle, request).expect("the raw signer");
                let class = if algorithm >= 8 {
                    "rsa-pkcs1-encoding"
                } else {
                    "rsa-pss-salt"
                };
                builder.add(class, algorithm, &public, &signed, &signature, "go:raw");
            }
        }
    }
}

/// The Wycheproof references: every case of each signature file under the
/// algorithm the crate's harness runs it under, skipping the PSS groups of
/// a hash no algorithm takes.
fn wycheproof(builder: &mut Builder<'_>) -> Vec<Value> {
    let mut out = Vec::new();
    for (file, _) in WYCHEPROOF_FILES {
        let vectors = wycheproof_file(file);
        for group in vectors["testGroups"].as_array().expect("testGroups") {
            let Some(algorithm) = wycheproof_algorithm(file, group) else {
                continue;
            };
            let key = wycheproof_key(file, group);
            for case in group["tests"].as_array().expect("tests") {
                let field = |name: &str| unhex(case[name].as_str().expect("a hex field"));
                let (message, signature) = (field("msg"), field("sig"));
                let ring = (builder.ring)(algorithm, &key, &message, &signature);
                let go = go_verifies(builder.oracle, algorithm, &key, &message, &signature);
                out.push(json!([file, case["tcId"], algorithm, ring, go]));
            }
        }
    }
    out
}

/// Make the corpus again, with `ring` for ring's verdicts, and write it,
/// failing above the bounds: the tool `regenerate_parity_corpus` runs.
/// The header records the count of each class and signer, the
/// compressed size, and where the verdicts came from, so the oracle must
/// run the reference Go, whatever `DCROXIDE_REQUIRE_ORACLE` says.
pub fn regenerate(oracle: &mut Oracle, ring: RingVerdict<'_>) {
    let build = oracle.call("build_info", b"");
    assert_eq!(
        build["go_version"].as_str(),
        Some(dcroxide_testutil::REFERENCE_GO),
        "the corpus's Go column is the reference Go's: {build}"
    );
    let rsa_names = RSA_TEST_KEYS
        .iter()
        .map(|&(name, ..)| (rsa_test_key(name).rsa_public_key(), name))
        .collect();
    let mut builder = Builder {
        oracle,
        ring,
        keys: Vec::new(),
        key_index: HashMap::new(),
        rsa_names,
        cases: Vec::new(),
        classes: BTreeMap::new(),
        signers: BTreeMap::new(),
    };
    let mut rng = SplitMix64(0x5160_2026_1027);
    ecdsa(&mut builder, &mut rng);
    ed25519(&mut builder, &mut rng);
    rsa(&mut builder, &mut rng);
    let references = wycheproof(&mut builder);
    let total = builder.cases.len() + references.len();
    assert!(total <= MAX_CASES, "{total} cases, above {MAX_CASES}");

    let mut corpus = json!({
        "about": "The signature verification parity corpus of ADR-0015's first step: \
                  dcroxide-tlscrypto's fourteen algorithms, in SUPPORTED_SIG_ALGS.all's \
                  order, on keys, messages and signatures valid and not, with ring's verdict \
                  and Go's recorded for each. Made by regenerate_parity_corpus in \
                  tests/ring_parity.rs; tests/sig_corpus/mod.rs says what each class is. \
                  The ring column came from ring 0.17.14 through rustls 0.23.46's ring \
                  provider, before the switch removes ring, and cannot be made again after \
                  it; the Go column can, through the oracle's sig_verify. A case is \
                  [class, algorithm, key, message, signature, signer, ring, go], its key an \
                  index into keys, where rsa:<name> is that key of dcroxide-testutil's RSA \
                  test-key fixture; a Wycheproof case is [file, tcId, algorithm, ring, go], \
                  into tests/data/wycheproof.",
        "ring": "0.17.14",
        "go_version": dcroxide_testutil::REFERENCE_GO,
        "algorithms": ALGORITHMS.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
        "classes": builder.classes,
        "signers": builder.signers,
        "wycheproof_cases": references.len(),
        "compressed_bytes": 0,
        "keys": builder.keys,
        "cases": builder.cases,
        "wycheproof": references,
    });
    // The header records the file's own compressed size, so compress until
    // the size it records is the size it has.
    let mut compressed = Vec::new();
    for _ in 0..8 {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        let mut text = serde_json::to_string(&corpus).expect("the corpus as JSON");
        text.push('\n');
        encoder.write_all(text.as_bytes()).expect("compressed");
        compressed = encoder.finish().expect("compressed");
        if corpus["compressed_bytes"] == json!(compressed.len()) {
            break;
        }
        corpus["compressed_bytes"] = json!(compressed.len());
    }
    assert_eq!(
        corpus["compressed_bytes"],
        json!(compressed.len()),
        "a size that settles"
    );
    assert!(
        compressed.len() <= MAX_BYTES,
        "{} bytes, above {MAX_BYTES}",
        compressed.len()
    );
    let path = format!("{}/{PATH}", env!("CARGO_MANIFEST_DIR"));
    std::fs::create_dir_all(std::path::Path::new(&path).parent().expect("a directory"))
        .expect("the directory");
    std::fs::write(&path, compressed).unwrap_or_else(|e| panic!("{path}: {e}"));
}
