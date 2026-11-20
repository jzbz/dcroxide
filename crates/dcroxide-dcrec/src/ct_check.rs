// SPDX-License-Identifier: ISC
//! The timing check of this crate's secrets: dudect's fixed-against-random
//! t-test, on `dcroxide-testutil`'s harness ([`dcroxide_testutil::ct`],
//! which `dcroxide-tlscrypto`'s check of ADR-0015 T10 shares, with
//! every class an equal share of the samples), over every entry
//! point that computes on a secret.  ADR-0017's second addendum of
//! 2026-11-19 records what it shows and what it does not.
//!
//! **The entry points that touch a secret**, from the crate's public
//! items and the one internal function they share, each with the target
//! that times it:
//!
//! | entry point | the secret | target |
//! |---|---|---|
//! | `mul_secret_by_generator` (internal: k256's `mul_by_generator`, the basepoint table's walk or `lincomb`) | the scalar | `generator_multiply` |
//! | `PrivateKey::public_key`, and through it `ReducedPrivateKey::public_point` and an HD private child's public key | the key | `public_key` |
//! | `PrivateKey::from_bytes`, `check_scalar`, `PrivateKey::serialize` | the key's bytes | `key_from_bytes` |
//! | `ecdsa::sign`, `ecdsa::sign_compact` (one signer, `sign_rfc6979`) | the key; the nonce | `ecdsa_signing_by_key`; `ecdsa_signing_by_nonce` |
//! | `schnorr::sign` | the key; the nonce | `schnorr_signing_by_key`; `schnorr_signing_by_nonce` |
//! | `nonce::nonce_rfc6979` | the key's bytes | `rfc6979_nonce_by_key` |
//! | `add_private_tweak`, and in it `ReducedPrivateKey::from_bytes`'s reduction and `ReducedPrivateKey::serialize` | Il; the parent key | `hd_private_child_by_tweak`; `hd_private_child_by_parent` |
//! | `edwards::SecretKey::from_seed`, which derives the scalar, the nonce prefix and the public key once (`SecretKey::public_key` returns the copy it keeps), and in it the seed's expansion that `SecretKey::from_bytes` also runs | the seed | `ed25519_public_key` |
//! | `edwards::sign`, `edwards::sign_with_pub_key_bytes`, from the scalar and prefix the key keeps | the seed's scalar and prefix | `ed25519_signing` |
//!
//! Nothing else computes on a secret.  Verification, compact recovery,
//! key parsing and serialization take public values, and
//! `add_public_tweak` takes a public tweak by its contract.
//! `ecdsa::sign_compact` adds to `ecdsa::sign` only the packing of a
//! public recovery code, so it is not timed apart.
//!
//! **The classes.**  A secp256k1 scalar's classes ([`key_classes`]) are
//! the extremes `dcroxide-tlscrypto` times its curves by: 1, 2, 0xff,
//! 2^64 - 1, the top bit alone, n - 1, n - 2, n - 1 with its bottom or its
//! top half zero (the high bits clear), eight bits set and eight cleared,
//! and n - 1 with every 4-bit window but the top one zero; and (n - 1)/2,
//! the low-S boundary, and a placebo ([`PLACEBO`]), the random class's
//! draw under a fixed label, which leans only on what the label brings.
//! A scalar that reaches the basepoint walk also has the classes of
//! k256's signed radix-16 recoding ([`walk_classes`]), whose 65 digits
//! each choose one of a table's eight multiples, or the identity for a
//! zero digit: every digit 1, every digit 7, every digit -8 (the largest
//! entry, negated, in every table), the even digits all zero (all 33 of
//! the walk's selects for its first accumulator give the identity: the
//! one that starts it, digit 64's, and the 32 it adds), and the odd digits
//! all zero (the second accumulator, which starts from the identity, adds
//! it in all 32 of its additions).  Those digits are the table path's
//! alone.  `lincomb`, without the feature, first splits the scalar k by
//! the GLV endomorphism into halves r1 and r2 of at most 128 bits, with
//! k = r1 + r2·λ modulo n, and recodes each half's magnitude into 33
//! signed digits: there 1, 2, 0xff, 2^64 - 1, n - 1 and n - 2 have r2 = 0
//! and r1 mostly zero digits, and the top bit alone has r1 of 32 bits (28
//! of its 33 digits zero) and r2 of full width, while the top window alone
//! and the walk's classes split into halves whose digits look like a
//! random scalar's.  So a scalar that reaches the multiplication also has
//! the classes of the split ([`glv_classes`]): λ, 2λ and (2^64 - 1)λ,
//! whose r1 is 0, every digit zero, and r2 is 1, 2 and 2^64 - 1, and the
//! two whose halves are equal and have every digit 7 or every digit -8
//! below the top.  On the table path they are scalars like any other.  An
//! HD parent key is reduced modulo n, so its classes add n, n + 1,
//! 2^256 - 1 and 0 ([`parent_classes`]).  An Ed25519 seed is hashed before
//! any arithmetic, so its classes are a few fixed seeds, dudect's own
//! fixed-against-random ([`seed_classes`]).
//!
//! **What varies with the class, and what does not.**  Signing by the key
//! draws a message hash for each sample, in the building and for every
//! class alike ([`ct::with_hedge`]), so that a fixed key fixes the key
//! alone: with the hash fixed too, a fixed key would repeat one RFC 6979
//! nonce and one signature on every sample, and a lean on the key could
//! not be told from one on them.  Signing by the nonce fixes the key and
//! the hash and times the nonce's own classes, which RFC 6979 never lands
//! on: ECDSA's `sign_with_nonce` from the nonce point to the low-S
//! signature, and EC-Schnorr-DCRv0's from the nonce's bytes to the
//! signature.  The HD targets fix one input and vary the other.
//!
//! **The positive control** (`vartime_multiply_control`) times k256's
//! variable-time multiply, `GENERATOR.mul_vartime(k)` (width-5 wNAF over
//! the GLV halves), on the classes of the generator's multiplication, and
//! must fail: it shows that the run sees a secret routed through a
//! variable-time multiply, the mistake the targets guard against.  Its
//! leak is far larger than any a target looks for, so finding it says
//! little of a run's power, though a |t| far below its usual hundreds
//! marks a run of low power; ADR-0017's addendum gives the planted leaks
//! that measured that power, and the control's |t| over runs.
//!
//! **Both multiplication paths.**  With the default `precomputed-tables`
//! feature the scalar walks k256's basepoint table; without it k256
//! computes `GENERATOR * k` by `lincomb`.  Each target's name in its row
//! carries the path its build took, `(table)` or `(no table)`, and the
//! workflow runs the targets once in each build.
//!
//! The targets are `#[ignore]` tests: they time code, so they run only when
//! asked, one at a time and in release mode, each for `DCROXIDE_CT_SECONDS`
//! seconds (10 when it is unset), best pinned to one processor:
//!
//! ```text
//! taskset -c 2 cargo test -p dcroxide-dcrec --release --lib ct_check -- --ignored --test-threads=1 --nocapture
//! taskset -c 2 cargo test -p dcroxide-dcrec --release --lib --no-default-features ct_check -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! `.github/workflows/constant-time.yml` runs them so, on x86_64 and arm64,
//! with and without the table.  The class lists' own tests run in every
//! `cargo test` and time nothing.
#![allow(
    clippy::arithmetic_side_effects,
    reason = "test arithmetic over bit positions, nibbles and digits, each far below its type's \
              limit, and k256's modular scalar arithmetic"
)]

use dcroxide_testutil::SplitMix64;
use dcroxide_testutil::ct::{
    self, PLACEBO, by_class, clear_eight, distinct, plus, random_bytes, set_bit, time_inputs,
    time_target,
};
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::ops::{MulVartime, Reduce};
use k256::{FieldBytes, ProjectivePoint, Scalar};

use crate::edwards;
use crate::secp256k1::{
    GROUP_ORDER_BYTES, PrivateKey, add_private_tweak, check_scalar, ecdsa, mul_secret_by_generator,
    nonce::nonce_rfc6979, schnorr,
};

/// The multiplication path this build takes for a secret scalar, which
/// each target's name carries: k256's basepoint table with the
/// `precomputed-tables` feature, and its `lincomb` without.
const PATH: &str = if cfg!(feature = "precomputed-tables") {
    "table"
} else {
    "no table"
};

/// The name a target's row gives: its test's name and [`PATH`].
fn target(name: &str) -> String {
    format!("{name} ({PATH})")
}

/// The fixed key, nonce, tweak or parent a target holds while it varies
/// another secret: 0x5a repeated, inside [1, n - 1].
const FIXED: [u8; 32] = [0x5a; 32];

/// The message hash signing by the nonce signs.
const HASH: [u8; 32] = [0xc3; 32];

/// The classes of a secret scalar in [1, n - 1], big-endian: the extremes
/// of the module's notes and a placebo, in that order.
fn key_classes() -> Vec<(&'static str, Vec<u8>)> {
    let order = GROUP_ORDER_BYTES.to_vec();
    let zero = vec![0; 32];
    let n_minus_1 = plus(&order, -1);
    let mut ones_64 = zero.clone();
    ones_64[24..].fill(0xff);
    let mut top_bit = zero.clone();
    set_bit(&mut top_bit, 255, true);
    let mut bottom_zero = n_minus_1.clone();
    bottom_zero[16..].fill(0);
    let mut top_zero = n_minus_1.clone();
    top_zero[..16].fill(0);
    let mut low_weight = zero.clone();
    for i in 0..8 {
        set_bit(&mut low_weight, i * 31, true);
    }
    let mut windows = n_minus_1.clone();
    for at in 0..252 {
        set_bit(&mut windows, at, false);
    }
    let mut half = n_minus_1.clone();
    let mut carry = 0;
    for byte in &mut half {
        let next = *byte & 1;
        *byte = (*byte >> 1) | (carry << 7);
        carry = next;
    }
    let mut classes = distinct(vec![
        ("1", plus(&zero, 1)),
        ("2", plus(&zero, 2)),
        ("0xff", plus(&zero, 0xff)),
        ("2^64 - 1", ones_64),
        ("top bit alone", top_bit),
        ("n - 1", n_minus_1.clone()),
        ("n - 2", plus(&order, -2)),
        ("(n - 1)/2", half),
        ("bottom half zero", bottom_zero),
        ("top half zero", top_zero),
        ("low weight", low_weight),
        ("high weight", clear_eight(&n_minus_1)),
        ("top window alone", windows),
    ]);
    classes.push((PLACEBO, Vec::new()));
    classes
}

/// The classes of k256's signed radix-16 recoding of a scalar the
/// basepoint walk reads, big-endian (the module's notes): every digit 1,
/// every digit 7, every digit -8 (0x77...78, whose nibbles of 7 each
/// carry 1 from the one below), the even digits zero and the odd digits
/// zero.
fn walk_classes() -> Vec<(&'static str, Vec<u8>)> {
    let mut minus_8 = vec![0x77; 32];
    minus_8[31] = 0x78;
    vec![
        ("every digit 1", vec![0x11; 32]),
        ("every digit 7", vec![0x77; 32]),
        ("every digit -8", minus_8),
        ("even digits zero", vec![0x70; 32]),
        ("odd digits zero", vec![0x07; 32]),
    ]
}

/// λ, big-endian: the cube root of unity modulo n by which k256's GLV
/// split writes k = r1 + r2·λ (k256 0.14.0 keeps its negation,
/// `MINUS_LAMBDA`, in `src/arithmetic/mul/glv.rs`).
const LAMBDA: [u8; 32] = [
    0x53, 0x63, 0xad, 0x4c, 0xc0, 0x5c, 0x30, 0xe0, 0xa5, 0x26, 0x1c, 0x02, 0x88, 0x12, 0x64, 0x5a,
    0x12, 0x2e, 0x22, 0xea, 0x20, 0x81, 0x66, 0x78, 0xdf, 0x02, 0x96, 0x7c, 0x1b, 0x23, 0xbd, 0x72,
];

/// The classes of k256's GLV split, which `lincomb` makes of a scalar
/// before its recoding (the module's notes), big-endian: λ, 2λ and
/// (2^64 - 1)λ, whose r1 is 0 and r2 is 1, 2 and 2^64 - 1, and the
/// scalars whose halves are both 0x0777...7 or both 0x0777...78, 31
/// nibbles, every digit 7, or every digit -8 below a top digit of 1.
/// Halves of 32 nibbles of 7 are too long: the split gives other halves
/// for their scalar.
fn glv_classes() -> Vec<(&'static str, Vec<u8>)> {
    let lambda = scalar(&LAMBDA);
    let of = |r1: &[u8], r2: &[u8]| -> Vec<u8> {
        let widen = |half: &[u8]| {
            let mut wide = vec![0; 32 - half.len()];
            wide.extend_from_slice(half);
            scalar(&wide)
        };
        (widen(r1) + widen(r2) * lambda).to_repr().to_vec()
    };
    let mut sevens = vec![0x77; 16];
    sevens[0] = 0x07;
    let mut minus_8 = sevens.clone();
    minus_8[15] = 0x78;
    vec![
        ("lambda", of(&[0], &[1])),
        ("2 lambda", of(&[0], &[2])),
        ("(2^64 - 1) lambda", of(&[0], &[0xff; 8])),
        ("both halves every digit 7", of(&sevens, &sevens)),
        ("both halves every digit -8", of(&minus_8, &minus_8)),
    ]
}

/// The classes of a scalar that reaches the generator's multiplication:
/// [`key_classes`], then [`walk_classes`] and [`glv_classes`].
fn scalar_classes() -> Vec<(&'static str, Vec<u8>)> {
    let mut classes = key_classes();
    classes.extend(walk_classes());
    classes.extend(glv_classes());
    classes
}

/// The classes of an HD parent key, which `add_private_tweak` reduces
/// modulo n: [`key_classes`], then n and 0, which reduce to zero, n + 1,
/// which reduces to 1, and 2^256 - 1, the largest.
fn parent_classes() -> Vec<(&'static str, Vec<u8>)> {
    let mut classes = key_classes();
    classes.extend([
        ("n", GROUP_ORDER_BYTES.to_vec()),
        ("0", vec![0; 32]),
        ("n + 1", plus(&GROUP_ORDER_BYTES, 1)),
        ("2^256 - 1", vec![0xff; 32]),
    ]);
    classes
}

/// The classes of an Ed25519 seed: all zeros, all ones, and 0x55 and 0xaa
/// in turn.  SHA-512 stands between the seed and the arithmetic, so
/// these are fixed secrets and not extremes.
fn seed_classes() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("all zeros", vec![0; 32]),
        ("all ones", vec![0xff; 32]),
        ("0x55 and 0xaa", [0x55, 0xaa].repeat(16)),
    ]
}

/// A random scalar in [1, n - 1], big-endian: 32 random bytes, drawn until
/// they are one.
fn random_scalar(rng: &mut SplitMix64) -> Vec<u8> {
    loop {
        let bytes = random_bytes(rng, 32);
        if bytes.iter().any(|&b| b != 0) && bytes.as_slice() < GROUP_ORDER_BYTES.as_slice() {
            return bytes;
        }
    }
}

/// 32 bytes from a class's or a draw's.
fn array(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().expect("32 bytes")
}

/// The k256 scalar of 32 big-endian bytes below n.
fn scalar(bytes: &[u8]) -> Scalar {
    Option::from(Scalar::from_repr(FieldBytes::from(array(bytes)))).expect("a scalar below n")
}

/// The private key of 32 big-endian bytes in [1, n - 1].
fn key(bytes: &[u8]) -> PrivateKey {
    PrivateKey::from_bytes(&array(bytes)).expect("a key in [1, n - 1]")
}

/// The inputs of a target by a key's classes, each with a message hash of
/// 32 bytes drawn for it, whatever its class, so that a fixed class fixes
/// the key alone.
fn by_key_with_hash<I>(
    classes: &[(&'static str, Vec<u8>)],
    build: impl FnMut(&[u8]) -> I,
) -> impl FnMut(Option<usize>, &mut SplitMix64) -> (I, [u8; 32]) {
    let mut input = ct::with_hedge(by_class(classes, random_scalar, build), 32);
    move |class, rng| {
        let (made, hash) = input(class, rng);
        (made, array(&hash))
    }
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn generator_multiply() {
    time_target(
        &target("generator_multiply"),
        &scalar_classes(),
        random_scalar,
        scalar,
        |k| mul_secret_by_generator(k),
    )
    .assert_constant_time();
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn public_key() {
    time_target(
        &target("public_key"),
        &scalar_classes(),
        random_scalar,
        key,
        |key| key.public_key(),
    )
    .assert_constant_time();
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn key_from_bytes() {
    time_target(
        &target("key_from_bytes"),
        &key_classes(),
        random_scalar,
        array,
        |bytes| {
            (
                check_scalar(bytes),
                PrivateKey::from_bytes(bytes).map(|key| key.serialize()),
            )
        },
    )
    .assert_constant_time();
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn ecdsa_signing_by_key() {
    let classes = key_classes();
    time_inputs(
        &target("ecdsa_signing_by_key"),
        &classes,
        by_key_with_hash(&classes, key),
        |(key, hash)| ecdsa::sign(key, hash),
    )
    .assert_constant_time();
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn ecdsa_signing_by_nonce() {
    let d = scalar(&FIXED);
    let e = <Scalar as Reduce<FieldBytes>>::reduce(&FieldBytes::from(HASH));
    time_target(
        &target("ecdsa_signing_by_nonce"),
        &scalar_classes(),
        random_scalar,
        scalar,
        |k| ecdsa::sign_with_nonce(&d, k, &e),
    )
    .assert_constant_time();
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn schnorr_signing_by_key() {
    let classes = key_classes();
    time_inputs(
        &target("schnorr_signing_by_key"),
        &classes,
        by_key_with_hash(&classes, key),
        |(key, hash)| schnorr::sign(key, hash),
    )
    .assert_constant_time();
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn schnorr_signing_by_nonce() {
    let d = scalar(&FIXED);
    time_target(
        &target("schnorr_signing_by_nonce"),
        &scalar_classes(),
        random_scalar,
        array,
        |nonce| schnorr::sign_with_nonce(&d, nonce, &HASH),
    )
    .assert_constant_time();
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn rfc6979_nonce_by_key() {
    let classes = key_classes();
    time_inputs(
        &target("rfc6979_nonce_by_key"),
        &classes,
        by_key_with_hash(&classes, array),
        |(key, hash)| nonce_rfc6979(key, hash, None, None, 0),
    )
    .assert_constant_time();
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn hd_private_child_by_tweak() {
    time_target(
        &target("hd_private_child_by_tweak"),
        &key_classes(),
        random_scalar,
        array,
        |tweak| add_private_tweak(tweak, &FIXED),
    )
    .assert_constant_time();
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn hd_private_child_by_parent() {
    time_target(
        &target("hd_private_child_by_parent"),
        &parent_classes(),
        |rng| random_bytes(rng, 32),
        array,
        |parent| add_private_tweak(&FIXED, parent),
    )
    .assert_constant_time();
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn ed25519_public_key() {
    time_target(
        &target("ed25519_public_key"),
        &seed_classes(),
        |rng| random_bytes(rng, 32),
        array,
        |seed| edwards::SecretKey::from_seed(*seed).public_key(),
    )
    .assert_constant_time();
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn ed25519_signing() {
    time_target(
        &target("ed25519_signing"),
        &seed_classes(),
        |rng| random_bytes(rng, 32),
        |seed| edwards::SecretKey::from_seed(array(seed)),
        |secret| edwards::sign(secret, &HASH),
    )
    .assert_constant_time();
}

/// The positive control: k256's variable-time multiply of the generator,
/// on the classes of a scalar that reaches the multiplication.
#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn vartime_multiply_control() {
    time_target(
        &target("vartime_multiply_control"),
        &scalar_classes(),
        random_scalar,
        scalar,
        |k| ProjectivePoint::GENERATOR.mul_vartime(&*k),
    )
    .assert_leak_found();
}

mod tests {
    use k256::elliptic_curve::Group;
    use k256::elliptic_curve::scalar::IsHigh;
    use k256::elliptic_curve::sec1::ToSec1Point;

    use super::*;
    use crate::secp256k1::PublicKey;

    /// The class named `name` among `classes`.
    fn class(classes: &[(&'static str, Vec<u8>)], name: &str) -> Vec<u8> {
        classes
            .iter()
            .find(|(label, _)| *label == name)
            .unwrap_or_else(|| panic!("no class {name}"))
            .1
            .clone()
    }

    /// k256's signed radix-16 digits of the big-endian `bytes`, as
    /// `primeorder`'s `Radix16Decomposition` makes them (`primeorder`
    /// 0.14.0 `src/tables/radix16.rs:31-55`): the nibbles from the least
    /// significant, each recentred into [-8, 8) by carrying one into the
    /// next, and the carry out as the last digit.  Of 32 bytes these are
    /// the basepoint walk's 65 digits (`U65`), and of the low 16 bytes of
    /// a GLV half's magnitude `lincomb`'s 33 (`U33`).
    fn digits(bytes: &[u8]) -> Vec<i8> {
        let mut out = vec![0i8; 2 * bytes.len() + 1];
        for (i, byte) in bytes.iter().rev().enumerate() {
            out[2 * i] = (byte & 0xf) as i8;
            out[2 * i + 1] = (byte >> 4) as i8;
        }
        for i in 0..2 * bytes.len() {
            let carry = (out[i] + 8) >> 4;
            out[i] -= carry << 4;
            out[i + 1] += carry;
        }
        out
    }

    /// The 32 bytes of a hexadecimal constant of 64 digits.
    fn hex(text: &str) -> [u8; 32] {
        let mut out = [0; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex");
        }
        out
    }

    /// k256 0.14.0's constants of the GLV split
    /// (`src/arithmetic/mul/glv.rs:9-37`): -λ, -b1, -b2, g1 and g2.
    const MINUS_LAMBDA: &str = "ac9c52b33fa3cf1f5ad9e3fd77ed9ba4a880b9fc8ec739c2e0cfc810b51283cf";
    const MINUS_B1: &str = "00000000000000000000000000000000e4437ed6010e88286f547fa90abfe4c3";
    const MINUS_B2: &str = "fffffffffffffffffffffffffffffffe8a280ac50774346dd765cda83db1562c";
    const G1: &str = "3086d221a7d46bcde86c90e49284eb153daa8a1471e8ca7fe893209a45dbb031";
    const G2: &str = "e4437ed6010e88286f547fa90abfe4c4221208ac9df506c61571b4ae8ac47f71";

    /// round(a·b / 2^384) of two big-endian 256-bit values, as k256's
    /// `WideScalar::mul_shift_vartime(a, b, 384)` computes it
    /// (`src/arithmetic/scalar/wide64.rs:64-118`): the 512-bit product's
    /// top 128 bits, plus one when the highest bit discarded is set.
    fn mul_shift_384(a: &[u8; 32], b: &[u8; 32]) -> Scalar {
        let limbs = |v: &[u8; 32]| -> [u64; 4] {
            std::array::from_fn(|i| {
                u64::from_be_bytes(v[32 - 8 * (i + 1)..32 - 8 * i].try_into().expect("8"))
            })
        };
        let (a, b) = (limbs(a), limbs(b));
        let mut product = [0u64; 8];
        for (i, &x) in a.iter().enumerate() {
            let mut carry = 0u128;
            for (j, &y) in b.iter().enumerate() {
                let sum = u128::from(x) * u128::from(y) + u128::from(product[i + j]) + carry;
                product[i + j] = sum as u64;
                carry = sum >> 64;
            }
            product[i + 4] = carry as u64;
        }
        let top = (u128::from(product[7]) << 64) | u128::from(product[6]);
        let rounded = top + u128::from(product[5] >> 63);
        let mut bytes = [0u8; 32];
        bytes[16..].copy_from_slice(&rounded.to_be_bytes());
        scalar(&bytes)
    }

    /// k256 0.14.0's GLV split of k, `glv::decompose_scalar`
    /// (`src/arithmetic/mul/glv.rs:149-156`), ported: r1 and r2 with
    /// r1 + r2·λ = k modulo n, each of magnitude below 2^128.
    fn glv_split(k: &Scalar) -> (Scalar, Scalar) {
        let k_bytes: [u8; 32] = k.to_repr().into();
        let c1 = mul_shift_384(&k_bytes, &hex(G1)) * scalar(&hex(MINUS_B1));
        let c2 = mul_shift_384(&k_bytes, &hex(G2)) * scalar(&hex(MINUS_B2));
        let r2 = c1 + c2;
        let r1 = *k + r2 * scalar(&hex(MINUS_LAMBDA));
        (r1, r2)
    }

    /// The 33 digits `lincomb` recodes a GLV half into: those of its
    /// magnitude, the half or its negation, whichever is at most
    /// (n - 1)/2, as `lincomb`'s `conditional_select` on `is_high` picks
    /// it (`src/arithmetic/mul.rs:121-129`), which must fit 128 bits.
    fn half_digits(half: &Scalar) -> Vec<i8> {
        let magnitude = if bool::from(half.is_high()) {
            -*half
        } else {
            *half
        };
        let bytes: [u8; 32] = magnitude.to_repr().into();
        assert!(bytes[..16].iter().all(|&b| b == 0), "{bytes:02x?}");
        digits(&bytes[16..])
    }

    /// How many of `digits` are zero.
    fn zeros(digits: &[i8]) -> usize {
        digits.iter().filter(|&&d| d == 0).count()
    }

    /// The digits' recoding, by hand on the module's examples, gives back
    /// the scalar: 0x78 is 8 + 7·16, digits -8 and 8 before the carry
    /// into the top.
    #[test]
    fn the_recoding_answers_a_hand_computation() {
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(digits(&one)[..3], [1, 0, 0]);
        let mut x78 = [0u8; 32];
        x78[31] = 0x78;
        assert_eq!(digits(&x78)[..3], [-8, -8, 1]);
        let mut x0f = [0u8; 32];
        x0f[31] = 0x0f;
        assert_eq!(digits(&x0f)[..3], [-1, 1, 0]);
    }

    /// Every secp256k1 class but the placebo is a scalar in [1, n - 1],
    /// distinct from every other, and named for what it is.
    #[test]
    fn the_scalar_classes_are_distinct_scalars_in_range() {
        let classes = scalar_classes();
        let values: Vec<&Vec<u8>> = classes.iter().map(|(_, value)| value).collect();
        for (name, value) in &classes {
            if *name == PLACEBO {
                assert!(value.is_empty());
                continue;
            }
            assert_eq!(value.len(), 32, "{name}");
            assert!(value.iter().any(|&b| b != 0), "{name}");
            assert!(value.as_slice() < GROUP_ORDER_BYTES.as_slice(), "{name}");
            assert_eq!(values.iter().filter(|v| **v == value).count(), 1, "{name}");
        }
        let names: Vec<&str> = classes.iter().map(|(name, _)| *name).collect();
        assert_eq!(names.len(), 24, "{names:?}");
        assert_eq!(class(&classes, "n - 1"), plus(&GROUP_ORDER_BYTES, -1));
        let half = class(&classes, "(n - 1)/2");
        assert_eq!(
            plus(&ct::times(&half, 2), 1),
            plus(&GROUP_ORDER_BYTES, 0),
            "(n - 1)/2 doubled and one added is n"
        );
        let weight = |v: &[u8]| v.iter().map(|b| b.count_ones()).sum::<u32>();
        assert_eq!(weight(&class(&classes, "low weight")), 8);
        assert_eq!(
            weight(&class(&classes, "high weight")) + 8,
            weight(&plus(&GROUP_ORDER_BYTES, -1))
        );
        assert!(
            class(&classes, "top half zero")[..16]
                .iter()
                .all(|&b| b == 0)
        );
        assert!(
            class(&classes, "bottom half zero")[16..]
                .iter()
                .all(|&b| b == 0)
        );
        assert_eq!(class(&classes, "top window alone")[0], 0xf0);
    }

    /// The walk's classes have the digits they are named for: every digit
    /// 1 or 7 below the top, every digit -8 below a top of 1, and the even
    /// or the odd digits all zero, the top digit 64 being even.
    #[test]
    fn the_walk_classes_have_the_digits_they_are_named_for() {
        let classes = walk_classes();
        let of = |name: &str| digits(&class(&classes, name));
        let one = of("every digit 1");
        assert!(one[..64].iter().all(|&d| d == 1) && one[64] == 0, "{one:?}");
        let seven = of("every digit 7");
        assert!(
            seven[..64].iter().all(|&d| d == 7) && seven[64] == 0,
            "{seven:?}"
        );
        let minus_8 = of("every digit -8");
        assert!(
            minus_8[..64].iter().all(|&d| d == -8) && minus_8[64] == 1,
            "{minus_8:?}"
        );
        let even = of("even digits zero");
        assert!(even.iter().step_by(2).all(|&d| d == 0), "{even:?}");
        assert!(even.iter().skip(1).step_by(2).all(|&d| d == 7), "{even:?}");
        let odd = of("odd digits zero");
        assert!(odd.iter().skip(1).step_by(2).all(|&d| d == 0), "{odd:?}");
        assert!(odd[..64].iter().step_by(2).all(|&d| d == 7), "{odd:?}");
        // On the table path the top window alone is mostly zero digits too.
        let keys = key_classes();
        assert_eq!(
            digits(&class(&keys, "top window alone"))
                .iter()
                .filter(|&&d| d != 0)
                .count(),
            2
        );
    }

    /// The port of k256's GLV split meets k256's own bounds on random
    /// scalars, each half's magnitude below 2^128 (which [`half_digits`]
    /// checks), and gives back k from r1 + r2·λ with the [`LAMBDA`] the
    /// classes use, a cube root of unity modulo n other than 1: wrong
    /// constants in the port would break the bounds.
    #[test]
    fn the_glv_split_port_meets_k256s_bounds() {
        let lambda = scalar(&LAMBDA);
        assert_eq!(lambda, -scalar(&hex(MINUS_LAMBDA)));
        assert_ne!(lambda, Scalar::ONE);
        assert_eq!(lambda * lambda * lambda, Scalar::ONE);
        let mut rng = SplitMix64(0x676c_765f_7370_6c74);
        let mut extremes = vec![plus(&GROUP_ORDER_BYTES, -1), plus(&[0; 32], 1)];
        extremes.extend((0..2_000).map(|_| random_scalar(&mut rng)));
        for value in &extremes {
            let k = scalar(value);
            let (r1, r2) = glv_split(&k);
            assert_eq!(r1 + r2 * lambda, k, "{value:02x?}");
            assert_eq!(half_digits(&r1).len(), 33);
            assert_eq!(half_digits(&r2).len(), 33);
        }
    }

    /// The split's classes split as named: λ, 2λ and (2^64 - 1)λ into
    /// r1 = 0, every digit zero, and r2 = 1, 2 and 2^64 - 1, and the
    /// equal halves into 31 digits of 7, or of -8 below a 1, and zeros
    /// above.  No other class has r1 = 0.
    #[test]
    fn the_glv_classes_split_as_named() {
        let classes = glv_classes();
        let split = |name: &str| glv_split(&scalar(&class(&classes, name)));
        for (name, r2) in [
            ("lambda", 1),
            ("2 lambda", 2),
            ("(2^64 - 1) lambda", u64::MAX),
        ] {
            let (r1, got) = split(name);
            assert_eq!(r1, Scalar::ZERO, "{name}");
            assert_eq!(got, Scalar::from(r2), "{name}");
            assert_eq!(zeros(&half_digits(&r1)), 33, "{name}");
        }
        let (r1, r2) = split("both halves every digit 7");
        assert_eq!(r1, r2);
        let sevens = half_digits(&r1);
        assert!(
            sevens[..31].iter().all(|&d| d == 7) && sevens[31..] == [0, 0],
            "{sevens:?}"
        );
        let (r1, r2) = split("both halves every digit -8");
        assert_eq!(r1, r2);
        let minus_8 = half_digits(&r1);
        assert!(
            minus_8[..31].iter().all(|&d| d == -8) && minus_8[31..] == [1, 0],
            "{minus_8:?}"
        );
        for (name, value) in key_classes().into_iter().chain(walk_classes()) {
            if name == PLACEBO {
                continue;
            }
            assert_ne!(glv_split(&scalar(&value)).0, Scalar::ZERO, "{name}");
        }
    }

    /// What the split makes of the other classes, as the module's notes
    /// say: r2 = 0 and r1 of at most 64 bits for the small classes and
    /// n - 1 and n - 2; r1 of 28 zero digits of 33 for the top bit alone;
    /// and at most 5 zero digits in each half, as a random scalar has
    /// about 2, for the top window alone and the walk's classes, whose
    /// structure is the table path's only.
    #[test]
    fn the_other_classes_split_as_the_notes_say() {
        let keys = key_classes();
        let walk = walk_classes();
        let halves = |classes: &[(&'static str, Vec<u8>)], name: &str| {
            let (r1, r2) = glv_split(&scalar(&class(classes, name)));
            (half_digits(&r1), half_digits(&r2))
        };
        for name in ["1", "2", "0xff", "2^64 - 1", "n - 1", "n - 2"] {
            let (r1, r2) = halves(&keys, name);
            assert_eq!(zeros(&r2), 33, "{name}");
            assert!(zeros(&r1) >= 31, "{name}: {r1:?}");
        }
        let (r1, r2) = halves(&keys, "top bit alone");
        assert_eq!(zeros(&r1), 28, "{r1:?}");
        assert!(zeros(&r2) <= 5, "{r2:?}");
        let mut random_looking = vec![halves(&keys, "top window alone")];
        random_looking.extend(walk.iter().map(|(name, _)| halves(&walk, name)));
        for (r1, r2) in random_looking {
            assert!(zeros(&r1) <= 5 && zeros(&r2) <= 5, "{r1:?} {r2:?}");
        }
    }

    /// The parent classes reduce as named: n and 0 to zero, n + 1 to 1, and
    /// 2^256 - 1 to 2^256 - 1 - n; each makes a child with Il fixed.
    #[test]
    fn the_parent_classes_reduce_as_named() {
        let classes = parent_classes();
        let tweak = scalar(&FIXED);
        for (name, value) in &classes {
            if *name == PLACEBO {
                continue;
            }
            let child = add_private_tweak(&FIXED, value).expect("Il in range");
            let reduced = <Scalar as Reduce<FieldBytes>>::reduce(&FieldBytes::from(array(value)));
            let want: [u8; 32] = (tweak + reduced).to_repr().into();
            assert_eq!(*child.serialize(), want, "{name}");
        }
        let fixed = *add_private_tweak(&FIXED, &[0; 32]).expect("Il").serialize();
        assert_eq!(fixed, FIXED);
        assert_eq!(
            *add_private_tweak(&FIXED, &GROUP_ORDER_BYTES)
                .expect("Il")
                .serialize(),
            FIXED
        );
    }

    /// The targets' operations reach what they are named for, on each
    /// class: the multiply is the public key's point, signing by the nonce
    /// gives a signature that verifies under the fixed key, and every key
    /// class signs, both ways, a hash that verifies.
    #[test]
    fn every_class_reaches_its_targets_operation() {
        let fixed = key(&FIXED);
        let fixed_public = fixed.public_key();
        for (name, value) in scalar_classes() {
            if name == PLACEBO {
                continue;
            }
            let k = scalar(&value);
            let point = mul_secret_by_generator(&k);
            assert!(!bool::from(point.is_identity()), "{name}");
            assert_eq!(point, ProjectivePoint::GENERATOR.mul_vartime(&k), "{name}");
            let public = key(&value).public_key();
            let encoded = k256::AffinePoint::from(point).to_sec1_point(false);
            assert_eq!(
                PublicKey::parse(encoded.as_bytes()).expect("a point on the curve"),
                public,
                "{name}"
            );

            let e = <Scalar as Reduce<FieldBytes>>::reduce(&FieldBytes::from(HASH));
            let (signature, _) =
                ecdsa::sign_with_nonce(&scalar(&FIXED), &k, &e).expect("r and s nonzero");
            assert!(signature.verify(&HASH, &fixed_public), "{name}");
            let signature =
                schnorr::sign_with_nonce(&scalar(&FIXED), &array(&value), &HASH).expect("e < n");
            assert!(signature.verify(&HASH, &fixed_public), "{name}");
        }
        for (name, value) in key_classes() {
            if name == PLACEBO {
                continue;
            }
            let signer = key(&value);
            let public = signer.public_key();
            assert!(ecdsa::sign(&signer, &HASH).verify(&HASH, &public), "{name}");
            let signature = schnorr::sign(&signer, &HASH).expect("a 32-byte hash");
            assert!(signature.verify(&HASH, &public), "{name}");
            assert_eq!(check_scalar(&array(&value)), Ok(()), "{name}");
            assert!(add_private_tweak(&array(&value), &FIXED).is_ok(), "{name}");
        }
    }

    /// Signing by the key draws a hash for every input, whatever its class:
    /// from generators alike, a fixed class's hash and the placebo's are
    /// the random class's, and a fixed class keeps its key while its hashes
    /// differ.
    #[test]
    fn signing_by_the_key_fixes_the_key_alone() {
        let classes = key_classes();
        let mut build = by_key_with_hash(&classes, <[u8]>::to_vec);
        let placebo = classes.len() - 1;
        let seed = 0x6279_5f6b_6579_2121;
        let (mut fixed, mut placebo_rng, mut random) =
            (SplitMix64(seed), SplitMix64(seed), SplitMix64(seed));
        let mut hashes = Vec::new();
        for _ in 0..8 {
            let (value, hash) = build(Some(0), &mut fixed);
            assert_eq!(value, classes[0].1);
            let (drawn, random_hash) = build(None, &mut random);
            assert_eq!(hash, random_hash);
            assert_eq!(build(Some(placebo), &mut placebo_rng), (drawn, random_hash));
            hashes.push(hash);
        }
        assert!(hashes.windows(2).all(|pair| pair[0] != pair[1]));
    }

    /// The random draws are in range: a scalar in [1, n - 1], and every
    /// seed and parent of 32 bytes.
    #[test]
    fn the_random_scalars_are_in_range() {
        let mut rng = SplitMix64(0x7261_6e67_6521_2121);
        for _ in 0..1_000 {
            let value = random_scalar(&mut rng);
            assert_eq!(value.len(), 32);
            assert!(PrivateKey::from_bytes(&array(&value)).is_some());
        }
    }

    /// Each target names the path its build takes.
    #[test]
    fn a_targets_name_carries_the_multiplication_path() {
        let name = target("public_key");
        if cfg!(feature = "precomputed-tables") {
            assert_eq!(name, "public_key (table)");
        } else {
            assert_eq!(name, "public_key (no table)");
        }
    }

    /// The Ed25519 seeds are three distinct seeds of 32 bytes that sign.
    #[test]
    fn the_seed_classes_sign() {
        let classes = seed_classes();
        for (name, seed) in &classes {
            let secret = edwards::SecretKey::from_seed(array(seed));
            assert!(
                edwards::sign(&secret, &HASH).verify(&HASH, &secret.public_key()),
                "{name}"
            );
        }
        assert_eq!(distinct(classes.clone()).len(), classes.len());
    }
}
