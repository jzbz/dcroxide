// SPDX-License-Identifier: ISC
//! The constant-time check ADR-0015 asks for (T10), on the paths where a
//! secret meets this crate's code: ECDSA and Ed25519 signing, the four key
//! exchanges, the three AEADs, AES-GCM's keying and HMAC.  It is dudect's
//! test (Reparaz, Balasch and Verbauwhede, "Dude, is my code constant
//! time?", 2017) on `dcroxide-testutil`'s harness
//! ([`dcroxide_testutil::ct`]), which `dcroxide-dcrec`'s timing check
//! shares and whose notes give the measurement and the verdict: an
//! operation is timed with `std::time::Instant` on inputs of fixed classes
//! and of a random class, interleaved, each class an equal share of the
//! samples; the inputs are built ahead, every class's the same way; an
//! operation quicker than about two microseconds runs in a batch; dudect's
//! crops trim the slow tail; and Welch's t fails a class at |t| above 10
//! on a difference of 1 ns an operation or more.  Until 2026-11-20 this
//! module held its own copy of that harness, which gave the random class
//! half of the samples and each fixed class an equal share of the other
//! half (ADR-0015's addendum of that date); the targets, their classes,
//! the positive control, the verdict and the known report below are what
//! they were.
//!
//! * **Fixed classes at extremes.**  A fixed secret drawn at random has
//!   about the random class's average count of whatever a leak would key
//!   on (zero windows, set bits, leading zero limbs), so its mean time
//!   matches the random class's even where the code leaks.  Each target
//!   has several fixed classes instead, each a corner case of its secret
//!   (the scalar 1, n - 1, the top bit alone, a clamped scalar's least and
//!   greatest values), and each is compared with the random class on its
//!   own.
//! * **Inputs as the provider holds them.**  A key, an exchange or a
//!   cipher is made from each sample's bytes in the building, outside the
//!   timed region, and the operation borrows it.  Only an exchange's
//!   `complete` consumes its input, as it does in the provider, so that
//!   drop is timed.  A chunk's inputs fit in a core's cache, so that an
//!   operation finds its input there, as the provider finds the cipher or
//!   the key it keeps.
//! * **Two classes on P-256 and P-384 that check the check.**  P-384's
//!   complete failed the nightly arm64 runs of 2026-11-10 and 11-12 on
//!   fixed classes about 250 ns an operation quicker than the random
//!   class, n - 1 and n - 2 the first night and the top window alone the
//!   second, and by then had passed every other 60 s run there (ADR-0015's
//!   note of 2026-11-12).  P-256's signing by the key failed the nightly
//!   x86_64 run of 2026-11-13 on the portable backends on n - 2, about 11
//!   ns an operation quicker than the random class, an offset its earlier
//!   runs did not show (ADR-0015's note of 2026-11-14).  The targets of
//!   both curves time two more classes to tell why: a placebo
//!   ([`PLACEBO`]), whose input is the random class's draw under a fixed
//!   label of its own, which leans only on what the label and not the
//!   value brings, from the harness or the machine; and n - 2 again, under
//!   a name of its own, which leans with n - 2 if a lean follows the
//!   value.  Each is compared and judged like any other class.
//! * **A hedge for each sample in signing by the key.**  The handshake
//!   signer mixes a hedge it draws for each signature into RFC 6979's
//!   nonce, and signing by the key draws one for each sample's input, in
//!   the building and so outside the timed region, the same way for every
//!   class ([`with_hedge`]).  A fixed class fixes the key alone: with the
//!   hedge fixed too, each fixed class repeated one nonce, and so one r
//!   and s, on every sample and in every run, and a lean on the key could
//!   not be told from one on them.  Signing by the nonce times the nonce's
//!   own classes.
//! * **A known report on x86_64.**  P-256 signing by the nonce failed a
//!   push run and the nightly run of 2026-11-15 on x86_64, both on AMD
//!   EPYC 7763 runners: the classes 1, 2, 0xff and 2^64 - 1 were about
//!   15 ns an operation quicker than the random class, |t| up to 27 at
//!   60 s, and every class's difference followed one line, about 0.27 ns
//!   quicker for each addition of the identity to the identity in its
//!   basepoint walk (ADR-0015's note of 2026-11-15).  No branch or
//!   address in the timed code follows the nonce's value, in the source or
//!   in a near-identical local build.  That target, and no other, gives
//!   the harness a known report ([`known_report`],
//!   [`P256_SIGNING_BY_NONCE_KNOWN`]): built for x86_64, so on both legs
//!   there, a failure in which every comparison that fails has the fixed
//!   class quicker than the random class, by 40 ns an operation or less,
//!   passes, and its row and its failing classes' lines say so where they
//!   would say LEAK.  A class slower than the random class, a difference
//!   beyond the bound, any other target and any other architecture fail
//!   as before.
//!
//! The targets are `#[ignore]` tests: they time code, so they run only when
//! asked, one at a time and in release mode, each for `DCROXIDE_CT_SECONDS`
//! seconds of wall time (10 when it is unset).
//!
//! ```text
//! cargo test -p dcroxide-tlscrypto --release --lib ct_check -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! `.github/workflows/constant-time.yml` runs them so, with the processor's
//! backends and with the portable ones, on x86_64 and arm64; a dispatch of
//! it can run one target alone, for a budget of its own, on the legs it
//! picks.  Each target prints one row, marked `ct_check row |`, which the
//! workflow takes from the log wherever on its line the test runner's own
//! output leaves it and puts in the job's summary.  Below the row a target
//! that passes prints each class's result, a line each, as a failure's
//! message gives them, so that every run's log holds them and not only a
//! failing one's.  Those lines and a failure's message end with the
//! harness's trace, lines marked `ct_check run |`, `ct_check random |` and
//! `ct_check class |` at their start, which the summary does not take.
//! The workflow's arm64 jobs also check, in a program of their own outside
//! the crate, whether user space can switch DIT on, and a dispatch can ask
//! for the targets to be timed there with DIT on: a library outside the
//! crate (`.github/dit-on.rs`), loaded into the test binary, sets it
//! before `main` and prints its readings in lines marked `ct_check dit |`,
//! the harness itself unchanged.  Linux keeps it for each thread and hands
//! it to the threads a thread starts, the test runner's among them.  The
//! class lists' own tests run in every `cargo test` and time nothing; the
//! harness's run in `dcroxide-testutil`'s.
//!
//! It is statistical.  It sees a difference large enough to show on the
//! machine that runs it, fails only on one of a nanosecond an operation or
//! more, and a pass is not a proof.  What is timed is the operation as the
//! provider runs it, so public work inside it is timed too, with one
//! exception: an ECDSA target's timed region ends at the signature as r
//! and s at the field's length each, short of the DER encoding the
//! provider sends.  The encoding's path and length follow r's and s's
//! leading bytes.  A fixed nonce, with the message and the key fixed,
//! makes the same signature on every sample, so it repeats one r and s and
//! always takes one path, where the random class mixes them, as a fixed key
//! did while its hedge was fixed.
//! With the encoding timed, P-256 signing by the nonce failed nightly runs
//! on differences of a few nanoseconds an operation that followed the
//! signature's shape and no property of the nonce.  The encoding depends
//! only on the signature, which the handshake publishes, so leaving it out
//! hides nothing secret.  A seal's cipher is built ahead, as the provider
//! makes one for each traffic key and seals every record with it, so AES's
//! key schedule and GHASH's key are timed by the keying targets alone
//! (ChaCha20-Poly1305 keys itself in each seal).  The Ed25519 nonce
//! target's nonce is a scalar built ahead too, where the provider reduces
//! SHA-512's output to one inside the signing that the key target times.
//! The Ed25519 key reduces its expanded scalar mod L, as RFC 8032's signing
//! does, so what its arithmetic sees of 2^254 or 2^255 - 8 is the residue;
//! two of its classes are expanded scalars within the clamp whose residues
//! are extremes themselves, 2 and L - 1.
//!
//! ML-DSA is not timed: neither its signing nor its key's expansion from
//! the seed (ADR-0015's addenda of 2026-11-13 and 2026-11-14).  The
//! rounds of signing's rejection loop, and so its time, follow the key,
//! the message and the hedge by design.  The expansion samples by
//! rejection too.  For each polynomial of the secret vectors (FIPS 204's
//! `RejBoundedPoly`) the crate squeezes two SHAKE256 blocks up front,
//! enough for nearly every seed (`ml-dsa-0.1.2/src/sampling.rs:122-146`),
//! but how many of their bytes it reads, and which of their halves it
//! rejects, follow the secret seed in all three sets, as they do in Go's
//! `sampleBoundedPoly` (`crypto/internal/fips140/mldsa/field.go:330-365`);
//! and the public matrix's sampling rejects as many values as the seed's
//! hash gives it.  A fixed seed repeats one such walk where the random
//! class mixes them, which the t-test does not tell apart from a leak.
//! The expansion runs once when a key loads or is rotated in, never in a
//! handshake.
#![allow(
    clippy::arithmetic_side_effects,
    reason = "test arithmetic over bit positions and lengths, each far below its type's limit"
)]

use std::hint::black_box;

use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use curve25519_dalek::scalar::{Scalar, clamp_integer};
use dcroxide_testutil::ct::{
    KnownReport, PLACEBO, by_class, clear_eight, distinct, plus, random_bytes, set_bit,
    time_inputs, time_target, times, with_hedge,
};
use dcroxide_testutil::{SplitMix64, unhex};
use rustls::crypto::hmac::Hmac;
use rustls::{NamedGroup, SignatureScheme};

use crate::aead::{self, RecordAead};
use crate::hmac::{HMAC_SHA256, HMAC_SHA384};
use crate::kx::exchange_with;
use crate::sign::timing;

/// P-256 signing by the nonce's known report (the module's notes), which
/// that target hands the harness ([`known_report`]).  The architecture is
/// that of both x86_64 legs, which run the same P-256 code.  The pattern
/// was measured on the x86_64 leg, on AMD EPYC 7763 runners: the classes
/// whose basepoint walk adds the identity to the identity most often, 1,
/// 2, 0xff and 2^64 - 1, were about 15 ns an operation quicker than the
/// random class, about 0.27 ns for each such addition, in a 10 s and a
/// 60 s run alike.  The bound is more than twice the largest difference
/// measured, 17.8 ns, of 14 to 18.  A secret-dependent path in the walk,
/// such as a skipped addition, would change each of those classes' time
/// by many complete additions of hundreds of cycles each, far beyond it,
/// and a class slower than the random class fails whatever its
/// difference.  What the bound gives up is a quicker path of under 40 ns
/// a signature in this target on x86_64, a cycle or so for each window of
/// the walk.
const P256_SIGNING_BY_NONCE_KNOWN: KnownReport = KnownReport {
    arch: "x86_64",
    bound_nanos: 40,
};

/// The known report of ECDSA signing on `curve` by the nonce:
/// [`P256_SIGNING_BY_NONCE_KNOWN`] on P-256, and none on P-384 and P-521.
/// No other target names one.
fn known_report(curve: &Nist) -> Option<KnownReport> {
    (curve.group == NamedGroup::secp256r1).then_some(P256_SIGNING_BY_NONCE_KNOWN)
}

/// A NIST curve as the targets take it.
struct Nist {
    /// The ECDSA scheme its keys sign with.
    scheme: SignatureScheme,
    /// Its key exchange group.
    group: NamedGroup,
    /// Its order, big-endian at the field's length.
    order: &'static str,
}

const P256: Nist = Nist {
    scheme: SignatureScheme::ECDSA_NISTP256_SHA256,
    group: NamedGroup::secp256r1,
    order: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
};

const P384: Nist = Nist {
    scheme: SignatureScheme::ECDSA_NISTP384_SHA384,
    group: NamedGroup::secp384r1,
    order: "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf\
            581a0db248b0a77aecec196accc52973",
};

const P521: Nist = Nist {
    scheme: SignatureScheme::ECDSA_NISTP521_SHA512,
    group: NamedGroup::secp521r1,
    order: "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
            fffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
};

/// The fixed classes of a NIST curve's scalars, for the curve of order
/// `order`, big-endian at the field's length: 1, 2, 0xff, 2^64 - 1 (every
/// limb but the lowest zero), the top bit alone (the largest power of two
/// below n), n - 1 and n - 2; n - 1 with its bottom half zero, and with its
/// top half zero; eight set bits, spread, and n - 1 with eight of its set
/// bits cleared, spread; and n - 1 with every 4-bit window but the top one
/// zero.  A class whose value an earlier one has is left out: on P-521 the
/// top window holds the order's one top bit, so it is the top bit alone.
fn nist_classes(order: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let len = order.len();
    let bits = 8 * len - order[0].leading_zeros() as usize;
    let zero = vec![0; len];
    let n_minus_1 = plus(order, -1);
    let mut ones_64 = zero.clone();
    ones_64[len - 8..].fill(0xff);
    let mut top_bit = zero.clone();
    set_bit(&mut top_bit, bits - 1, true);
    let mut bottom_zero = n_minus_1.clone();
    bottom_zero[len - len / 2..].fill(0);
    let mut top_zero = n_minus_1.clone();
    top_zero[..len - len / 2].fill(0);
    let mut low_weight = zero.clone();
    for i in 0..8 {
        set_bit(&mut low_weight, i * ((bits - 1) / 8), true);
    }
    let mut windows = n_minus_1.clone();
    for at in 0..4 * ((bits - 1) / 4) {
        set_bit(&mut windows, at, false);
    }
    distinct(vec![
        ("1", plus(&zero, 1)),
        ("2", plus(&zero, 2)),
        ("0xff", plus(&zero, 0xff)),
        ("2^64 - 1", ones_64),
        ("top bit alone", top_bit),
        ("n - 1", n_minus_1.clone()),
        ("n - 2", plus(order, -2)),
        ("bottom half zero", bottom_zero),
        ("top half zero", top_zero),
        ("low weight", low_weight),
        ("high weight", clear_eight(&n_minus_1)),
        ("top window alone", windows),
    ])
}

/// The classes `curve`'s targets time: [`nist_classes`], and on P-256 and
/// P-384 two more after them that check the check (the module's notes), a
/// placebo ([`PLACEBO`]) and n - 2 again, under a name of its own.
fn nist_target_classes(curve: &Nist) -> Vec<(&'static str, Vec<u8>)> {
    let order = unhex(curve.order);
    let mut classes = nist_classes(&order);
    if [NamedGroup::secp256r1, NamedGroup::secp384r1].contains(&curve.group) {
        classes.push((PLACEBO, Vec::new()));
        classes.push(("n - 2 again", plus(&order, -2)));
    }
    classes
}

/// A random scalar of the curve of order `order`: the field's length in
/// bytes, the first masked to the order's bit length, drawn until it is in
/// `[1, n)`.
fn random_scalar(order: &[u8], rng: &mut SplitMix64) -> Vec<u8> {
    let mut scalar = vec![0; order.len()];
    loop {
        rng.fill(&mut scalar);
        scalar[0] &= u8::MAX >> order[0].leading_zeros();
        if scalar.iter().any(|&byte| byte != 0) && scalar.as_slice() < order {
            return scalar;
        }
    }
}

/// The scalar the targets fix where the scalar is not what they vary: 0x5a
/// repeated, masked as [`random_scalar`] masks a draw.
fn fixed_scalar(order: &[u8]) -> Vec<u8> {
    let mut scalar = vec![0x5a; order.len()];
    scalar[0] &= u8::MAX >> order[0].leading_zeros();
    scalar
}

/// A 32-byte little-endian value from its big-endian bytes.
fn little_endian(big_endian: &[u8]) -> Vec<u8> {
    big_endian.iter().rev().copied().collect()
}

/// L, the order of Curve25519's prime subgroup, big-endian.
fn curve25519_order() -> Vec<u8> {
    plus(&little_endian(&(-Scalar::ONE).to_bytes()), 1)
}

/// The clamped scalars of low and high weight, big-endian: eight bits
/// set, 2^254 and seven more spread over bits 3 to 253, and 2^255 - 8
/// with eight bits cleared, spread over the same bits.
fn clamped_weights() -> [Vec<u8>; 2] {
    let mut low = vec![0; 32];
    set_bit(&mut low, 254, true);
    for i in 0..7 {
        set_bit(&mut low, 3 + 36 * i, true);
    }
    let mut high = vec![0; 32];
    for at in 3..255 {
        set_bit(&mut high, at, true);
    }
    for i in 0..8 {
        set_bit(&mut high, 3 + 31 * i, false);
    }
    [low, high]
}

/// The fixed classes of an Ed25519 expanded scalar, little-endian, each
/// within the clamp (bits 0 to 2 clear, bit 254 set, bit 255 clear): the
/// least, 2^254, the next, 2^254 + 8, and the greatest, 2^255 - 8; low
/// and high weight (eight bits set, eight cleared); and 6L + 2 and 5L - 1,
/// whose residues mod L, what the key's arithmetic sees, are 2 and L - 1.
fn ed25519_scalar_classes() -> Vec<(&'static str, Vec<u8>)> {
    let mut least = vec![0; 32];
    set_bit(&mut least, 254, true);
    let mut next = least.clone();
    set_bit(&mut next, 3, true);
    let mut greatest = vec![0; 32];
    for at in 3..255 {
        set_bit(&mut greatest, at, true);
    }
    let [low, high] = clamped_weights();
    let order = curve25519_order();
    [
        ("2^254", least),
        ("2^254 + 8", next),
        ("2^255 - 8", greatest),
        ("low weight", low),
        ("high weight", high),
        ("6L + 2, residue 2", plus(&times(&order, 6), 2)),
        ("5L - 1, residue L - 1", plus(&times(&order, 5), -1)),
    ]
    .into_iter()
    .map(|(name, value)| (name, little_endian(&value)))
    .collect()
}

/// The fixed classes of an Ed25519 nonce, little-endian and below L: 0, 1
/// and L - 1, eight set bits spread below 2^252, and L - 1 with eight of
/// its set bits cleared.
fn ed25519_nonce_classes() -> Vec<(&'static str, Vec<u8>)> {
    let zero = vec![0; 32];
    let l_minus_1 = plus(&curve25519_order(), -1);
    let mut low = zero.clone();
    for i in 0..8 {
        set_bit(&mut low, 31 * i, true);
    }
    [
        ("0", zero.clone()),
        ("1", plus(&zero, 1)),
        ("L - 1", l_minus_1.clone()),
        ("low weight", low),
        ("high weight", clear_eight(&l_minus_1)),
    ]
    .into_iter()
    .map(|(name, value)| (name, little_endian(&value)))
    .collect()
}

/// The fixed classes of an X25519 secret, as drawn: all zeros and all
/// ones, which clamp to 2^254 and 2^255 - 8, and the clamped scalars of
/// low and high weight (eight bits set, eight cleared).
fn x25519_classes() -> Vec<(&'static str, Vec<u8>)> {
    let [low, high] = clamped_weights();
    vec![
        ("all zeros", vec![0; 32]),
        ("all ones", vec![0xff; 32]),
        ("low weight", little_endian(&low)),
        ("high weight", little_endian(&high)),
    ]
}

/// The fixed classes of an AEAD key of `len` bytes: all zeros, all ones,
/// and 0x55 and 0xaa in turn.
fn aead_key_classes(len: usize) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("all zeros", vec![0; len]),
        ("all ones", vec![0xff; len]),
        ("0x55 and 0xaa", [0x55, 0xaa].repeat(len / 2)),
    ]
}

/// The fixed classes of an HMAC key of `len` bytes: all zeros, all ones,
/// and one bit set, the first.
fn hmac_key_classes(len: usize) -> Vec<(&'static str, Vec<u8>)> {
    let mut one_bit = vec![0; len];
    one_bit[0] = 0x80;
    vec![
        ("all zeros", vec![0; len]),
        ("all ones", vec![0xff; len]),
        ("one bit set", one_bit),
    ]
}

/// The fixed classes of a bad tag for the right one, `tag`: wrong in its
/// first byte, and wrong in its last.
fn bad_tag_classes(tag: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let mut first = tag.to_vec();
    first[0] ^= 1;
    let mut last = tag.to_vec();
    last[tag.len() - 1] ^= 1;
    vec![("wrong first byte", first), ("wrong last byte", last)]
}

/// A random Ed25519 expanded scalar: 32 random bytes, clamped, as a seed's
/// hash is.
fn random_clamped(rng: &mut SplitMix64) -> Vec<u8> {
    let mut scalar = [0; 32];
    rng.fill(&mut scalar);
    clamp_integer(scalar).to_vec()
}

/// A random Ed25519 nonce: 64 random bytes reduced mod L, as RFC 8032
/// reduces SHA-512's.
fn random_nonce(rng: &mut SplitMix64) -> Vec<u8> {
    let mut wide = [0; 64];
    rng.fill(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide).to_bytes().to_vec()
}

/// The Ed25519 nonce whose canonical encoding is `r`, which is below L.
fn nonce_scalar(r: [u8; 32]) -> Scalar {
    Option::from(Scalar::from_canonical_bytes(r)).expect("a nonce below L")
}

/// A random tag other than `tag`.
fn wrong_tag(tag: &[u8], rng: &mut SplitMix64) -> Vec<u8> {
    loop {
        let wrong = random_bytes(rng, tag.len());
        if wrong != tag {
            return wrong;
        }
    }
}

/// The positive control's random class: 64 random bytes whose first
/// differs from [`REFERENCE`]'s.
fn control_input(rng: &mut SplitMix64) -> Vec<u8> {
    let mut bytes = random_bytes(rng, REFERENCE.len());
    bytes[0] = !REFERENCE[0];
    bytes
}

/// The message the signing targets sign.
const MESSAGE: &[u8] = b"a TLS 1.3 CertificateVerify's content";

/// The Ed25519 prefix the targets fix.
const PREFIX: [u8; 32] = [0x3c; 32];

/// The record the AEAD targets seal: 64 bytes of content.
const RECORD: [u8; 64] = [0x17; 64];

/// The record's nonce.
const NONCE: [u8; 12] = [0x24; 12];

/// The record's additional data: a TLS 1.3 record's header, for the
/// content and the tag, 80 bytes.
const AAD: [u8; 5] = [0x17, 0x03, 0x03, 0x00, 0x50];

/// The data the HMAC targets authenticate.
const HMAC_MESSAGE: &[u8] = b"tls13 derived";

/// What the positive control compares with.
const REFERENCE: [u8; 64] = [0x5a; 64];

/// ECDSA signing on `curve` by the key's extremes, with the message fixed
/// and a hedge drawn for each sample ([`by_key_inputs`]), so that RFC
/// 6979's nonce follows the key and the hedge as it does in the handshake
/// signer, and a fixed class fixes the key alone.  The timed region ends at
/// the signature as r and s, before the signer's DER encoding.
fn ecdsa_signing_by_key(target: &str, curve: &Nist) {
    let classes = nist_target_classes(curve);
    time_inputs(
        target,
        &classes,
        by_key_inputs(curve, &classes),
        sign_by_key,
    )
    .assert_constant_time();
}

/// The inputs of signing on `curve` by the key, of the fixed classes
/// `classes`: the key made from the class's scalar ([`by_class`]), and a
/// hedge of the field's length drawn for it in the building, outside the
/// timed region, whatever the class ([`with_hedge`]).
fn by_key_inputs<'a>(
    curve: &'a Nist,
    classes: &'a [(&'static str, Vec<u8>)],
) -> impl FnMut(Option<usize>, &mut SplitMix64) -> (timing::Ecdsa, Vec<u8>) + 'a {
    let order = unhex(curve.order);
    let len = order.len();
    with_hedge(
        by_class(
            classes,
            move |rng| random_scalar(&order, rng),
            |scalar| timing::Ecdsa::new(curve.scheme, scalar).expect("a scalar in [1, n)"),
        ),
        len,
    )
}

/// Signing by the key's timed operation: the input's key signs [`MESSAGE`]
/// with the input's hedge.
fn sign_by_key(input: &mut (timing::Ecdsa, Vec<u8>)) -> Vec<u8> {
    let (key, hedge) = input;
    key.sign_hedged(MESSAGE, hedge)
}

/// ECDSA signing on `curve` by the nonce's extremes, with the key fixed:
/// the nonce reaches `k.invert()` and `mul_by_generator`
/// (`ecdsa-0.17.0/src/hazmat.rs:64-67`), and RFC 6979's nonce never lands
/// on an extreme of its own.  The timed region ends at the signature as r
/// and s, with no DER encoding.  On P-256 a failure that keeps to the
/// known report passes ([`known_report`]).
fn ecdsa_signing_by_nonce(target: &str, curve: &Nist) {
    let order = unhex(curve.order);
    let key = timing::Ecdsa::new(curve.scheme, &fixed_scalar(&order)).expect("the fixed key");
    time_target(
        target,
        &nist_target_classes(curve),
        |rng| random_scalar(&order, rng),
        <[u8]>::to_vec,
        |nonce| key.sign_with_nonce(nonce, MESSAGE),
    )
    .with_known_report(known_report(curve))
    .assert_constant_time();
}

/// The exchange on `group` completed by its secret's extremes, `classes`,
/// with the peer's share fixed; `draw` draws the random class's secret.
/// `complete` consumes its exchange, as it does in the provider, so the
/// input holds it in an `Option` for the operation to take.
fn exchange_complete(
    target: &str,
    group: NamedGroup,
    classes: &[(&'static str, Vec<u8>)],
    peer_secret: &[u8],
    draw: impl FnMut(&mut SplitMix64) -> Vec<u8>,
) {
    let peer = exchange_with(group, peer_secret)
        .expect("the peer's secret")
        .pub_key()
        .to_vec();
    time_target(
        target,
        classes,
        draw,
        |secret| Some(exchange_with(group, secret).expect("a secret the group takes")),
        |exchange| {
            exchange
                .take()
                .expect("each exchange completed once")
                .complete(&peer)
        },
    )
    .assert_constant_time();
}

/// The step `start` runs on `group` once its secret is drawn: the exchange
/// made from the secret, whose public key that computes, by the secret's
/// extremes, `classes`; `draw` draws the random class's.
fn exchange_public(
    target: &str,
    group: NamedGroup,
    classes: &[(&'static str, Vec<u8>)],
    draw: impl FnMut(&mut SplitMix64) -> Vec<u8>,
) {
    time_target(target, classes, draw, <[u8]>::to_vec, |secret| {
        exchange_with(group, secret)
    })
    .assert_constant_time();
}

/// Sealing a record with the AEAD `A` by the key's extremes, with a cipher
/// built ahead, as the provider seals every record with the one it keyed
/// for the traffic key.
fn aead_seal<A: RecordAead>(target: &str) {
    let len = A::key_size();
    time_target(
        target,
        &aead_key_classes(len),
        |rng| random_bytes(rng, len),
        |key| A::new_from_slice(key).expect("a key of the AEAD's length"),
        |aead| {
            let mut record = RECORD;
            let tag = aead::seal(aead, NONCE, &AAD, &mut record);
            (record, tag)
        },
    )
    .assert_constant_time();
}

/// Keying the AEAD `A` by the key's extremes, as the provider keys one for
/// each traffic key: for AES-GCM, AES's key schedule and GHASH's key, the
/// encryption of zeros, which the seal targets make ahead.
fn aead_key<A: RecordAead>(target: &str) {
    let len = A::key_size();
    time_target(
        target,
        &aead_key_classes(len),
        |rng| random_bytes(rng, len),
        <[u8]>::to_vec,
        |key| A::new_from_slice(key),
    )
    .assert_constant_time();
}

/// Opening a record with the AEAD `A` by where its tag is wrong: in its
/// first byte or its last, against wrong at random.
fn aead_open_bad_tag<A: RecordAead>(target: &str) {
    let aead = A::new_from_slice(&vec![0x5a; A::key_size()]).expect("a key of the AEAD's length");
    let mut record = RECORD;
    let tag = aead::seal(&aead, NONCE, &AAD, &mut record).expect("sealed");
    time_target(
        target,
        &bad_tag_classes(&tag),
        |rng| wrong_tag(&tag, rng),
        |wrong| [&record[..], wrong].concat(),
        |sealed| aead::open(&aead, NONCE, &AAD, sealed),
    )
    .assert_constant_time();
}

/// Keying `hmac` and making a tag, by the key's extremes, keys of the
/// hash's length.
fn hmac_key(target: &str, hmac: &dyn Hmac) {
    let len = hmac.hash_output_len();
    time_target(
        target,
        &hmac_key_classes(len),
        |rng| random_bytes(rng, len),
        <[u8]>::to_vec,
        |key| hmac.with_key(key).sign(&[HMAC_MESSAGE]),
    )
    .assert_constant_time();
}

/// The positive control's comparison, which returns at the first byte that
/// differs and so leaks where that is.  `black_box` keeps it a byte at a
/// time, as written, where the compiler could make it a wider comparison
/// whose leak is too small to be a control.
fn leaky_eq(a: &[u8; 64], b: &[u8; 64]) -> bool {
    for (x, y) in a.iter().zip(b) {
        if black_box(*x) != black_box(*y) {
            return false;
        }
    }
    true
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn ecdsa_p256_signing_by_key() {
    ecdsa_signing_by_key("ecdsa_p256_signing_by_key", &P256);
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn ecdsa_p384_signing_by_key() {
    ecdsa_signing_by_key("ecdsa_p384_signing_by_key", &P384);
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn ecdsa_p521_signing_by_key() {
    ecdsa_signing_by_key("ecdsa_p521_signing_by_key", &P521);
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn ecdsa_p256_signing_by_nonce() {
    ecdsa_signing_by_nonce("ecdsa_p256_signing_by_nonce", &P256);
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn ecdsa_p384_signing_by_nonce() {
    ecdsa_signing_by_nonce("ecdsa_p384_signing_by_nonce", &P384);
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn ecdsa_p521_signing_by_nonce() {
    ecdsa_signing_by_nonce("ecdsa_p521_signing_by_nonce", &P521);
}

/// [`exchange_complete`] on `curve`, by the scalar's extremes.
fn nist_complete(target: &str, curve: &Nist) {
    let order = unhex(curve.order);
    exchange_complete(
        target,
        curve.group,
        &nist_target_classes(curve),
        &fixed_scalar(&order),
        |rng| random_scalar(&order, rng),
    );
}

/// [`exchange_public`] on `curve`, by the scalar's extremes.
fn nist_public(target: &str, curve: &Nist) {
    let order = unhex(curve.order);
    exchange_public(target, curve.group, &nist_target_classes(curve), |rng| {
        random_scalar(&order, rng)
    });
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn ecdh_p256_complete() {
    nist_complete("ecdh_p256_complete", &P256);
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn ecdh_p384_complete() {
    nist_complete("ecdh_p384_complete", &P384);
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn ecdh_p521_complete() {
    nist_complete("ecdh_p521_complete", &P521);
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn ecdh_p256_public_key() {
    nist_public("ecdh_p256_public_key", &P256);
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn ecdh_p384_public_key() {
    nist_public("ecdh_p384_public_key", &P384);
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn ecdh_p521_public_key() {
    nist_public("ecdh_p521_public_key", &P521);
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn x25519_complete() {
    exchange_complete(
        "x25519_complete",
        NamedGroup::X25519,
        &x25519_classes(),
        &[0x5a; 32],
        |rng| random_bytes(rng, 32),
    );
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn x25519_public_key() {
    exchange_public(
        "x25519_public_key",
        NamedGroup::X25519,
        &x25519_classes(),
        |rng| random_bytes(rng, 32),
    );
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn ed25519_signing_by_key() {
    time_target(
        "ed25519_signing_by_key",
        &ed25519_scalar_classes(),
        random_clamped,
        |scalar| timing::Ed25519::new(scalar.try_into().expect("32 bytes"), PREFIX),
        |key| key.sign(MESSAGE),
    )
    .assert_constant_time();
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn ed25519_signing_by_nonce() {
    let key = timing::Ed25519::new(clamp_integer([0x5a; 32]), PREFIX);
    time_target(
        "ed25519_signing_by_nonce",
        &ed25519_nonce_classes(),
        random_nonce,
        |r| nonce_scalar(r.try_into().expect("32 bytes")),
        |r| key.sign_with_nonce(r, MESSAGE),
    )
    .assert_constant_time();
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn aes_128_gcm_seal() {
    aead_seal::<Aes128Gcm>("aes_128_gcm_seal");
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn aes_256_gcm_seal() {
    aead_seal::<Aes256Gcm>("aes_256_gcm_seal");
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn chacha20_poly1305_seal() {
    aead_seal::<ChaCha20Poly1305>("chacha20_poly1305_seal");
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn aes_128_gcm_key() {
    aead_key::<Aes128Gcm>("aes_128_gcm_key");
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn aes_256_gcm_key() {
    aead_key::<Aes256Gcm>("aes_256_gcm_key");
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn aes_128_gcm_open_bad_tag() {
    aead_open_bad_tag::<Aes128Gcm>("aes_128_gcm_open_bad_tag");
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn aes_256_gcm_open_bad_tag() {
    aead_open_bad_tag::<Aes256Gcm>("aes_256_gcm_open_bad_tag");
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn chacha20_poly1305_open_bad_tag() {
    aead_open_bad_tag::<ChaCha20Poly1305>("chacha20_poly1305_open_bad_tag");
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn hmac_sha256_key() {
    hmac_key("hmac_sha256_key", &HMAC_SHA256);
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn hmac_sha384_key() {
    hmac_key("hmac_sha384_key", &HMAC_SHA384);
}

/// The positive control: the early-exit comparison with all 64 bytes
/// equal, against inputs that differ in their first byte.
#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn positive_control() {
    time_target(
        "positive_control",
        &[("equal", REFERENCE.to_vec())],
        control_input,
        |bytes| <[u8; 64]>::try_from(bytes).expect("64 bytes"),
        |bytes| leaky_eq(bytes, &REFERENCE),
    )
    .assert_leak_found();
}

mod tests {
    use ::hmac::{KeyInit, Mac};
    use curve25519_dalek::edwards::EdwardsPoint;
    use curve25519_dalek::montgomery::MontgomeryPoint;
    use dcroxide_testutil::ct::bit;
    use ecdsa::signature::Verifier;
    use rustls::Error;
    use sha2::{Digest, Sha256, Sha384, Sha512};

    use super::*;
    use crate::verify;

    /// Signing on P-256 by the nonce, and only it, hands the harness a
    /// known report, built for x86_64 and quicker by 40 ns an operation or
    /// less, as ADR-0015's note of 2026-11-15 decided; signing on P-384
    /// and P-521 by the nonce names none.
    #[test]
    fn only_p256_signing_by_the_nonce_names_a_known_report() {
        assert_eq!(
            known_report(&P256),
            Some(KnownReport {
                arch: "x86_64",
                bound_nanos: 40,
            })
        );
        assert_eq!(known_report(&P384), None);
        assert_eq!(known_report(&P521), None);
    }

    /// `value`'s set bits.
    fn weight(value: &[u8]) -> u32 {
        value.iter().map(|byte| byte.count_ones()).sum()
    }

    /// The value of the class `name` among `classes`.
    fn class(classes: &[(&'static str, Vec<u8>)], name: &str) -> Vec<u8> {
        classes
            .iter()
            .find(|(class, _)| *class == name)
            .unwrap_or_else(|| panic!("no class {name}"))
            .1
            .clone()
    }

    /// No two classes share a name or a value.
    fn assert_distinct(classes: &[(&'static str, Vec<u8>)]) {
        for (i, (name, value)) in classes.iter().enumerate() {
            for (other, other_value) in &classes[..i] {
                assert!(name != other && value != other_value, "{name} and {other}");
            }
        }
    }

    /// Each NIST class is the value it is named for, in `[1, n)` by the
    /// curve's own check, and no two are alike; on P-521 the top window is
    /// the top bit, so it has eleven.  The orders are right: n - 1 is a
    /// scalar and n is not.
    #[test]
    fn the_nist_classes_are_the_extremes_they_are_named_for() {
        for (curve, count) in [(&P256, 12), (&P384, 12), (&P521, 11)] {
            let n = unhex(curve.order);
            let len = n.len();
            let bits = 8 * len - n[0].leading_zeros() as usize;
            let n_minus_1 = plus(&n, -1);
            let classes = nist_classes(&n);
            let value = |name| class(&classes, name);
            let below = |value: &[u8], at: usize| (at..8 * len).all(|i| !bit(value, i));
            assert_eq!(classes.len(), count, "{:?}", curve.group);
            assert_distinct(&classes);
            let name = format!("{:?}", curve.group);
            for (byte, class) in [(1, "1"), (2, "2"), (0xff, "0xff")] {
                let mut want = vec![0; len];
                want[len - 1] = byte;
                assert_eq!(value(class), want, "{name}");
            }
            let mut want = vec![0; len];
            want[len - 8..].fill(0xff);
            assert_eq!(value("2^64 - 1"), want, "{name}");
            let top = value("top bit alone");
            assert!(weight(&top) == 1 && bit(&top, bits - 1), "{name}");
            assert_eq!(plus(&value("n - 1"), 1), n, "{name}");
            assert_eq!(plus(&value("n - 2"), 2), n, "{name}");
            let half = len - len / 2;
            let bottom_zero = value("bottom half zero");
            assert_eq!(bottom_zero[..half], n_minus_1[..half], "{name}");
            assert!(bottom_zero[half..].iter().all(|&b| b == 0), "{name}");
            let top_zero = value("top half zero");
            assert!(top_zero[..half].iter().all(|&b| b == 0), "{name}");
            assert_eq!(top_zero[half..], n_minus_1[half..], "{name}");
            let low = value("low weight");
            assert!(weight(&low) == 8 && below(&low, bits - 1), "{name}");
            let high = value("high weight");
            assert_eq!(weight(&high), weight(&n_minus_1) - 8, "{name}");
            assert!(
                high.iter().zip(&n_minus_1).all(|(h, m)| h & !m == 0),
                "{name}"
            );
            let window = 4 * ((bits - 1) / 4);
            if count == 12 {
                let windows = value("top window alone");
                assert!((0..window).all(|i| !bit(&windows, i)), "{name}");
                assert!(
                    (window..8 * len).all(|i| bit(&windows, i) == bit(&n_minus_1, i)),
                    "{name}"
                );
                assert_ne!(windows, top, "{name}");
            } else {
                assert!(below(&n_minus_1, window + 1) && bit(&n_minus_1, window));
            }
            for (class, value) in classes.iter().chain([&("fixed", fixed_scalar(&n))]) {
                assert!(
                    exchange_with(curve.group, value).is_some(),
                    "{name}: {class} in [1, n)"
                );
            }
            assert!(exchange_with(curve.group, &n).is_none(), "{name}: n");
        }
    }

    /// P-256's and P-384's targets time [`nist_classes`] and after them a
    /// placebo, of no bytes, and n - 2 again, n - 2's value under a name of
    /// its own; P-521's time [`nist_classes`] alone.  Every name is its
    /// own.
    #[test]
    fn p256s_and_p384s_targets_add_a_placebo_and_n_minus_2_again() {
        for curve in [&P256, &P384, &P521] {
            let n = unhex(curve.order);
            let extremes = nist_classes(&n);
            let classes = nist_target_classes(curve);
            assert_eq!(classes[..extremes.len()], extremes, "{:?}", curve.group);
            let added = &classes[extremes.len()..];
            if curve.group != NamedGroup::secp521r1 {
                let n_minus_2 = class(&classes, "n - 2");
                assert_eq!(n_minus_2, plus(&n, -2));
                assert_eq!(added, [(PLACEBO, Vec::new()), ("n - 2 again", n_minus_2)]);
            } else {
                assert!(added.is_empty(), "{:?}: {added:?}", curve.group);
            }
            for (i, (name, _)) in classes.iter().enumerate() {
                assert!(
                    classes[..i].iter().all(|(other, _)| other != name),
                    "{:?}: {name}",
                    curve.group
                );
            }
        }
    }

    /// Whether `signature` of `message`, r and s at the field's length
    /// each as the timing hooks give it, verifies under the uncompressed
    /// point `public` on the curve of `scheme`: in DER by the provider's
    /// verifier for P-256 and P-384, and by the `p521` crate's for P-521,
    /// which the provider does not verify.  The signature has exactly the
    /// field's length twice, and the curve crate reads it as r and s.
    fn ecdsa_verifies(scheme: SignatureScheme, public: &[u8], signature: &[u8]) -> bool {
        match scheme {
            SignatureScheme::ECDSA_NISTP256_SHA256 => {
                let der = p256::ecdsa::Signature::from_slice(signature)
                    .expect("r and s at 32 bytes each")
                    .to_der();
                verify::ECDSA_P256_SHA256
                    .verify_signature(public, MESSAGE, der.as_bytes())
                    .is_ok()
            }
            SignatureScheme::ECDSA_NISTP384_SHA384 => {
                let der = p384::ecdsa::Signature::from_slice(signature)
                    .expect("r and s at 48 bytes each")
                    .to_der();
                verify::ECDSA_P384_SHA384
                    .verify_signature(public, MESSAGE, der.as_bytes())
                    .is_ok()
            }
            SignatureScheme::ECDSA_NISTP521_SHA512 => {
                let key = p521::ecdsa::VerifyingKey::from_sec1_bytes(public).expect("a point");
                let signature = p521::ecdsa::Signature::from_slice(signature)
                    .expect("r and s at 66 bytes each");
                key.verify(MESSAGE, &signature).is_ok()
            }
            other => panic!("{other:?}"),
        }
    }

    /// The timing check's ECDSA key takes the scalars in `[1, n)` at the
    /// field's length on the three ECDSA schemes, and nothing else.
    #[test]
    fn the_ecdsa_hook_takes_only_scalars_in_range() {
        for curve in [&P256, &P384, &P521] {
            let n = unhex(curve.order);
            let n_minus_1 = plus(&n, -1);
            let takes = |scalar: &[u8]| timing::Ecdsa::new(curve.scheme, scalar).is_some();
            assert!(takes(&n_minus_1), "{:?}", curve.scheme);
            for refused in [vec![0; n.len()], n.clone(), n_minus_1[1..].to_vec()] {
                assert!(!takes(&refused), "{:?}: {refused:02x?}", curve.scheme);
            }
        }
        assert!(timing::Ecdsa::new(SignatureScheme::ED25519, &[1; 32]).is_none());
    }

    /// Each key class reaches the signer: the key made from it has that
    /// scalar's public point, the one the key exchange computes for it, and
    /// its hedged signature verifies under it.  The hedge is the one given,
    /// not a draw: a signature with it is made again byte for byte, and
    /// one with another hedge differs.
    #[test]
    fn the_ecdsa_key_classes_are_the_signing_keys() {
        for curve in [&P256, &P384, &P521] {
            let n = unhex(curve.order);
            let hedge = vec![0xa5; n.len()];
            let key = timing::Ecdsa::new(curve.scheme, &fixed_scalar(&n)).expect("the key");
            let signature = key.sign_hedged(MESSAGE, &hedge);
            assert_eq!(
                key.sign_hedged(MESSAGE, &hedge),
                signature,
                "{:?}",
                curve.scheme
            );
            let other = key.sign_hedged(MESSAGE, &vec![0x5b; n.len()]);
            assert_ne!(other, signature, "{:?}", curve.scheme);
            for (name, scalar) in nist_classes(&n) {
                let key = timing::Ecdsa::new(curve.scheme, &scalar).expect("a scalar in [1, n)");
                let public = exchange_with(curve.group, &scalar).expect("a scalar");
                assert_eq!(key.public(), public.pub_key(), "{:?}: {name}", curve.scheme);
                let signature = key.sign_hedged(MESSAGE, &hedge);
                assert!(
                    ecdsa_verifies(curve.scheme, &key.public(), &signature),
                    "{:?}: {name}",
                    curve.scheme
                );
            }
        }
    }

    /// Signing by the key fixes the key alone: a fixed class's inputs one
    /// after another hold its key, each signs with its own hedge, and their
    /// signatures verify under that key and differ in r, so RFC 6979's
    /// nonce does not repeat with the class.
    #[test]
    fn signing_by_the_key_fixes_the_key_alone() {
        for curve in [&P256, &P384, &P521] {
            let name = format!("{:?}", curve.scheme);
            let classes = nist_target_classes(curve);
            let n_minus_2 = classes
                .iter()
                .position(|(class, _)| *class == "n - 2")
                .expect("n - 2");
            let public = exchange_with(curve.group, &classes[n_minus_2].1)
                .expect("a scalar")
                .pub_key()
                .to_vec();
            let mut build = by_key_inputs(curve, &classes);
            let len = unhex(curve.order).len();
            let mut rng = SplitMix64(0x6279_206b_6579_2121);
            let mut rs: Vec<Vec<u8>> = Vec::new();
            for _ in 0..4 {
                let mut input = build(Some(n_minus_2), &mut rng);
                assert_eq!(input.0.public(), public, "{name}");
                let signature = sign_by_key(&mut input);
                let (key, hedge) = &input;
                assert_eq!(signature, key.sign_hedged(MESSAGE, hedge), "{name}");
                assert!(ecdsa_verifies(curve.scheme, &public, &signature), "{name}");
                let r = signature[..len].to_vec();
                assert!(!rs.contains(&r), "{name}: r repeats");
                rs.push(r);
            }
        }
    }

    /// `a` minus `b`, big-endian at their length, `a` at least `b`.
    fn minus(a: &[u8], b: &[u8]) -> Vec<u8> {
        let mut out = vec![0; a.len()];
        let mut borrow = 0;
        for ((out, &a), &b) in out.iter_mut().zip(a).zip(b).rev() {
            let difference = i16::from(a) - i16::from(b) - borrow;
            *out = difference.rem_euclid(256) as u8;
            borrow = i16::from(difference < 0);
        }
        assert_eq!(borrow, 0);
        out
    }

    /// Each nonce class reaches the signature: its r, the signature's first
    /// half at the field's length, is the x-coordinate of the nonce times
    /// the generator, reduced mod n, and the signature verifies under the
    /// fixed key.
    #[test]
    fn the_ecdsa_nonce_classes_reach_r() {
        for curve in [&P256, &P384, &P521] {
            let n = unhex(curve.order);
            let len = n.len();
            let key = timing::Ecdsa::new(curve.scheme, &fixed_scalar(&n)).expect("the key");
            for (name, nonce) in nist_classes(&n) {
                let signature = key
                    .sign_with_nonce(&nonce, MESSAGE)
                    .unwrap_or_else(|| panic!("{:?}: {name} signs", curve.scheme));
                let point = exchange_with(curve.group, &nonce).expect("a scalar");
                let x = point.pub_key()[1..1 + len].to_vec();
                let want = if x.as_slice() < n.as_slice() {
                    x
                } else {
                    minus(&x, &n)
                };
                assert_eq!(signature.len(), 2 * len, "{:?}: {name}", curve.scheme);
                assert_eq!(signature[..len], want, "{:?}: {name}", curve.scheme);
                assert!(
                    ecdsa_verifies(curve.scheme, &key.public(), &signature),
                    "{:?}: {name}",
                    curve.scheme
                );
            }
        }
    }

    /// Each NIST class reaches both steps of the exchange: the secret it
    /// shares with a fixed peer, from its side, is the one the peer
    /// computes from the class's public key.
    #[test]
    fn the_nist_exchange_classes_reach_both_steps() {
        for curve in [&P256, &P384, &P521] {
            let n = unhex(curve.order);
            let peer = fixed_scalar(&n);
            let peer_public = exchange_with(curve.group, &peer)
                .expect("the peer")
                .pub_key()
                .to_vec();
            for (name, secret) in nist_classes(&n) {
                let ours = exchange_with(curve.group, &secret).expect("a scalar");
                let public = ours.pub_key().to_vec();
                let ours = ours.complete(&peer_public).expect("completed");
                let theirs = exchange_with(curve.group, &peer)
                    .expect("the peer")
                    .complete(&public)
                    .expect("completed");
                assert_eq!(
                    ours.secret_bytes(),
                    theirs.secret_bytes(),
                    "{:?}: {name}",
                    curve.group
                );
            }
        }
    }

    /// Each X25519 class clamps to the value it is named for and reaches
    /// both steps: its public key is the ladder's X25519 of it and 9, and
    /// the secret it shares with a fixed peer is the peer's.
    #[test]
    fn the_x25519_classes_reach_both_steps() {
        let classes = x25519_classes();
        assert_distinct(&classes);
        let clamped = |name| clamp_integer(class(&classes, name).try_into().expect("32 bytes"));
        let mut least = [0; 32];
        least[31] = 0x40;
        let mut greatest = [0xff; 32];
        greatest[0] = 0xf8;
        greatest[31] = 0x7f;
        assert_eq!(clamped("all zeros"), least);
        assert_eq!(clamped("all ones"), greatest);
        assert_eq!(weight(&clamped("low weight")), 8);
        assert_eq!(weight(&clamped("high weight")), 252 - 8);
        let peer = [0x5a; 32];
        let peer_public = exchange_with(NamedGroup::X25519, &peer)
            .expect("32 bytes")
            .pub_key()
            .to_vec();
        let mut nine = [0; 32];
        nine[0] = 9;
        for (name, secret) in &classes {
            let ours = exchange_with(NamedGroup::X25519, secret).expect("32 bytes");
            let public = ours.pub_key().to_vec();
            let ladder =
                MontgomeryPoint(nine).mul_clamped(secret.as_slice().try_into().expect("32 bytes"));
            assert_eq!(public, ladder.to_bytes(), "{name}");
            let ours = ours.complete(&peer_public).expect("completed");
            let theirs = exchange_with(NamedGroup::X25519, &peer)
                .expect("32 bytes")
                .complete(&public)
                .expect("completed");
            assert_eq!(ours.secret_bytes(), theirs.secret_bytes(), "{name}");
        }
    }

    /// Each Ed25519 scalar class is within the clamp and the value it is
    /// named for, the two named for their residues reduce to them, and the
    /// key made from each has its residue's public key and signs, through
    /// the handshake signer's code, what that key verifies, with the nonce
    /// RFC 8032 hashes from the prefix and the message.
    #[test]
    fn the_ed25519_scalar_classes_are_clamped_extremes_that_sign() {
        let classes = ed25519_scalar_classes();
        assert_eq!(classes.len(), 7);
        assert_distinct(&classes);
        let mut least = [0; 32];
        least[31] = 0x40;
        let mut next = least;
        next[0] = 0x08;
        let mut greatest = [0xff; 32];
        greatest[0] = 0xf8;
        greatest[31] = 0x7f;
        assert_eq!(class(&classes, "2^254"), least);
        assert_eq!(class(&classes, "2^254 + 8"), next);
        assert_eq!(class(&classes, "2^255 - 8"), greatest);
        assert_eq!(weight(&class(&classes, "low weight")), 8);
        assert_eq!(weight(&class(&classes, "high weight")), 252 - 8);
        // The nonce RFC 8032 hashes from the prefix and the message, which
        // the handshake signer's signature is made with.
        let hash: [u8; 64] = Sha512::new()
            .chain_update(PREFIX)
            .chain_update(MESSAGE)
            .finalize()
            .into();
        let nonce = Scalar::from_bytes_mod_order_wide(&hash);
        for (name, scalar) in &classes {
            let scalar: [u8; 32] = scalar.as_slice().try_into().expect("32 bytes");
            assert_eq!(clamp_integer(scalar), scalar, "{name}: within the clamp");
            let residue = Scalar::from_bytes_mod_order(scalar);
            match *name {
                "6L + 2, residue 2" => assert_eq!(residue, Scalar::from(2u64)),
                "5L - 1, residue L - 1" => assert_eq!(residue, -Scalar::ONE),
                _ => {}
            }
            let key = timing::Ed25519::new(scalar, PREFIX);
            let public = EdwardsPoint::mul_base(&residue).compress().to_bytes();
            assert_eq!(key.public(), public, "{name}");
            let signature = key.sign(MESSAGE);
            assert!(
                verify::ED25519
                    .verify_signature(&public, MESSAGE, &signature)
                    .is_ok(),
                "{name}"
            );
            assert_eq!(signature, key.sign_with_nonce(&nonce, MESSAGE), "{name}");
        }
    }

    /// Each Ed25519 nonce class is below L and the value it is named for,
    /// is the scalar the target builds from it, and reaches the signature:
    /// its R is the nonce times the base point, the identity's encoding for
    /// 0, and the signature verifies.
    #[test]
    fn the_ed25519_nonce_classes_reach_r() {
        let classes = ed25519_nonce_classes();
        assert_distinct(&classes);
        let mut one = [0; 32];
        one[0] = 1;
        assert_eq!(class(&classes, "0"), [0; 32]);
        assert_eq!(class(&classes, "1"), one);
        assert_eq!(class(&classes, "L - 1"), (-Scalar::ONE).to_bytes());
        let low = class(&classes, "low weight");
        assert!(weight(&low) == 8 && low[31] < 0x10);
        let l_minus_1 = (-Scalar::ONE).to_bytes();
        let high = class(&classes, "high weight");
        assert_eq!(weight(&high), weight(&l_minus_1) - 8);
        assert!(high.iter().zip(&l_minus_1).all(|(h, m)| h & !m == 0));
        let key = timing::Ed25519::new(clamp_integer([0x5a; 32]), PREFIX);
        for (name, r) in &classes {
            let r: [u8; 32] = r.as_slice().try_into().expect("32 bytes");
            let nonce = nonce_scalar(r);
            assert_eq!(nonce.to_bytes(), r, "{name}");
            let signature = key.sign_with_nonce(&nonce, MESSAGE);
            let big_r = EdwardsPoint::mul_base(&Scalar::from_bytes_mod_order(r))
                .compress()
                .to_bytes();
            assert_eq!(signature[..32], big_r, "{name}");
            assert!(
                verify::ED25519
                    .verify_signature(&key.public(), MESSAGE, &signature)
                    .is_ok(),
                "{name}"
            );
        }
        assert_eq!(key.sign_with_nonce(&Scalar::ZERO, MESSAGE)[..32], one);
    }

    /// Each AEAD key class is the pattern it is named for and keys the
    /// cipher: a record it seals opens under a cipher made afresh from the
    /// class's key, and not under another key.
    #[test]
    fn the_aead_key_classes_key_the_cipher() {
        fn check<A: RecordAead>() {
            let len = A::key_size();
            let classes = aead_key_classes(len);
            assert_distinct(&classes);
            assert_eq!(class(&classes, "all zeros"), vec![0; len]);
            assert_eq!(class(&classes, "all ones"), vec![0xff; len]);
            let turns = class(&classes, "0x55 and 0xaa");
            assert_eq!((turns.len(), &turns[..3]), (len, &[0x55, 0xaa, 0x55][..]));
            let other = A::new_from_slice(&vec![0x5a; len]).expect("a key");
            for (name, key) in &classes {
                let mut record = RECORD;
                let aead = A::new_from_slice(key).expect("a key");
                let tag = aead::seal(&aead, NONCE, &AAD, &mut record).expect("sealed");
                let sealed = [&record[..], &tag].concat();
                let fresh = A::new_from_slice(key).expect("a key");
                assert_eq!(
                    aead::open(&fresh, NONCE, &AAD, &mut sealed.clone()),
                    Ok(RECORD.len()),
                    "{name}"
                );
                assert_eq!(
                    aead::open(&other, NONCE, &AAD, &mut sealed.clone()),
                    Err(Error::DecryptError),
                    "{name}"
                );
            }
        }
        check::<Aes128Gcm>();
        check::<Aes256Gcm>();
        check::<ChaCha20Poly1305>();
    }

    /// Each bad tag is wrong only where it is named for, and the random
    /// class's always; each is refused, the record left as it was, and
    /// the right tag opens it.
    #[test]
    fn the_bad_tags_are_wrong_where_they_are_named_for() {
        fn check<A: RecordAead>() {
            let aead = A::new_from_slice(&vec![0x5a; A::key_size()]).expect("a key");
            let mut record = RECORD;
            let tag = aead::seal(&aead, NONCE, &AAD, &mut record).expect("sealed");
            let classes = bad_tag_classes(&tag);
            let wrong_at = |wrong: &[u8]| -> Vec<usize> {
                (0..tag.len()).filter(|&i| wrong[i] != tag[i]).collect()
            };
            assert_eq!(wrong_at(&class(&classes, "wrong first byte")), [0]);
            assert_eq!(wrong_at(&class(&classes, "wrong last byte")), [15]);
            let mut rng = SplitMix64(0x7461_6773);
            let random: Vec<Vec<u8>> = (0..64).map(|_| wrong_tag(&tag, &mut rng)).collect();
            for wrong in classes.iter().map(|(_, wrong)| wrong).chain(&random) {
                let mut sealed = [&record[..], wrong].concat();
                assert_eq!(
                    aead::open(&aead, NONCE, &AAD, &mut sealed),
                    Err(Error::DecryptError)
                );
                assert_eq!(sealed[..record.len()], record);
            }
            let mut sealed = [&record[..], &tag].concat();
            assert_eq!(
                aead::open(&aead, NONCE, &AAD, &mut sealed),
                Ok(RECORD.len())
            );
            assert_eq!(sealed[..RECORD.len()], RECORD);
        }
        check::<Aes128Gcm>();
        check::<Aes256Gcm>();
        check::<ChaCha20Poly1305>();
    }

    /// Each HMAC key class is the pattern it is named for and keys the tag
    /// the provider makes, which is HMAC's under that key, computed by
    /// `hmac` directly.
    #[test]
    fn the_hmac_key_classes_key_the_tag() {
        for (hmac, len) in [(&HMAC_SHA256 as &dyn Hmac, 32), (&HMAC_SHA384, 48)] {
            let classes = hmac_key_classes(len);
            assert_distinct(&classes);
            assert_eq!(class(&classes, "all zeros"), vec![0; len]);
            assert_eq!(class(&classes, "all ones"), vec![0xff; len]);
            let one_bit = class(&classes, "one bit set");
            assert!(weight(&one_bit) == 1 && one_bit[0] == 0x80);
            for (name, key) in &classes {
                let tag = hmac.with_key(key).sign(&[HMAC_MESSAGE]);
                let want = if len == 32 {
                    ::hmac::Hmac::<Sha256>::new_from_slice(key)
                        .expect("any length")
                        .chain_update(HMAC_MESSAGE)
                        .finalize()
                        .into_bytes()
                        .to_vec()
                } else {
                    ::hmac::Hmac::<Sha384>::new_from_slice(key)
                        .expect("any length")
                        .chain_update(HMAC_MESSAGE)
                        .finalize()
                        .into_bytes()
                        .to_vec()
                };
                assert_eq!(tag.as_ref(), want, "{len}: {name}");
            }
        }
    }

    /// The control's comparison finds equal inputs equal and an input that
    /// differs in any one byte unequal; its random class's first byte is
    /// the reference's, inverted.
    #[test]
    fn the_control_compares_byte_by_byte() {
        assert!(leaky_eq(&REFERENCE, &REFERENCE));
        for at in 0..REFERENCE.len() {
            let mut other = REFERENCE;
            other[at] ^= 0x10;
            assert!(!leaky_eq(&other, &REFERENCE), "byte {at}");
        }
        let mut rng = SplitMix64(0x636f_6e74_726f_6c21);
        for _ in 0..100 {
            let input = control_input(&mut rng);
            assert_eq!(input[0], !REFERENCE[0]);
            assert!(!leaky_eq(&input.try_into().expect("64 bytes"), &REFERENCE));
        }
    }

    /// The random classes' draws: NIST scalars in `[1, n)`, P-521's first
    /// byte within the order's one bit; Ed25519 scalars within the clamp
    /// and nonces below L.
    #[test]
    fn the_random_classes_are_drawn_in_range() {
        let mut rng = SplitMix64(0x7261_6e64_6f6d_2121);
        for curve in [&P256, &P384, &P521] {
            let n = unhex(curve.order);
            for _ in 0..200 {
                let scalar = random_scalar(&n, &mut rng);
                assert_eq!(scalar.len(), n.len());
                assert!(scalar.iter().any(|&b| b != 0) && scalar < n);
                assert!(scalar[0] <= n[0]);
            }
        }
        for _ in 0..200 {
            let scalar: [u8; 32] = random_clamped(&mut rng).try_into().expect("32 bytes");
            assert_eq!(clamp_integer(scalar), scalar);
            let nonce: [u8; 32] = random_nonce(&mut rng).try_into().expect("32 bytes");
            assert!(bool::from(Scalar::from_canonical_bytes(nonce).is_some()));
        }
    }
}
