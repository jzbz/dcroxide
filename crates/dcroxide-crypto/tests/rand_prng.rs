// SPDX-License-Identifier: ISC
//! `Prng` rekeys before its block counter can run out, and splits a
//! budget-crossing read exactly where dcrd splits it.
//!
//! What is not pinned here: the `(2^32 - 1) * 64` byte cap itself,
//! which no test can reach in bounded time. It was confirmed out of
//! band by seeking a bare `chacha20::ChaCha20` near the end of its
//! counter and drawing until `try_apply_keystream` returned
//! `StreamCipherError`, at byte 274,877,906,880. What this file checks
//! is the mechanism that keeps the cap unreachable.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use chacha20::cipher::{KeyIvInit, StreamCipher};
use dcroxide_crypto::rand::{MAX_CIPHER_READ, Prng};

/// A bare cipher keyed exactly as `Prng::from_seed` keys its first one.
fn reference(seed: [u8; 32]) -> chacha20::ChaCha20 {
    chacha20::ChaCha20::new(&seed.into(), &[0u8; 12].into())
}

/// Go's zero-value `chacha20.Cipher` is ChaCha20 under an all-zero key
/// and nonce at counter zero, and `PRNG.seed` XORs the first kernel key
/// through it (`prng.go:56`, `:71`). `Prng::new` claims to reproduce
/// that; this is the cross-language known-answer vector that makes the
/// claim falsifiable. A future `chacha20` release that started its
/// block counter anywhere but zero would fail here rather than silently
/// changing what every fresh bucket key derives from.
#[test]
fn the_zero_value_cipher_matches_gos() {
    let mut cipher = chacha20::ChaCha20::new(&[0u8; 32].into(), &[0u8; 12].into());
    let mut block = [0u8; 32];
    cipher.apply_keystream(&mut block);
    let hex: String = block.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex, "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7",
        "the zero-key keystream must match Go's zero-value cipher"
    );
}

/// Eight-byte draws rekey at exactly the budget, in both directions.
#[test]
fn eight_byte_draws_rekey_exactly_at_the_budget() {
    let seed = [3u8; 32];
    let mut prng = Prng::from_seed(seed);
    let mut reference = reference(seed);
    for draw in 0..(MAX_CIPHER_READ / 8) {
        let mut got = [0u8; 8];
        prng.read(&mut got);
        let mut want = [0u8; 8];
        reference.apply_keystream(&mut want);
        assert_eq!(got, want, "draw {draw} must come from the first cipher");
    }
    let mut got = [0u8; 8];
    prng.read(&mut got);
    let mut want = [0u8; 8];
    reference.apply_keystream(&mut want);
    assert_ne!(
        got, want,
        "the crossing draw must come from a rekeyed cipher"
    );
}

/// A read that straddles the budget is split at it, head from the
/// retiring cipher and tail from its replacement (dcrd `prng.go:98-104`).
#[test]
fn a_read_that_crosses_the_budget_is_split_at_it() {
    let seed = [5u8; 32];
    let mut prng = Prng::from_seed(seed);
    let mut reference = reference(seed);
    // Spend all but sixteen bytes of the first cipher's budget.
    for _ in 0..(MAX_CIPHER_READ / 8 - 2) {
        let mut got = [0u8; 8];
        prng.read(&mut got);
        let mut want = [0u8; 8];
        reference.apply_keystream(&mut want);
        assert_eq!(got, want);
    }
    let mut got = [0u8; 64];
    prng.read(&mut got);
    let mut want = [0u8; 64];
    reference.apply_keystream(&mut want);
    assert_eq!(
        got[..16],
        want[..16],
        "the head comes from the retiring cipher"
    );
    assert_ne!(got[16..], want[16..], "the tail comes from its replacement");
}

/// A single read longer than the whole budget terminates and splits.
///
/// This is the case the connection manager never had, and the reason
/// the split loop is ported rather than a rekey-ahead guard: `read` is
/// public and caller-sized, so one draw can exceed a cipher's budget.
#[test]
fn a_read_longer_than_the_budget_terminates_and_splits() {
    let seed = [9u8; 32];
    let mut prng = Prng::from_seed(seed);
    let mut reference = reference(seed);
    let len = MAX_CIPHER_READ + 4096;
    let mut got = vec![0u8; len];
    prng.read(&mut got);
    let mut want = vec![0u8; len];
    reference.apply_keystream(&mut want);
    // `assert!` rather than `assert_eq!`: a failure must not dump four
    // megabytes of keystream into the log.
    assert!(
        got[..MAX_CIPHER_READ] == want[..MAX_CIPHER_READ],
        "the first budget's worth comes from the first cipher"
    );
    assert!(
        got[MAX_CIPHER_READ..] != want[MAX_CIPHER_READ..],
        "the remainder comes from a rekeyed cipher"
    );
    assert!(
        got[MAX_CIPHER_READ..].iter().any(|&b| b != 0),
        "the remainder must actually be drawn, not left zero"
    );
}

/// `Read` is `XORKeyStream(s, s)` (`prng.go:105`), not a fill.
#[test]
fn read_xors_in_place_as_go_does() {
    let seed = [11u8; 32];
    let mut prng = Prng::from_seed(seed);
    let mut reference = reference(seed);
    let mut buf = [0xAAu8; 32];
    prng.read(&mut buf);
    let mut keystream = [0u8; 32];
    reference.apply_keystream(&mut keystream);
    let want: Vec<u8> = keystream.iter().map(|k| k ^ 0xAA).collect();
    assert_eq!(buf.to_vec(), want);
}

/// Two kernel-seeded generators do not share a stream.
///
/// Every other test here goes through `from_seed`, so all of them would
/// still pass if `Prng::new` lost its `getrandom::fill` and every
/// process shipped the ChaCha20(0, 0) key. This is the only assertion
/// that catches that.
#[test]
fn two_kernel_seeded_generators_do_not_share_a_stream() {
    let mut first = [0u8; 32];
    let mut second = [0u8; 32];
    Prng::new().expect("system random source").read(&mut first);
    Prng::new().expect("system random source").read(&mut second);
    assert_ne!(first, second);
    assert_ne!(first, [0u8; 32]);
}
