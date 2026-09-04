// SPDX-License-Identifier: ISC
//! The randomness source rekeys before its block counter can run out.
//!
//! `SystemCsprng` promises an infallible draw, and that promise is not
//! free. `chacha20::ChaCha20` is the 96-bit-nonce variant, whose block
//! counter is a `u32` (`chacha20-0.9.1/src/lib.rs` `type Counter = u32`),
//! so one cipher yields `(2^32 - 1) * 64` bytes and then stops. The
//! stopping is not an error a caller can see: `apply_keystream` is
//! `try_apply_keystream(buf).unwrap()` (`cipher-0.4.4/src/stream.rs:119`),
//! and its own doc says it "will panic". Under `panic = "abort"` that is
//! a process outage on whichever path happened to draw.
//!
//! dcrd never reaches its own equivalent because it rekeys every 4 MiB
//! (`maxCipherRead`, `crypto/rand/prng.go:20`, applied at `:98-104`),
//! which is what lets it document that "The default global PRNG will
//! never panic after package init" (`crypto/rand/README.md:18`). The
//! port copies the budget, and this file pins it.
//!
//! What is not pinned here: the 256 GiB cap itself, which no test can
//! reach in bounded time. It was confirmed out of band by seeking a bare
//! `chacha20::ChaCha20` near the end of its counter and drawing until
//! `try_apply_keystream` returned `StreamCipherError`, at byte
//! 274,877,906,880 = `(2^32 - 1) * 64`. What this file checks is the
//! mechanism that keeps the cap unreachable.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_connmgr::{Csprng, SystemCsprng};

/// Draws per cipher: `MAX_CIPHER_READ` is 4 MiB and `uint64` draws 8
/// bytes, so the rekey lands when `8n + 8 > 4 * 1024 * 1024`.
const DRAWS_PER_CIPHER: usize = (4 * 1024 * 1024) / 8;

#[test]
fn the_source_rekeys_before_its_block_counter_can_run_out() {
    use chacha20::cipher::{KeyIvInit, StreamCipher};

    let seed = [3u8; 32];
    let mut source = SystemCsprng::from_seed(seed);

    // A bare cipher keyed exactly as `from_seed` keys its first one, so
    // the two agree for as long as the source has not rekeyed.
    let mut reference = chacha20::ChaCha20::new(&seed.into(), &[0u8; 12].into());
    let mut reference_u64 = || {
        let mut buf = [0u8; 8];
        reference.apply_keystream(&mut buf);
        u64::from_le_bytes(buf)
    };

    // Up to the budget the source is the plain keystream.
    for draw in 0..DRAWS_PER_CIPHER {
        assert_eq!(
            source.uint64(),
            reference_u64(),
            "draw {draw} must come from the first cipher, before the 4 MiB budget is spent"
        );
    }

    // The draw that would cross it comes from a new cipher instead. Both
    // halves matter: without the guard the source tracks the reference
    // forever, and with a different budget it diverges at another index.
    assert_ne!(
        source.uint64(),
        reference_u64(),
        "draw {DRAWS_PER_CIPHER} must come from a rekeyed cipher"
    );
}

#[test]
fn drawing_across_several_rekeys_never_panics() {
    let mut source = SystemCsprng::from_seed([7u8; 32]);
    let mut seen = std::collections::HashSet::new();

    // Three budgets and change. `apply_keystream` unwraps, so any
    // arithmetic error in the byte accounting surfaces as a panic here
    // rather than as a silent stall.
    for _ in 0..(3 * DRAWS_PER_CIPHER + 17) {
        seen.insert(source.uint64());
    }

    assert!(
        seen.len() > 1,
        "a keystream must not return a constant across rekeys"
    );
}
