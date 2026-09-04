// SPDX-License-Identifier: ISC
//! The address manager's random source is dcrd's PRNG, and its bucket
//! key is that stream's first thirty-two bytes.
//!
//! `SystemRng` used to be a ChaCha20 keystream seeded once and never
//! rekeyed. chacha20's block counter is a `u32`, so one cipher yields
//! `(2^32 - 1) * 64` bytes and then panics rather than erroring —
//! `apply_keystream` is `try_apply_keystream(..).unwrap()` — and under
//! `panic = "abort"` that is an outage. It now draws from
//! `dcroxide_crypto::rand::Prng`, which rekeys on dcrd's 4 MiB budget;
//! the budget's mechanics are pinned in that crate's own tests, and
//! what this file pins is the address manager's end of it.
//!
//! The bucket key is why this matters beyond the panic: it decides
//! which new/tried bucket an address lands in, so an attacker who can
//! predict it can steer its own addresses into chosen buckets, which is
//! the precondition for an eclipse. It is persisted in `peers.json`, so
//! a weak draw is permanent for the life of the data directory.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::{Arc, Mutex};

use chacha20::cipher::{KeyIvInit, StreamCipher};
use dcroxide_addrmgr::{AddrManager, AddrRng, SystemRng};
use dcroxide_crypto::rand::MAX_CIPHER_READ;

fn manager_with(seed: [u8; 32], dir: &std::path::Path) -> AddrManager {
    let rng: Arc<Mutex<dyn AddrRng + Send>> = Arc::new(Mutex::new(SystemRng::from_seed(seed)));
    AddrManager::new_with_hooks(dir, Arc::new(|| 0), rng)
}

/// The key `reset` installs is the stream's first thirty-two bytes.
///
/// Three claims at once, each broken by a different mutation: that
/// `reset` keys the buckets from the stream at all (dcrd
/// `addrmanager.go:809`); that the first cipher runs at nonce zero, so
/// a random-nonce `Default` or a counter starting at one makes the key
/// unequal; and that `read` applies the keystream rather than something
/// derived from it. It does not establish unpredictability — the next
/// test does that.
#[test]
fn the_bucket_key_is_the_first_thirty_two_bytes_of_the_stream() {
    let seed = [23u8; 32];
    let dir = tempfile::tempdir().expect("tempdir");
    let am = manager_with(seed, dir.path());

    let mut want = [0u8; 32];
    chacha20::ChaCha20::new(&seed.into(), &[0u8; 12].into()).apply_keystream(&mut want);

    assert_eq!(
        am.state_snapshot().3,
        want,
        "the bucket key must be the stream's first thirty-two bytes"
    );
}

/// Two managers built the production way do not share a bucket key.
///
/// The test above would still pass if `Default` hard-coded a seed;
/// this one would not. It is the end-to-end statement of the
/// eclipse-resistance property, reached through the `Default` path
/// every seeded test bypasses.
#[test]
fn two_fresh_managers_do_not_share_a_bucket_key() {
    let dir_a = tempfile::tempdir().expect("tempdir");
    let dir_b = tempfile::tempdir().expect("tempdir");
    let key_a = AddrManager::new(dir_a.path()).state_snapshot().3;
    let key_b = AddrManager::new(dir_b.path()).state_snapshot().3;

    assert_ne!(key_a, key_b, "two fresh managers must not share a key");
    assert_ne!(key_a, [0u8; 32], "the key must actually be drawn");
}

/// A second `reset` XORs into the key the peers file already supplied.
///
/// This is QK-0012's pin. dcrd's `rand.Read` is documented as filling
/// the buffer and implemented as `XORKeyStream(s, s)`
/// (`crypto/rand/prng.go:83-84`, `:103`), and its `reset` calls it
/// straight into `a.key` (`addrmgr/addrmanager.go:809`, whose comment
/// still says "fill key"). On the second `reset` of a process that is
/// exactly a XOR into whatever the partial load left there.
///
/// The path is live rather than hypothetical: `deserialize_peers`
/// assigns `self.key = sam.key` before validating the buckets, a bucket
/// naming an address the list lacks then errors, and `load_peers`
/// answers that by calling `reset()` — which draws into the
/// already-populated key.
#[test]
fn a_second_reset_xors_into_the_key_the_file_supplied() {
    let seed = [43u8; 32];
    let file_key = [0x5Au8; 32];
    let dir = tempfile::tempdir().expect("tempdir");

    // A peers file whose key parses and whose new-bucket entry names an
    // address the list does not carry, so the load fails AFTER the key
    // is assigned.  The version must be the accepted one: a rejected
    // version returns before `self.key = sam.key` and the test then
    // measures construction's key instead of the file's.
    let peers = format!(
        r#"{{"Version":1,"Key":{key:?},"Addresses":[],"NewBuckets":[["1.2.3.4:9108"]],"TriedBuckets":[]}}"#,
        key = file_key
    );
    std::fs::write(dir.path().join("peers.json"), peers).expect("write peers.json");

    let mut am = manager_with(seed, dir.path());
    // Construction already ran one reset, spending the stream's first
    // thirty-two bytes; the second draw is bytes 32..64.
    am.load_peers();

    let mut keystream = [0u8; 64];
    chacha20::ChaCha20::new(&seed.into(), &[0u8; 12].into()).apply_keystream(&mut keystream);
    let want: Vec<u8> = keystream[32..]
        .iter()
        .zip(file_key.iter())
        .map(|(k, f)| k ^ f)
        .collect();

    assert_eq!(
        am.state_snapshot().3.to_vec(),
        want,
        "the second reset must XOR into the file's key, not overwrite it"
    );
    // The offset half is its own control: had construction not spent
    // the first thirty-two bytes, this would be keystream[..32].
    assert_ne!(
        am.state_snapshot().3.to_vec(),
        keystream[..32]
            .iter()
            .zip(file_key.iter())
            .map(|(k, f)| k ^ f)
            .collect::<Vec<u8>>(),
        "the second reset must draw the stream's next thirty-two bytes"
    );
}

/// The selection loop draws across several budgets without panicking.
///
/// Honestly weak as a discriminator: it passes under the old
/// never-rekeyed source too, because nothing panics at these lengths.
/// What it controls for is the byte accounting — `apply_keystream`
/// unwraps, so an underflow in the split arithmetic or a
/// non-advancing loop surfaces here as a panic or a hang rather than a
/// silent stall — and for a source that stopped advancing, which
/// collapses the distinctness assertion.
#[test]
fn the_selection_loop_draws_across_several_budgets() {
    let mut rng = SystemRng::from_seed([31u8; 32]);
    let mut seen = std::collections::HashSet::new();

    for _ in 0..(3 * (MAX_CIPHER_READ / 8) + 17) {
        let v = rng.int_n(1000);
        assert!(v < 1000, "int_n must stay in range");
        seen.insert(v);
    }

    assert!(seen.len() > 1, "the source must keep advancing");
}
