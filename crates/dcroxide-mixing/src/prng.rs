// SPDX-License-Identifier: ISC
//! A ChaCha20 PRNG for a DC-net run (dcrd mixing
//! `internal/chacha20prng`).

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};

/// The required length of seeds for [`ChaCha20Prng::new`] (dcrd
/// `SeedSize`).
pub const SEED_SIZE: usize = 32;

/// A ChaCha20 PRNG for a DC-net run (dcrd `Reader`).
pub struct ChaCha20Prng {
    cipher: ChaCha20,
}

impl ChaCha20Prng {
    /// Create a ChaCha20 PRNG seeded by a 32-byte key and a run
    /// iteration (dcrd `New`).  Panics if the length of seed is not
    /// [`SEED_SIZE`] bytes.
    pub fn new(seed: &[u8], run: u32) -> ChaCha20Prng {
        assert_eq!(
            seed.len(),
            SEED_SIZE,
            "chacha20prng: bad seed length {}",
            seed.len()
        );

        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&run.to_le_bytes());

        let cipher = ChaCha20::new(seed.into(), (&nonce).into());
        ChaCha20Prng { cipher }
    }

    /// Fill the buffer with keystream bytes (dcrd `Read`; it never
    /// fails).
    pub fn read(&mut self, b: &mut [u8]) {
        for x in b.iter_mut() {
            *x = 0;
        }
        self.cipher.apply_keystream(b);
    }

    /// The next n bytes from the reader (dcrd `Next`).
    pub fn next_bytes(&mut self, n: usize) -> Vec<u8> {
        let mut b = vec![0u8; n];
        self.cipher.apply_keystream(&mut b);
        b
    }
}
