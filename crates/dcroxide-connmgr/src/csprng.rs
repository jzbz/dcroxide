// SPDX-License-Identifier: ISC
//! The connection manager's randomness seam (dcrd
//! `internal/connmgr/csprng.go`).
//!
//! dcrd consumes a `csprng` interface backed by a mutex-wrapped
//! `crypto/rand.PRNG` so tests can substitute a deterministic source;
//! the port mirrors that with a trait.  The production values (group
//! hashing keys, backoff jitter, probabilistic drops) only require
//! unpredictability, not reproducibility — dcrd's own generator is
//! seeded from OS entropy and cannot be replayed — so the default
//! implementation follows the workspace's [`AddrRng`] pattern: a
//! ChaCha20 keystream seeded from the system clock, with OS entropy
//! wired by the daemon phase.
//!
//! [`AddrRng`]: dcroxide_addrmgr::AddrRng

/// The CSPRNG methods the connection manager uses (dcrd's `csprng`
/// interface).
pub trait Csprng {
    /// A uniform random `u64` (dcrd `Uint64`).
    fn uint64(&mut self) -> u64;
    /// A random `u64` in `[0, n)` without modulo bias (dcrd
    /// `Uint64N`).
    fn uint64n(&mut self, n: u64) -> u64;
    /// A random `f64` in the half-open interval `[0.0, 1.0)`,
    /// derived exactly as dcrd's `lockingPRNG.Float64`: one
    /// `Uint64N(1<<53)` draw divided by 2^53.
    fn float64(&mut self) -> f64 {
        self.uint64n(1 << 53) as f64 / (1u64 << 53) as f64
    }
}

/// A ChaCha20-keystream randomness source seeded from the system
/// clock (the same construction as the address manager's default
/// source); the daemon phase wires OS entropy.
pub struct SystemCsprng {
    cipher: chacha20::ChaCha20,
}

impl SystemCsprng {
    /// A source keyed from the provided 32 bytes of seed material.
    pub fn from_seed(seed: [u8; 32]) -> SystemCsprng {
        use chacha20::cipher::KeyIvInit;
        let nonce = [0u8; 12];
        SystemCsprng {
            cipher: chacha20::ChaCha20::new(&seed.into(), &nonce.into()),
        }
    }
}

impl Default for SystemCsprng {
    fn default() -> SystemCsprng {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or_default();
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&nanos.to_le_bytes());
        seed[8..16].copy_from_slice(&(nanos ^ 0x5a5a_5a5a_5a5a_5a5a).to_be_bytes());
        seed[16..24].copy_from_slice(&(std::process::id() as u64).to_le_bytes());
        SystemCsprng::from_seed(seed)
    }
}

impl Csprng for SystemCsprng {
    fn uint64(&mut self) -> u64 {
        use chacha20::cipher::StreamCipher;
        let mut buf = [0u8; 8];
        self.cipher.apply_keystream(&mut buf);
        u64::from_le_bytes(buf)
    }

    // A zero bound short-circuits, `u64::MAX % n` never exceeds
    // `u64::MAX`, and the final reduction is over a nonzero n.
    #[allow(clippy::arithmetic_side_effects)]
    fn uint64n(&mut self, n: u64) -> u64 {
        // dcrd's PRNG treats a zero bound as a full-width mask and
        // returns an unconstrained value (reached by
        // `backoffWithJitter` when the backoff is a single
        // nanosecond).
        if n == 0 {
            return self.uint64();
        }
        // Rejection sampling for a uniform value without modulo bias.
        let bound = u64::MAX - u64::MAX % n;
        loop {
            let v = self.uint64();
            if v < bound {
                return v % n;
            }
        }
    }
}
