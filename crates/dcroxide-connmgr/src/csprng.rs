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
//! implementation draws from [`Prng`], the workspace's single port of
//! dcrd's `crypto/rand` generator -- the same type the address
//! manager's default source draws from.  dcrd has one `rand.PRNG`
//! reached three ways -- its addrmgr and peer packages through the
//! package global, this package through its own instance
//! (`internal/connmgr/csprng.go`) -- and so does this port, whose
//! global lives in `dcroxide_crypto::rand`.  This source stays an
//! instance because dcrd's is one.
//!
//! [`Prng`]: dcroxide_crypto::rand::Prng

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

/// The connection manager's randomness source: an instance of dcrd's
/// `crypto/rand` PRNG.
///
/// This keystream keys the outbound-group SipHash, the inbound
/// per-group rate limiter and the probabilistic connection drop, so a
/// predictable seed lets an attacker choose which groups it collides
/// with; dcrd draws all of it from `crypto/rand`
/// (`internal/connmgr/csprng.go`).  The 4 MiB rekey that keeps a draw
/// infallible lives in [`Prng`] and is documented there.
///
/// [`Prng`]: dcroxide_crypto::rand::Prng
pub struct SystemCsprng {
    prng: dcroxide_crypto::rand::Prng,
}

impl SystemCsprng {
    /// A source keyed from the provided 32 bytes of seed material.
    pub fn from_seed(seed: [u8; 32]) -> SystemCsprng {
        SystemCsprng {
            prng: dcroxide_crypto::rand::Prng::from_seed(seed),
        }
    }
}

impl Default for SystemCsprng {
    /// Seed from OS entropy.  This is the only step that can fail, and
    /// it runs at construction -- where dcrd's does, in `crypto/rand`'s
    /// package `init` (`crypto/rand/prng.go:116-122`), which panics for
    /// the same reason.
    fn default() -> SystemCsprng {
        SystemCsprng {
            prng: dcroxide_crypto::rand::Prng::new().expect("system random source"),
        }
    }
}

impl Csprng for SystemCsprng {
    fn uint64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.prng.read(&mut buf);
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
