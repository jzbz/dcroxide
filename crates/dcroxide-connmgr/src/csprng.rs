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
//! ChaCha20 keystream seeded from OS entropy, rekeyed on dcrd's 4 MiB
//! budget so a draw can never fail (`maxCipherRead`,
//! `crypto/rand/prng.go:20`, applied at `:98-104`).  dcrd also rekeys
//! every 20 seconds (`maxCipherDuration`, `:21`, applied at `:86-95`);
//! that half is not ported, because it is unobservable and would put a
//! clock read on every draw where the byte budget alone already removes
//! the panic.
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

/// The keystream bytes drawn from one cipher before it is rekeyed
/// (dcrd `maxCipherRead`, `crypto/rand/prng.go:20`).
const MAX_CIPHER_READ: usize = 4 * 1024 * 1024;

/// A ChaCha20-keystream randomness source seeded from OS entropy (the
/// same construction as the address manager's default source), rekeyed
/// every `MAX_CIPHER_READ` (4 MiB) as dcrd's `crypto/rand` PRNG is.
///
/// The rekey is what keeps a draw infallible, and it is not optional.
/// `chacha20::ChaCha20` is the 96-bit-nonce variant, whose 32-bit block
/// counter caps one cipher at `(2^32 - 1) * 64` bytes; past that,
/// `apply_keystream` panics rather than returning an error, and under
/// `panic = "abort"` that is a process outage on whatever path happened
/// to draw.  Rekeying every 4 MiB keeps a cipher five orders of
/// magnitude short of the cap, which is how dcrd can document that
/// "The default global PRNG will never panic after package init"
/// (`crypto/rand/README.md:18`).
pub struct SystemCsprng {
    cipher: chacha20::ChaCha20,
    /// The nonce for the *next* cipher.  dcrd increments it on every
    /// seeding (`crypto/rand/prng.go:26-40`, `:77`).
    nonce: [u8; 12],
    /// Bytes drawn from the current cipher.
    read: usize,
}

impl SystemCsprng {
    /// A source keyed from the provided 32 bytes of seed material.
    pub fn from_seed(seed: [u8; 32]) -> SystemCsprng {
        use chacha20::cipher::KeyIvInit;
        let nonce = [0u8; 12];
        let mut source = SystemCsprng {
            cipher: chacha20::ChaCha20::new(&seed.into(), &nonce.into()),
            nonce,
            read: 0,
        };
        source.inc_nonce();
        source
    }

    /// Increment the 12-byte little-endian nonce counter (dcrd
    /// `nonce.inc`, `crypto/rand/prng.go:26-40`).
    fn inc_nonce(&mut self) {
        for byte in self.nonce.iter_mut() {
            let (next, carry) = byte.overflowing_add(1);
            *byte = next;
            if !carry {
                break;
            }
        }
    }

    /// Rekey from kernel entropy mixed through the keystream being
    /// replaced (dcrd `PRNG.seed`, `crypto/rand/prng.go:66-81`).
    ///
    /// dcrd's seeding returns an error only on the first call --
    /// `if err != nil && p.t.IsZero()` (`prng.go:68-70`) -- and the
    /// 4 MiB path discards the return value outright (`prng.go:101`).
    /// A failed kernel read after construction is therefore harmless
    /// here too: the XOR below leaves the new key a function of the
    /// current cipher state, which an observer without the old key
    /// cannot predict.  [`SystemCsprng::default`] is the one fallible
    /// construction, and it runs at startup.
    fn reseed(&mut self) {
        use chacha20::cipher::{KeyIvInit, StreamCipher};
        let mut key = [0u8; 32];
        // Deliberately ignored; see the doc comment above.
        let _ = getrandom::fill(&mut key);
        self.cipher.apply_keystream(&mut key);
        self.cipher = chacha20::ChaCha20::new(&key.into(), &self.nonce.into());
        self.inc_nonce();
        self.read = 0;
    }

    /// XOR `buf` with the keystream, rekeying first if this draw would
    /// carry the current cipher past [`MAX_CIPHER_READ`].
    ///
    /// dcrd splits a crossing read and reseeds mid-buffer
    /// (`crypto/rand/prng.go:98-104`); rekeying before a crossing draw
    /// is the same bound without the split.  The keystream alignment
    /// that differs is not observable -- every consumer of this type
    /// wants unpredictability, not a reproducible byte position.
    fn fill(&mut self, buf: &mut [u8]) {
        use chacha20::cipher::StreamCipher;
        if self.read.saturating_add(buf.len()) > MAX_CIPHER_READ {
            self.reseed();
        }
        self.cipher.apply_keystream(buf);
        self.read = self.read.saturating_add(buf.len());
    }
}

impl Default for SystemCsprng {
    /// Seed from OS entropy.  This keystream keys the outbound-group
    /// SipHash, the inbound per-group rate limiter and the
    /// probabilistic connection drop, so a predictable seed lets an
    /// attacker choose which groups it collides with; dcrd draws all
    /// of it from `crypto/rand` (`internal/connmgr/csprng.go`).  This
    /// seeding is the only step that can fail, and it runs at
    /// construction -- where dcrd's does, in `crypto/rand`'s package
    /// `init` (`crypto/rand/prng.go:116-122`), which panics for the
    /// same reason.
    fn default() -> SystemCsprng {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("system random source");
        SystemCsprng::from_seed(seed)
    }
}

impl Csprng for SystemCsprng {
    fn uint64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill(&mut buf);
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
