// SPDX-License-Identifier: ISC
//! dcrd's userspace CSPRNG (`crypto/rand`, `prng.go`): a ChaCha20
//! keystream that rekeys itself from kernel entropy on a byte budget,
//! so a draw can never fail.
//!
//! dcrd has one generator type and two ways of reaching it.  The
//! address manager draws from the package global
//! (`addrmgr/addrmanager.go:809` `rand.Read(a.key[:])`, `:341`, `:797`,
//! `:909-968`); the connection manager holds an instance of its own
//! (`internal/connmgr/csprng.go`).  [`Prng`] is that one type, and
//! `dcroxide_addrmgr::SystemRng` and `dcroxide_connmgr::SystemCsprng`
//! are the two instances.  Stating the budget once is the point: it is
//! a magic number whose only justification is a panic no test can reach
//! in bounded time, and copies of such a number drift.
//!
//! Ported: `maxCipherRead` (`prng.go:20`), `nonce.inc` (`:26-40`),
//! `NewPRNG` (`:55-63`), `PRNG.seed` (`:67-81`) and `PRNG.Read`
//! including its mid-buffer split loop (`:85-105`).
//!
//! Not ported, and why:
//!
//! * `maxCipherDuration`, the 20-second reseed (`prng.go:21`, applied
//!   at `:86-95`).  The byte budget alone removes the panic the rekey
//!   exists to prevent, and a duration would put a clock read on every
//!   draw.  Unobservable outside the process; recorded in PARITY.md.
//! * `uniform.go`'s integer reductions.  Each consumer keeps the
//!   rejection loop it already has, so this module alters no drawn
//!   value.  The modulo-versus-Lemire difference is pre-existing and
//!   already recorded in PARITY.md's divergences table.
//! * The package globals -- `globalRand`, `lockingPRNG` and
//!   `default.go`.  This port has no process-wide `init`; each
//!   consumer owns an instance instead, which is the shape dcrd's own
//!   connection manager uses.  Where a consumer needs one shared across
//!   threads it wraps it itself, as the address manager does.
//! * The OpenBSD `arc4random` build variant
//!   (`crypto/rand/prng_arc4random.go`), a Go-toolchain fallback.

use chacha20::cipher::{KeyIvInit, StreamCipher};

/// The keystream bytes drawn from one cipher before it is rekeyed
/// (dcrd `maxCipherRead`, `crypto/rand/prng.go:20`).
pub const MAX_CIPHER_READ: usize = 4 * 1024 * 1024;

/// A cryptographically secure pseudorandom number generator (dcrd
/// `PRNG`, `crypto/rand/prng.go:46-51`).
///
/// The rekey is not hygiene, it is what keeps a draw infallible.
/// `chacha20::ChaCha20` is the 96-bit-nonce variant, whose block
/// counter is a `u32` (`chacha20-0.9.1/src/lib.rs`,
/// `type Counter = u32`), so one cipher yields `(2^32 - 1) * 64` bytes
/// and then stops -- and stops by panicking, because `apply_keystream`
/// is `try_apply_keystream(..).unwrap()`
/// (`cipher-0.4.4/src/stream.rs:119`).  Under this workspace's
/// `panic = "abort"` release profile that is a process outage on
/// whichever path happened to draw.  Rekeying every [`MAX_CIPHER_READ`]
/// bytes keeps a cipher five orders of magnitude short of the cap,
/// which is how dcrd can document that "The default global PRNG will
/// never panic after package init" (`crypto/rand/README.md:18`).
///
/// Go's `PRNG` keeps its key in the struct because `XORKeyStream`
/// rewrites it in place; here it is a local in `Prng::seed`.  Go's
/// `t` field is the 20-second reseed deadline, which is not ported --
/// see the module documentation.
pub struct Prng {
    cipher: chacha20::ChaCha20,
    /// The nonce for the *next* cipher.  dcrd increments it on every
    /// seeding (`crypto/rand/prng.go:26-40`, `:77`).
    nonce: [u8; 12],
    /// Bytes drawn from the current cipher.
    read: usize,
}

impl Prng {
    /// A generator seeded from the operating system (dcrd `NewPRNG`,
    /// `crypto/rand/prng.go:55-63`).
    ///
    /// Go's `new(PRNG)` leaves a zero-value `chacha20.Cipher`, which is
    /// a usable keystream in Go -- all-zero key, all-zero nonce,
    /// counter zero -- and the first seeding XORs the kernel bytes
    /// through it before keying (`prng.go:56`, `:72`).  So dcrd's first
    /// key is the kernel bytes XORed with ChaCha20(0, 0).  That is
    /// reproduced rather than simplified away, which is also what lets
    /// the initial seeding and every rekey share one `Prng::seed`
    /// path, as dcrd's do.  The zero-key keystream is pinned by
    /// `tests/rand_prng.rs`.
    ///
    /// This is the only fallible step, exactly as it is in dcrd, where
    /// only the first seeding can return an error (`prng.go:68-70`) and
    /// the package `init` turns it into a panic (`:116-122`).
    pub fn new() -> Result<Prng, getrandom::Error> {
        let mut prng = Prng {
            cipher: chacha20::ChaCha20::new(&[0u8; 32].into(), &[0u8; 12].into()),
            nonce: [0u8; 12],
            read: 0,
        };
        let mut key = [0u8; 32];
        // dcrd returns the read error only on the first seeding, before
        // any cipher of its own is installed (`prng.go:68-70`).
        getrandom::fill(&mut key)?;
        prng.seed(key);
        Ok(prng)
    }

    /// A generator keyed directly from the provided 32 bytes, so a test
    /// can predict the stream.
    ///
    /// dcrd has no such constructor: its `PRNG` is only ever seeded
    /// from the kernel.  Keying directly rather than through
    /// `Prng::seed`'s mix is what lets a test state its reference as
    /// a bare `ChaCha20::new(seed, zero nonce)` without putting the
    /// construction under test on both sides of the comparison.  The
    /// budget, the nonce sequence and the rekey path are the production
    /// ones; only the first key differs.
    pub fn from_seed(seed: [u8; 32]) -> Prng {
        let mut prng = Prng {
            cipher: chacha20::ChaCha20::new(&seed.into(), &[0u8; 12].into()),
            nonce: [0u8; 12],
            read: 0,
        };
        prng.inc_nonce();
        prng
    }

    /// Increment the 12-byte little-endian nonce counter (dcrd
    /// `nonce.inc`, `crypto/rand/prng.go:26-40`).
    ///
    /// dcrd carries between three little-endian `u32` limbs; a
    /// byte-wise carry over the same twelve bytes is the same counter.
    fn inc_nonce(&mut self) {
        for byte in self.nonce.iter_mut() {
            let (next, carry) = byte.overflowing_add(1);
            *byte = next;
            if !carry {
                break;
            }
        }
    }

    /// Install `key`, mixed through the keystream being replaced, and
    /// reset the byte budget (dcrd `PRNG.seed` from `:72` onward).
    ///
    /// The 32-byte mix is drawn from the outgoing cipher and is not
    /// charged against the budget, because dcrd clears the counter
    /// immediately afterwards (`prng.go:72`, `:78`).  A cipher
    /// therefore yields `MAX_CIPHER_READ + 32` bytes rather than
    /// `MAX_CIPHER_READ`.  That is upstream's arithmetic, reproduced
    /// rather than corrected; it is five orders of magnitude clear of
    /// the block-counter cap either way.
    fn seed(&mut self, mut key: [u8; 32]) {
        self.cipher.apply_keystream(&mut key);
        self.cipher = chacha20::ChaCha20::new(&key.into(), &self.nonce.into());
        self.inc_nonce();
        self.read = 0;
    }

    /// Rekey from fresh kernel entropy (dcrd `PRNG.seed`'s
    /// `cryptorand.Read`, `crypto/rand/prng.go:68`).
    ///
    /// A failed read is ignored, which follows dcrd's structure rather
    /// than its behaviour, and the difference is worth stating.  dcrd
    /// guards the error with `if err != nil && p.t.IsZero()`
    /// (`prng.go:68-70`) and its own rekey path discards the return
    /// value outright (`:101`), so the *shape* is infallible-after-init
    /// -- "Read never errors" (`:84`).  But on any toolchain dcrd can
    /// build with (`go.mod` requires 1.25) `crypto/rand.Read` never
    /// returns an error at all: it calls `runtime.fatal` and kills the
    /// process.  So dcrd's guard is dead code, and where upstream would
    /// die this continues with a key drawn from the outgoing keystream,
    /// which an observer without the old key cannot predict.  That is a
    /// deliberate divergence in favour of the infallible draw this type
    /// exists to provide, recorded in PARITY.md.  [`Prng::new`] is the
    /// one construction that treats the read as fatal, and it runs at
    /// startup, where dcrd's package `init` does too (`:116-122`).
    fn reseed(&mut self) {
        let mut key = [0u8; 32];
        // Deliberately ignored; see the doc comment above.
        let _ = getrandom::fill(&mut key);
        self.seed(key);
    }

    /// XOR `buf` with the keystream in place, rekeying as many times as
    /// the buffer's length requires (dcrd `PRNG.Read`,
    /// `crypto/rand/prng.go:85-105`).
    ///
    /// The loop is dcrd's (`:98-104`): a draw that would carry the
    /// current cipher past [`MAX_CIPHER_READ`] is split, its head taken
    /// from the current cipher and the remainder from a rekeyed one, as
    /// many times as it takes.  Splitting rather than rekeying ahead of
    /// the whole draw is what makes the budget a bound for a buffer of
    /// *any* length: rekeying ahead would leave one cipher responsible
    /// for a read larger than the budget, and
    /// `dcroxide_addrmgr::AddrRng::read` is public and caller-sized.
    /// The loop terminates because `Prng::seed` clears the counter, so
    /// each further iteration consumes a full budget's worth.  For any
    /// draw at or below the budget the two shapes are identical: at the
    /// boundary the split is empty, so the whole draw comes from the
    /// rekeyed cipher either way.
    ///
    /// The buffer is XORed, not overwritten, exactly as
    /// `XORKeyStream(s, s)` is (`prng.go:105`); dcrd's doc comment at
    /// `:83` says it fills.  A
    /// caller wanting bytes rather than a XOR passes a zeroed buffer,
    /// which is what dcrd's own callers do.  See QK-0012.
    pub fn read(&mut self, buf: &mut [u8]) {
        let mut rest = buf;
        // `read` never exceeds the budget -- `seed` clears it and the
        // loop stops at the boundary -- so the saturating forms below
        // are the plain arithmetic dcrd writes, spelled so this module
        // needs no `arithmetic_side_effects` allow.
        while self.read.saturating_add(rest.len()) > MAX_CIPHER_READ {
            let split = MAX_CIPHER_READ.saturating_sub(self.read);
            let (head, tail) = rest.split_at_mut(split);
            self.cipher.apply_keystream(head);
            self.reseed();
            rest = tail;
        }
        self.cipher.apply_keystream(rest);
        self.read = self.read.saturating_add(rest.len());
    }
}
