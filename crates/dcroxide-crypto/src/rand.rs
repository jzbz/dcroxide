// SPDX-License-Identifier: ISC
//! dcrd's userspace CSPRNG (`crypto/rand`, `prng.go`): a ChaCha20
//! keystream that rekeys itself from kernel entropy on a byte budget,
//! so a draw can never fail.
//!
//! dcrd has one generator type and two ways of reaching it.  Most
//! packages draw from the package global -- the address manager
//! (`addrmgr/addrmanager.go:809` `rand.Read(a.key[:])`, `:341`,
//! `:797`, `:909-968`), the peer package (`peer/peer.go:842`, `:873`,
//! `:1629`, `:1813`, `:2186`) and the RPC server
//! (`internal/rpcserver/rpcwebsocket.go:2037`) among them; the
//! connection manager holds an instance of its own
//! (`internal/connmgr/csprng.go`).  [`Prng`] is that one type;
//! `dcroxide_addrmgr::SystemRng` and `dcroxide_connmgr::SystemCsprng`
//! are two instances of it, and the process-wide generator [`init`]
//! seeds is the third reach.  Stating the budget once is the point: it
//! is a magic number whose only justification is a panic no test can
//! reach in bounded time, and copies of such a number drift.
//!
//! Ported: `maxCipherRead` (`prng.go:20`), `nonce.inc` (`:26-40`),
//! `NewPRNG` (`:55-63`), `PRNG.seed` (`:67-81`), `PRNG.Read` including
//! its mid-buffer split loop (`:85-105`); `uniform.go`'s `PRNG.Uint64`
//! (`:54-58`), `PRNG.Uint64N` (`:102-148`), `PRNG.Duration`
//! (`:202-209`) and `PRNG.Shuffle` (`:214-230`); and the package
//! globals -- `lockingPRNG`
//! (`prng.go:111-114`), the `init` that seeds it (`:116-122`), and the
//! `default.go` entry points the daemon's draws go through:
//! `Uint64` (`default.go:37-42`) and `ShuffleSlice` (`:144-148`) over
//! `Shuffle` (`:136-141`) for the peer module, `IntN` (`:109-114`)
//! for the mining package's address pick, and `Duration`
//! (`:126-131`) for the seeder's address backdating.
//!
//! The globals are ported because dcrd's peer module reaches
//! randomness through nothing else: `rand.Uint64()` for the ping and
//! version nonces (`peer/peer.go:1813`, `:2186`) and
//! `rand.ShuffleSlice` for both addr relays (`:842`, `:873`), with no
//! per-peer generator anywhere in that file.  Go runs `init` before
//! `main`; Rust has no equivalent, so the seeding here is lazy and
//! [`init`] is the explicit hook a peer-serving binary calls first to
//! put dcrd's one fatal kernel read back at startup.
//!
//! Not ported, and why:
//!
//! * `maxCipherDuration`, the 20-second reseed (`prng.go:21`, applied
//!   at `:86-95`).  The byte budget alone removes the panic the rekey
//!   exists to prevent, and a duration would put a clock read on every
//!   draw.  Unobservable outside the process; recorded in PARITY.md.
//! * `uniform.go`'s `Uint32N` and the `is32bit` delegation to it
//!   (`:61-97`, `:99`, `:103-104`).  Go's own comment says the 32-bit
//!   arithmetic is there "to preserve the exact output sequence
//!   observed on 64-bit machines" (`:69-71`), so the 64-bit
//!   [`Prng::uint64n`] ported here yields the same values on every
//!   target and the split is a Go performance detail.
//! * `Shuffle`'s `(n, swap)` callback form (`uniform.go:214-230`,
//!   `default.go:136-141`).  Go needs a swap closure because it cannot
//!   name a generic slice-element swap; `<[T]>::swap` is that closure,
//!   so the two Go functions collapse into [`shuffle_slice`].
//! * The `default.go` entry points no consumer reaches: `Reader`,
//!   `Read`, `Uint32`, `Uint32N`, `Uint64N`, and the remaining
//!   `Int*`/`UintN`/`BigInt`/`Float64` wrappers.  Each is two lines
//!   over [`Prng`] when a consumer appears -- which is how `IntN`
//!   arrived with the mining-address pick and `Duration` with the
//!   seeder's backdating.  `peer/peer.go:1629`'s inventory trickle
//!   timeout is a further `rand.Duration` caller whose port is not
//!   yet wired.
//! * The OpenBSD `arc4random` build variant
//!   (`crypto/rand/prng_arc4random.go`), a Go-toolchain fallback.
//!
//! What this does *not* change: `SystemRng` and `SystemCsprng` keep
//! the rejection loops they already have, so no value either of them
//! draws moves.  What did change is the two daemon sites that reduced
//! by raw modulo where dcrd's own arithmetic was the target -- the
//! peer environment's address shuffles, the mining-address pick and
//! the seeder's backdating -- which now use dcrd's reduction.  The two
//! raw modulos left, both in `dcroxide-mempool`, are deliberate and
//! are not work in progress: dcrd draws nothing at either site, so
//! there is no reduction to converge on, and [`Prng::uint64n`] rejects
//! and redraws where that crate's test doubles answer with a constant.
//! See PARITY.md's *Orphan eviction source* row and
//! `PoolChain::random_u64`'s contract before changing them.

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

    /// A uniform random `u64` (dcrd `PRNG.Uint64`,
    /// `crypto/rand/uniform.go:54-58`).
    ///
    /// Little-endian, as Go's `binary.LittleEndian.Uint64` is.
    /// [`Prng::read`] XORs rather than fills (see QK-0012), so the
    /// zeroed buffer is what makes this a draw.
    pub fn uint64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.read(&mut buf);
        u64::from_le_bytes(buf)
    }

    /// A uniform random `u64` in `[0, n)` without modulo bias (dcrd
    /// `PRNG.Uint64N`, `crypto/rand/uniform.go:102-148`).
    ///
    /// Lemire's multiply-shift, not a modulo: the high half of the
    /// double-width product `x * n` is already the reduced value, and
    /// the low half says whether `x` fell in the short residue class
    /// that would bias it.  Go skips the `-n % n` division unless
    /// `lo < n`, because the threshold is always below `n` and the
    /// rejection loop therefore almost never runs (`:141-146`); that
    /// shortcut is reproduced because it decides the draw count, and
    /// the draw count is observable through a shared stream.
    ///
    /// A zero bound takes the power-of-two branch exactly as Go's does
    /// -- `0 & (0 - 1)` is `u64::MAX`, so the mask is the whole range
    /// (`:106-108`) -- and yields an unconstrained draw.  That branch
    /// is reachable upstream, from `connmgr`'s `backoffWithJitter` on a
    /// single-nanosecond backoff, so it is reproduced rather than
    /// asserted away.
    ///
    /// Go's `is32bit` delegation to `Uint32N` (`:103-104`) is not
    /// reproduced; the module documentation says why it cannot change
    /// a value.
    pub fn uint64n(&mut self, n: u64) -> u64 {
        // `n` is a power of two -- zero included, as in Go -- so the
        // reduction is a mask (`uniform.go:106-108`).
        if n & n.wrapping_sub(1) == 0 {
            return self.uint64() & n.wrapping_sub(1);
        }
        let (mut hi, mut lo) = wide_mul(self.uint64(), n);
        if lo < n {
            // Go's `-n % n`, i.e. `2^64 mod n` (`uniform.go:142`).  `n`
            // is nonzero on this branch, so the remainder is defined;
            // `checked_rem` is the spelling that spares this module an
            // `arithmetic_side_effects` allow.
            let thresh = n.wrapping_neg().checked_rem(n).unwrap_or(0);
            while lo < thresh {
                (hi, lo) = wide_mul(self.uint64(), n);
            }
        }
        hi
    }

    /// A uniform index in `[0, n)` without modulo bias (dcrd
    /// `PRNG.IntN`, `crypto/rand/uniform.go:190-195`).
    ///
    /// dcrd takes and returns an `int` and panics for `n <= 0`
    /// (`:191-193`); this takes a `usize`, so only the zero case can
    /// occur and only that half of the guard survives.  The message is
    /// dcrd's.
    pub fn int_n(&mut self, n: usize) -> usize {
        assert!(n > 0, "rand: invalid argument to IntN");
        self.uint64n(n as u64) as usize
    }

    /// A uniform duration in `[0, n)` nanoseconds (dcrd
    /// `PRNG.Duration`, `crypto/rand/uniform.go:202-209`).
    ///
    /// Nanoseconds as an `i64` because that is what Go's
    /// `time.Duration` is, so the bound and the result carry dcrd's own
    /// range.  Panics for a non-positive bound with dcrd's message
    /// (`:203-205`); the port had been coercing such a bound to one
    /// instead, which is a divergence no caller reaches -- every
    /// production bound is a positive constant -- but which would have
    /// hidden the mistake if one ever did.
    pub fn duration(&mut self, n: i64) -> i64 {
        assert!(n > 0, "rand: invalid argument to Duration");
        self.uint64n(n as u64) as i64
    }

    /// Randomize the order of every element in `s` (dcrd
    /// `PRNG.Shuffle`, `crypto/rand/uniform.go:214-230`).
    ///
    /// Fisher-Yates drawing each index through [`Prng::uint64n`].  Two
    /// things here are load-bearing.  The reduction is what makes the
    /// permutation uniform: a full-width draw reduced by modulo -- what
    /// the daemon's peer environment did before this -- is not, and
    /// dcrd does not do it.  And the direction is upstream's
    /// (`:225-228`): descending from `n - 1` with a draw in `[0, i]` is
    /// the Fisher-Yates that is uniform over permutations; the
    /// ascending variant with a draw in `[0, n)` is not.
    ///
    /// Go's `Shuffle` takes a swap closure and `ShuffleSlice` supplies
    /// the slice one (`default.go:144-148`); `<[T]>::swap` is that
    /// closure, so the two Go functions collapse into this one.  Go's
    /// `n < 0` panic (`:215-217`) has no counterpart, because a slice
    /// length cannot be negative.
    pub fn shuffle<T>(&mut self, s: &mut [T]) {
        let len = s.len();
        for i in (1..len).rev() {
            // dcrd's `j := int(p.Uint64N(uint64(i + 1)))` (`:226`).
            // `i` is below `len`, so the increment cannot overflow; the
            // saturating form is what spares this module an
            // `arithmetic_side_effects` allow.
            let bound = (i as u64).saturating_add(1);
            let j = self.uint64n(bound) as usize;
            s.swap(i, j);
        }
    }
}

/// The double-width product of two `u64`s as `(hi, lo)` (Go
/// `math/bits.Mul64`, which `Uint64N` calls at
/// `crypto/rand/uniform.go:140`).
fn wide_mul(x: u64, y: u64) -> (u64, u64) {
    let wide = u128::from(x).wrapping_mul(u128::from(y));
    ((wide >> 64) as u64, wide as u64)
}

/// The process-wide generator the functions below draw from (dcrd
/// `globalRand *lockingPRNG`, `crypto/rand/default.go:20`,
/// `crypto/rand/prng.go:111-114`).
///
/// dcrd seeds this in package `init` and panics when the first read of
/// the kernel fails (`prng.go:116-122`); that panic is the whole basis
/// of the package's promise that "The default global PRNG will never
/// panic after package init" (`crypto/rand/README.md:18`).  Rust has
/// no pre-`main` `init`, so the seeding is lazy here and [`init`] is
/// the explicit hook that puts it back at startup.  Laziness is the
/// fallback, not the design: a daemon that never calls [`init`] moves
/// its one fallible read to whichever draw comes first, which for a
/// node serving peers is a handshake nonce on an accepted connection.
static GLOBAL: std::sync::OnceLock<std::sync::Mutex<Prng>> = std::sync::OnceLock::new();

fn global() -> &'static std::sync::Mutex<Prng> {
    GLOBAL.get_or_init(|| {
        // dcrd's package `init` panics on a failed first seeding
        // (`crypto/rand/prng.go:116-122`).  Every draw after it is
        // infallible, which is the property this module exists to
        // provide.
        std::sync::Mutex::new(Prng::new().expect("system random source"))
    })
}

/// The global generator, recovering a poisoned lock.
///
/// A panic while the guard was held cannot leave a [`Prng`] in a state
/// later draws must avoid -- [`Prng::read`] XORs a buffer and advances
/// a counter, and a partially applied keystream is still keystream --
/// so the poison flag carries no information here, while honouring it
/// would turn one unrelated panic on one peer's thread into a failure
/// on every later draw in the process.  `dcroxide_peer::PeerGlobals`
/// treats its own lock the same way, for the same reason.
fn locked() -> std::sync::MutexGuard<'static, Prng> {
    global()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Seed the process-wide generator now, panicking if the operating
/// system cannot supply the first key (dcrd `crypto/rand`'s package
/// `init`, `crypto/rand/prng.go:116-122`).
///
/// Go runs that `init` before `main`, so upstream's one fatal kernel
/// read is always a startup read and every later draw is infallible.
/// A binary that serves peers calls this first to inherit the same
/// guarantee.  Calling it more than once is a no-op; not calling it is
/// safe but relocates the fallible read to the first draw.
pub fn init() {
    let _ = global();
}

/// A uniform random `u64` from the process-wide generator (dcrd
/// `rand.Uint64`, `crypto/rand/default.go:37-42`).
pub fn uint64() -> u64 {
    locked().uint64()
}

/// A uniform index in `[0, n)` from the process-wide generator (dcrd
/// `rand.IntN`, `crypto/rand/default.go:109-114`).
pub fn int_n(n: usize) -> usize {
    locked().int_n(n)
}

/// A uniform duration in `[0, n)` nanoseconds from the process-wide
/// generator (dcrd `rand.Duration`, `crypto/rand/default.go:126-131`).
pub fn duration(n: i64) -> i64 {
    locked().duration(n)
}

/// Randomize the order of every element in `s` using the process-wide
/// generator (dcrd `rand.ShuffleSlice`,
/// `crypto/rand/default.go:144-148`).
///
/// One lock acquisition covers the whole shuffle, which is dcrd's
/// shape rather than a shortcut taken here: `ShuffleSlice` calls
/// `Shuffle`, and `Shuffle` takes `globalRand.Lock()` once and defers
/// the unlock past the entire loop (`default.go:136-141`).  Taking it
/// per swap would be a divergence and slower besides.  The longest
/// hold the daemon can be made to produce is one over-full addr relay:
/// the address cache is capped at `getKnownAddressLimit = 2500`
/// (`addrmgr/addrmanager.go:234`), so at most 2499 reductions, and at
/// most once per inbound connection, because a second getaddr is not
/// answered (`serverPeer.addrsSent`).
pub fn shuffle_slice<T>(s: &mut [T]) {
    locked().shuffle(s);
}
