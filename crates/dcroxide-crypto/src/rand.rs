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
//! its mid-buffer split loop (`:85-105`); `uniform.go`'s `PRNG.Uint32`
//! (`:47-51`), `PRNG.Uint64` (`:54-58`), `PRNG.Uint32N` (`:61-97`),
//! `PRNG.Uint64N` (`:102-148`), `PRNG.Int32` (`:152-154`),
//! `PRNG.Int32N` (`:159-164`), `PRNG.Int64` (`:168-170`),
//! `PRNG.Int64N` (`:175-180`), `PRNG.Int` (`:183-185`), `PRNG.IntN`
//! (`:190-195`), `PRNG.UintN` (`:198-200`), `PRNG.Duration`
//! (`:202-209`) and `PRNG.Shuffle` (`:214-230`); and the package
//! globals -- `lockingPRNG`
//! (`prng.go:111-114`), the `init` that seeds it (`:116-122`), and the
//! `default.go` entry points over each of those methods, each holding
//! the lock for the whole call as dcrd's do: `Read` (`default.go:22-26`),
//! `Uint32` (`:29-34`), `Uint64` (`:37-42`), `Uint32N` (`:45-50`),
//! `Uint64N` (`:53-58`), `Int32` (`:62-67`), `Int32N` (`:72-77`),
//! `Int64` (`:81-86`), `Int64N` (`:91-96`), `Int` (`:99-104`), `IntN`
//! (`:109-114`), `UintN` (`:117-122`), `Duration` (`:126-131`) and
//! `ShuffleSlice` (`:144-148`) over `Shuffle` (`:136-141`).  The daemon
//! draws through `Uint64` and `ShuffleSlice` for the peer module, `IntN`
//! for the mining package's address pick, `Duration` for the seeder's
//! backdating, the rebroadcast timer and the inventory trickle, and
//! `Read` for the RPC server's auth HMAC key; the rest serve library
//! consumers such as a wallet, whose change-position draw is
//! dcrwallet's `rand.Int32N` in `RandomizeOutputPosition`
//! (`wallet/txauthor`).
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
//! * The 32-bit arithmetic inside `uniform.go`'s `Uint32N` (`:80-95`)
//!   and the `is32bit` delegation of `Uint64N` to it (`:99`,
//!   `:103-104`).  Go's own comment says the 32-bit form is there "to
//!   preserve the exact output sequence observed on 64-bit machines"
//!   (`:68-70`).  That comment came from `math/rand/v2`, where the
//!   form runs on 32-bit machines only; dcrd's `Uint32N` has no
//!   `is32bit` test and runs it on every target.  It computes the high
//!   word and the low 64 bits of the 96-bit product `x * n` from
//!   32-bit halves.  [`Prng::uint32n`]
//!   computes the same two quantities with one 128-bit product, through
//!   [`Prng::uint64n`]; its documentation gives the argument that the
//!   values and the draw count are Go's, `tests/rand_uniform.rs` checks
//!   it against the 32-bit form written out, and
//!   `tests/rand_oracle_differential.rs` against dcrd itself.
//! * `Shuffle`'s `(n, swap)` callback form (`uniform.go:214-230`,
//!   `default.go:136-141`).  Go needs a swap closure because it cannot
//!   name a generic slice-element swap; `<[T]>::swap` is that closure,
//!   so the two Go functions collapse into [`shuffle_slice`].
//! * `Reader` (`default.go:16-18`), `BigInt` (`uniform.go:232-236`,
//!   `default.go:151-156`) and the generic `N` (`default.go:161-166`).
//!   `Reader` hands out the global as a Go `io.Reader`, which [`read`]
//!   already is in substance; `BigInt` needs an arbitrary-precision
//!   integer type and Go's `crypto/rand.Int` sampling over it, which no
//!   consumer of this crate has asked for; and `N` is Go's way of
//!   spelling one function for every integer type, which the typed
//!   functions here already are for the types that have consumers.
//!   Each is a small addition over [`Prng`] when a consumer appears.
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
/// counter is a `u32` (`chacha20-0.10.2/src/variants.rs:37`,
/// `type Counter = u32`), so one cipher yields `(2^32 - 1) * 64` bytes
/// and then stops -- and stops by panicking, because `apply_keystream`
/// is `try_apply_keystream(buf).expect("end of keystream reached")`
/// (`cipher-0.5.2/src/stream.rs:185-188`).  Under this workspace's
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

    /// A uniform random `u32` (dcrd `PRNG.Uint32`,
    /// `crypto/rand/uniform.go:47-51`).
    ///
    /// Four stream bytes, little-endian, as Go's
    /// `binary.LittleEndian.Uint32` of a four-byte read: half the
    /// stream [`Prng::uint64`] consumes.  That is observable through a
    /// shared stream, so it is reproduced rather than taken as the low
    /// half of an eight-byte draw.
    pub fn uint32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.read(&mut buf);
        u32::from_le_bytes(buf)
    }

    /// A uniform random `u32` in `[0, n)` without modulo bias (dcrd
    /// `PRNG.Uint32N`, `crypto/rand/uniform.go:61-97`).
    ///
    /// The values and the number of eight-byte draws are Go's for every
    /// `n`, zero included, because this is [`Prng::uint64n`] of the same
    /// bound, and Go's two functions agree draw for draw whenever the
    /// bound fits in 32 bits:
    ///
    /// * A power of two, and zero, masks one draw in both (`:62-64`,
    ///   `:106-108`).  `n - 1` fits in 32 bits, so masking the whole
    ///   draw and masking its low half give the same value; for a zero
    ///   bound Go's `uint32(x) & 0xffffffff` is the low half of the
    ///   unconstrained draw `uint64n(0)` returns.
    /// * Otherwise Go's `hi` and `lo1:lo0` are the high word and the low
    ///   64 bits of the 96-bit product `x * n` (`:80-84`), which for
    ///   `n < 2^32` are exactly `Mul64(x, n)`'s high and low words.  Go's
    ///   `lo1 == 0 && lo0 < n` is then `lo < n`, and its
    ///   `uint32(-n64 % n64)` threshold is `Uint64N`'s `-n % n`, which is
    ///   below `n` and so survives the narrowing, so both functions enter
    ///   the rejection loop on the same draws and leave it on the same
    ///   draws (`:85-95`, `:141-146`).
    ///
    /// dcrd computes `Uint32N` from 32-bit halves on every target, the
    /// form `math/rand/v2` keeps for 32-bit machines only.  The comment
    /// dcrd inherited with it (`:65-67`) still says 64-bit systems take
    /// the `uint64` code, but dcrd's `Uint32N` has no `is32bit` branch:
    /// that constant is read only by `Uint64N` (`:99`, `:103`).  One
    /// 128-bit product gives the same high word and low 64 bits as the
    /// halves, so this port spells it that way, and the oracle
    /// differential (`tests/rand_oracle_differential.rs`) runs dcrd's
    /// halves directly, whatever the oracle host's word size.
    pub fn uint32n(&mut self, n: u32) -> u32 {
        // Below `n`, or for a zero bound the low half of the draw, so the
        // narrowing is exact; see the doc comment.
        self.uint64n(u64::from(n)) as u32
    }

    /// A random non-negative `i32`, 31 uniform bits (dcrd `PRNG.Int32`,
    /// `crypto/rand/uniform.go:152-154`): the low 31 bits of a four-byte
    /// [`Prng::uint32`] draw.
    pub fn int32(&mut self) -> i32 {
        (self.uint32() & 0x7fff_ffff) as i32
    }

    /// A uniform random `i32` in `[0, n)` without modulo bias (dcrd
    /// `PRNG.Int32N`, `crypto/rand/uniform.go:159-164`): Go's
    /// `int32(p.Uint32N(uint32(n)))`.
    ///
    /// # Panics
    ///
    /// For `n <= 0`, with dcrd's message, before anything is drawn
    /// (`:160-162`), as [`Prng::int_n`] and [`Prng::duration`] do for
    /// their bounds.  A caller that cannot rule such a bound out checks
    /// it first, as a caller of dcrd's must.
    pub fn int32n(&mut self, n: i32) -> i32 {
        assert!(n > 0, "rand: invalid argument to Int32N");
        // `n` is positive, so it converts to `u32` exactly, and the draw,
        // being below it, converts back exactly.
        self.uint32n(n as u32) as i32
    }

    /// A random non-negative `i64`, 63 uniform bits (dcrd `PRNG.Int64`,
    /// `crypto/rand/uniform.go:168-170`): the low 63 bits of a
    /// [`Prng::uint64`] draw.
    pub fn int64(&mut self) -> i64 {
        (self.uint64() & 0x7fff_ffff_ffff_ffff) as i64
    }

    /// A uniform random `i64` in `[0, n)` without modulo bias (dcrd
    /// `PRNG.Int64N`, `crypto/rand/uniform.go:175-180`): Go's
    /// `int64(p.Uint64N(uint64(n)))`.
    ///
    /// # Panics
    ///
    /// For `n <= 0`, with dcrd's message, before anything is drawn
    /// (`:176-178`).
    pub fn int64n(&mut self, n: i64) -> i64 {
        assert!(n > 0, "rand: invalid argument to Int64N");
        // As in `int32n`: positive, so both conversions are exact.
        self.uint64n(n as u64) as i64
    }

    /// A random non-negative `isize`, uniform in every bit of the word
    /// but the sign (dcrd `PRNG.Int`, `crypto/rand/uniform.go:183-185`).
    ///
    /// Go's `int(uint(p.Uint64()) << 1 >> 1)` narrows the draw to the
    /// machine word before clearing its top bit, so a 32-bit target keeps
    /// 31 bits of the draw's low half and a 64-bit one 63 bits; `usize`
    /// and `isize` are Go's `uint` and `int` in that respect.  One
    /// eight-byte draw is consumed on both, as in Go.
    pub fn int(&mut self) -> isize {
        ((self.uint64() as usize) << 1 >> 1) as isize
    }

    /// A uniform random `usize` in `[0, n)` without modulo bias (dcrd
    /// `PRNG.UintN`, `crypto/rand/uniform.go:198-200`): Go's
    /// `uint(p.Uint64N(uint64(n)))`.
    ///
    /// Unlike the signed forms this has no guard, as Go's has none: a
    /// zero bound takes [`Prng::uint64n`]'s mask branch and yields an
    /// unconstrained draw narrowed to the word.
    pub fn uint_n(&mut self, n: usize) -> usize {
        // Below `n` for a nonzero bound; for a zero one, Go's `uint()`
        // conversion of the whole draw, which this cast is.
        self.uint64n(n as u64) as usize
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
    /// `n < 0` panic (`uniform.go:215-217`) has no counterpart, because
    /// a slice length cannot be negative.
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

/// XOR `buf` with the process-wide generator's keystream (dcrd
/// `rand.Read`, `crypto/rand/default.go:22-26`).
///
/// One lock acquisition covers the whole buffer, as dcrd's does -- its
/// comment at `:24` says so explicitly.  Like every `Read` in this
/// module it XORs rather than fills (see QK-0012); dcrd's callers pass
/// a freshly allocated slice, so the two coincide, and a caller here
/// wanting bytes passes a zeroed buffer for the same reason.
pub fn read(buf: &mut [u8]) {
    locked().read(buf);
}

/// A uniform random `u64` from the process-wide generator (dcrd
/// `rand.Uint64`, `crypto/rand/default.go:37-42`).
pub fn uint64() -> u64 {
    locked().uint64()
}

/// A uniform random `u32` from the process-wide generator (dcrd
/// `rand.Uint32`, `crypto/rand/default.go:29-34`).
pub fn uint32() -> u32 {
    locked().uint32()
}

/// A uniform random `u32` in `[0, n)` from the process-wide generator
/// (dcrd `rand.Uint32N`, `crypto/rand/default.go:45-50`).
///
/// The lock is held across every draw of the call, rejected ones
/// included, as dcrd holds it, so no other thread's draw can fall
/// between two draws of one reduction.
pub fn uint32n(n: u32) -> u32 {
    locked().uint32n(n)
}

/// A uniform random `u64` in `[0, n)` from the process-wide generator
/// (dcrd `rand.Uint64N`, `crypto/rand/default.go:53-58`), the lock held
/// for the whole call.
pub fn uint64n(n: u64) -> u64 {
    locked().uint64n(n)
}

/// A random non-negative `i32` from the process-wide generator (dcrd
/// `rand.Int32`, `crypto/rand/default.go:62-67`).
pub fn int32() -> i32 {
    locked().int32()
}

/// A uniform random `i32` in `[0, n)` from the process-wide generator
/// (dcrd `rand.Int32N`, `crypto/rand/default.go:72-77`), the lock held
/// for the whole call.
///
/// # Panics
///
/// For `n <= 0`, as [`Prng::int32n`] does.
pub fn int32n(n: i32) -> i32 {
    locked().int32n(n)
}

/// A random non-negative `i64` from the process-wide generator (dcrd
/// `rand.Int64`, `crypto/rand/default.go:81-86`).
pub fn int64() -> i64 {
    locked().int64()
}

/// A uniform random `i64` in `[0, n)` from the process-wide generator
/// (dcrd `rand.Int64N`, `crypto/rand/default.go:91-96`), the lock held
/// for the whole call.
///
/// # Panics
///
/// For `n <= 0`, as [`Prng::int64n`] does.
pub fn int64n(n: i64) -> i64 {
    locked().int64n(n)
}

/// A random non-negative `isize` from the process-wide generator (dcrd
/// `rand.Int`, `crypto/rand/default.go:99-104`).
pub fn int() -> isize {
    locked().int()
}

/// A uniform random `usize` in `[0, n)` from the process-wide generator
/// (dcrd `rand.UintN`, `crypto/rand/default.go:117-122`), the lock held
/// for the whole call.
pub fn uint_n(n: usize) -> usize {
    locked().uint_n(n)
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

#[cfg(test)]
mod tests {
    use super::{Prng, locked};

    /// Each process-wide function is one call of the matching [`Prng`]
    /// method on the global generator, as each of dcrd's `default.go`
    /// entry points is one `globalRand` method call under the lock: the
    /// global, keyed as a twin `Prng::from_seed` is, gives the twin's
    /// value from every function and leaves both streams at the same
    /// place, which the eight-byte draw after each call pins.  A function
    /// that drew a different width, reduced by modulo or post-processed
    /// the method's answer would part the two.
    ///
    /// This is the only test in the crate's library that touches the
    /// global, so nothing else draws from it between the calls; the
    /// integration tests run in processes of their own.
    #[test]
    fn the_global_functions_are_the_prng_methods() {
        let seed = [0x5a; 32];
        *locked() = Prng::from_seed(seed);
        let mut twin = Prng::from_seed(seed);
        let step = |what: &str, global: u64, method: u64, twin: &mut Prng| {
            assert_eq!(global, method, "{what}");
            assert_eq!(super::uint64(), twin.uint64(), "stream after {what}");
        };
        // Bounds that reject now and then (just above a power of two,
        // and near the top of the range) as well as plain ones.
        let bounds32 = [1, 2, 3, 7, 1 << 20, (1 << 31) + 1, u32::MAX - 1];
        let bounds64 = [1, 3, 1 << 40, (1 << 63) + 1, u64::MAX];
        for _ in 0..16 {
            step("uint64", super::uint64(), twin.uint64(), &mut twin);
            step(
                "uint32",
                super::uint32().into(),
                twin.uint32().into(),
                &mut twin,
            );
            step(
                "int32",
                super::int32() as u64,
                twin.int32() as u64,
                &mut twin,
            );
            step(
                "int64",
                super::int64() as u64,
                twin.int64() as u64,
                &mut twin,
            );
            step("int", super::int() as u64, twin.int() as u64, &mut twin);
            for n in bounds32 {
                let g = super::uint32n(n).into();
                step("uint32n", g, twin.uint32n(n).into(), &mut twin);
                let n = (n >> 1).max(1) as i32;
                let g = super::int32n(n) as u64;
                step("int32n", g, twin.int32n(n) as u64, &mut twin);
            }
            for n in bounds64 {
                step("uint64n", super::uint64n(n), twin.uint64n(n), &mut twin);
                let n = (n >> 1).max(1) as i64;
                let g = super::int64n(n) as u64;
                step("int64n", g, twin.int64n(n) as u64, &mut twin);
                let g = super::duration(n) as u64;
                step("duration", g, twin.duration(n) as u64, &mut twin);
                let n = n as usize;
                let g = super::uint_n(n) as u64;
                step("uint_n", g, twin.uint_n(n) as u64, &mut twin);
                let g = super::int_n(n) as u64;
                step("int_n", g, twin.int_n(n) as u64, &mut twin);
            }
            let (mut a, mut b) = ([0u8; 37], [0u8; 37]);
            super::read(&mut a);
            twin.read(&mut b);
            assert_eq!(a, b, "read");
            let (mut a, mut b) = ([0u16; 40], [0u16; 40]);
            for (i, (x, y)) in a.iter_mut().zip(b.iter_mut()).enumerate() {
                (*x, *y) = (i as u16, i as u16);
            }
            super::shuffle_slice(&mut a);
            twin.shuffle(&mut b);
            assert_eq!(a, b, "shuffle_slice");
            step("after read and shuffle", 0, 0, &mut twin);
        }
    }
}
