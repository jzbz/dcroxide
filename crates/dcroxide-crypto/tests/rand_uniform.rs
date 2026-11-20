// SPDX-License-Identifier: ISC
//! `uniform.go`'s reductions: dcrd's arithmetic, not merely dcrd's
//! distribution.
//!
//! Every test writes dcrd's loop out longhand over a second generator
//! from the same seed and compares exactly, because the difference
//! between Lemire and any other unbiased reduction is invisible to a
//! sampling test — the bias it would detect is one part in 2^54 at
//! realistic bounds — but shows up in the first drawn value.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_crypto::rand::Prng;

mod common;

/// dcrd's `Uint64N` written out longhand (`crypto/rand/uniform.go:102-148`).
fn dcrd_uint64n(p: &mut Prng, n: u64) -> u64 {
    if n & n.wrapping_sub(1) == 0 {
        return p.uint64() & n.wrapping_sub(1);
    }
    let wide = |x: u64| -> (u64, u64) {
        let w = u128::from(x).wrapping_mul(u128::from(n));
        ((w >> 64) as u64, w as u64)
    };
    let (mut hi, mut lo) = wide(p.uint64());
    if lo < n {
        let thresh = n.wrapping_neg() % n;
        while lo < thresh {
            let next = wide(p.uint64());
            hi = next.0;
            lo = next.1;
        }
    }
    hi
}

/// `uint64n` is Lemire's reduction, value for value.
///
/// A modulo reduction over the same stream gives a different answer for
/// almost every bound, so this discriminates the two rather than merely
/// asserting the result is in range.
#[test]
fn uint64n_is_dcrds_multiply_shift() {
    let seed = [17u8; 32];
    let mut got = Prng::from_seed(seed);
    let mut want = Prng::from_seed(seed);
    let mut modulo = Prng::from_seed(seed);

    let mut differed_from_modulo = 0;
    for n in [3u64, 5, 7, 10, 100, 1000, 2499, 65535, u64::MAX / 3] {
        let g = got.uint64n(n);
        let w = dcrd_uint64n(&mut want, n);
        assert_eq!(g, w, "bound {n} must match dcrd's reduction exactly");
        assert!(g < n, "bound {n} must stay in range");
        if modulo.uint64() % n != g {
            differed_from_modulo += 1;
        }
    }
    assert!(
        differed_from_modulo > 0,
        "the test must be able to tell Lemire from a modulo reduction"
    );
}

/// A power-of-two bound masks, and a zero bound is unconstrained.
///
/// Go takes the same branch for both, because `0 & (0 - 1)` is
/// `u64::MAX` (`uniform.go:106-108`). The zero case is reachable
/// upstream from the connection manager's single-nanosecond backoff, so
/// it is reproduced rather than asserted away.
#[test]
fn power_of_two_and_zero_bounds_take_dcrds_mask_branch() {
    let seed = [19u8; 32];
    let mut got = Prng::from_seed(seed);
    let mut want = Prng::from_seed(seed);

    for n in [1u64, 2, 8, 1024, 1 << 40] {
        assert_eq!(got.uint64n(n), want.uint64() & (n - 1), "bound {n} masks");
    }
    // A zero bound consumes exactly one draw and constrains nothing.
    assert_eq!(got.uint64n(0), want.uint64());
}

/// `shuffle` is dcrd's Fisher-Yates over dcrd's reduction.
///
/// Written out longhand against a second generator: descending from
/// `n - 1`, drawing `uint64n(i + 1)`, swapping `i` with `j`
/// (`uniform.go:225-228`). The final assertion pins the stream
/// position, which is what separates a streamed shuffle from one
/// reading the kernel per swap — a `getrandom` shuffle consumes none of
/// the generator's bytes.
#[test]
fn shuffle_is_dcrds_fisher_yates_over_its_own_reduction() {
    let seed = [23u8; 32];
    let mut got = Prng::from_seed(seed);
    let mut want = Prng::from_seed(seed);

    let mut a: Vec<u32> = (0..64).collect();
    let mut b = a.clone();

    got.shuffle(&mut a);
    for i in (1..b.len()).rev() {
        let j = dcrd_uint64n(&mut want, (i as u64) + 1) as usize;
        b.swap(i, j);
    }
    assert_eq!(a, b, "the permutation must be dcrd's, element for element");

    // A permutation, not a corruption.
    let mut sorted = a.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, (0..64).collect::<Vec<u32>>());

    assert_eq!(
        got.uint64(),
        want.uint64(),
        "the shuffle must consume exactly dcrd's draws from the stream"
    );
}

/// `int_n` is `uint64n` with dcrd's positive-argument guard.
///
/// The mining-address pick reduced a full-width draw by modulo before
/// this; replaying that over the same stream shows the two are
/// distinguishable, which is what makes the conversion a bias fix
/// rather than a rename.
#[test]
fn int_n_is_dcrds_reduction_not_a_modulo() {
    let seed = [37u8; 32];
    let mut got = Prng::from_seed(seed);
    let mut want = Prng::from_seed(seed);
    let mut modulo = Prng::from_seed(seed);

    let mut differed = 0;
    for n in [1usize, 2, 3, 7, 10, 100, 1000] {
        let g = got.int_n(n);
        assert_eq!(g, dcrd_uint64n(&mut want, n as u64) as usize);
        assert!(g < n, "index {g} must be below {n}");
        if (modulo.uint64() % (n as u64)) as usize != g {
            differed += 1;
        }
    }
    assert!(
        differed > 0,
        "the test must be able to tell dcrd's reduction from a modulo"
    );
}

/// A zero bound panics with dcrd's message (`uniform.go:191-193`).
#[test]
#[should_panic(expected = "rand: invalid argument to IntN")]
fn int_n_rejects_a_zero_bound_as_dcrd_does() {
    Prng::from_seed([41u8; 32]).int_n(0);
}

/// `duration` is `uint64n` in nanoseconds, with dcrd's guard.
///
/// The seeder's backdating reduced by modulo over four days in
/// nanoseconds before this, a bias near one part in 2^16 — big enough
/// that the two disagree on the very first draw, which is what this
/// asserts rather than sampling for skew.
#[test]
fn duration_is_dcrds_reduction_not_a_modulo() {
    const FOUR_DAYS_NANOS: i64 = 4 * 24 * 60 * 60 * 1_000_000_000;
    let seed = [43u8; 32];
    let mut got = Prng::from_seed(seed);
    let mut want = Prng::from_seed(seed);
    let mut modulo = Prng::from_seed(seed);

    let d = got.duration(FOUR_DAYS_NANOS);
    assert_eq!(d, dcrd_uint64n(&mut want, FOUR_DAYS_NANOS as u64) as i64);
    assert!(
        (0..FOUR_DAYS_NANOS).contains(&d),
        "{d} must fall inside the four-day window"
    );
    assert_ne!(
        d,
        (modulo.uint64() % (FOUR_DAYS_NANOS as u64)) as i64,
        "dcrd's reduction and the modulo it replaced must be distinguishable"
    );
}

/// A non-positive bound panics with dcrd's message
/// (`uniform.go:203-205`), where the port used to coerce it to one.
#[test]
#[should_panic(expected = "rand: invalid argument to Duration")]
fn duration_rejects_a_non_positive_bound_as_dcrd_does() {
    Prng::from_seed([47u8; 32]).duration(0);
}

/// The old modulo shuffle produced a different permutation.
///
/// The daemon's peer environment reduced a full-width draw by modulo
/// before this change. Replaying that loop over the same stream pins
/// the closed divergence closed: if `shuffle` ever went back to a
/// modulo, this test would stop distinguishing them.
#[test]
fn the_replaced_modulo_shuffle_gave_a_different_permutation() {
    let seed = [29u8; 32];
    let mut got = Prng::from_seed(seed);
    let mut old = Prng::from_seed(seed);

    let mut a: Vec<u32> = (0..64).collect();
    let mut b = a.clone();

    got.shuffle(&mut a);
    for i in (1..b.len()).rev() {
        let j = (old.uint64() % ((i as u64) + 1)) as usize;
        b.swap(i, j);
    }
    assert_ne!(
        a, b,
        "dcrd's reduction and the modulo it replaced must be distinguishable"
    );
}

/// dcrd's `Uint32N` written out longhand over a draw source, 32-bit
/// halves and all (`crypto/rand/uniform.go:61-97`), as dcrd runs it on
/// every target: its `Uint32N` has no `is32bit` branch, whatever the
/// comment it inherited from `math/rand/v2` at `:65-67` says.
fn dcrd_uint32n_32bit(mut next: impl FnMut() -> u64, n: u32) -> u32 {
    if n & n.wrapping_sub(1) == 0 {
        return (next() as u32) & n.wrapping_sub(1);
    }
    let mul32 = |x: u32, y: u32| {
        let p = u64::from(x) * u64::from(y);
        ((p >> 32) as u32, p as u32)
    };
    let product = |x: u64| {
        let (lo1a, lo0) = mul32(x as u32, n);
        let (hi, lo1b) = mul32((x >> 32) as u32, n);
        let (lo1, c) = lo1a.overflowing_add(lo1b);
        (hi + u32::from(c), lo1, lo0)
    };
    let (mut hi, mut lo1, mut lo0) = product(next());
    if lo1 == 0 && lo0 < n {
        let n64 = u64::from(n);
        let thresh = (n64.wrapping_neg() % n64) as u32;
        while lo1 == 0 && lo0 < thresh {
            (hi, lo1, lo0) = product(next());
        }
    }
    hi
}

/// `uint32n` is dcrd's `Uint32N`: the 32-bit form written out, over a
/// second generator from the same seed, gives the same values and leaves
/// the stream at the same place.
#[test]
fn uint32n_is_dcrds_32_bit_reduction() {
    let seed = [53u8; 32];
    let mut got = Prng::from_seed(seed);
    let mut want = Prng::from_seed(seed);
    for n in [
        0u32,
        1,
        2,
        3,
        5,
        7,
        1000,
        1 << 31,
        (1 << 31) - 1,
        (1 << 31) + 1,
        u32::MAX,
        u32::MAX - 1,
        0x5555_5555,
    ] {
        for _ in 0..200 {
            assert_eq!(
                got.uint32n(n),
                dcrd_uint32n_32bit(|| want.uint64(), n),
                "bound {n}"
            );
        }
    }
    assert_eq!(got.uint64(), want.uint64(), "the same draws were consumed");
}

/// On seeds whose first draw Go's `Uint32N` rejects, `uint32n` consumes
/// a second draw and returns what the 32-bit form returns; on seeds whose
/// first draw it tests and keeps, it consumes one.  A random seed reaches
/// the test with probability below 2^-32; `common::reduction_edge_cases`
/// finds such seeds through the continued fraction of the first draw.
#[test]
fn uint32n_takes_dcrds_rejection_branch() {
    for (rejected, draws) in [(true, 2), (false, 1)] {
        for (seed, n) in common::reduction_edge_cases(8, 1 << 32, rejected) {
            let mut got = Prng::from_seed(seed);
            let mut want = Prng::from_seed(seed);
            let mut taken = 0;
            let value = dcrd_uint32n_32bit(
                || {
                    taken += 1;
                    want.uint64()
                },
                n,
            );
            assert_eq!(taken, draws, "bound {n} (rejected: {rejected})");
            assert_eq!(got.uint32n(n), value, "bound {n} (rejected: {rejected})");
            assert_eq!(got.uint64(), want.uint64(), "bound {n}: stream position");
        }
    }
}

/// Go's 32-bit `Uint32N` and its 64-bit `Uint64N` agree draw for draw on
/// every 32-bit bound, which is the argument `Prng::uint32n` rests on.
/// Checked here on scripted draws, where the rejection loop can be driven
/// as often as wanted: draws rejected once and twice, the draw exactly at
/// the threshold (tested and kept), and uniform draws.
#[test]
fn the_32_and_64_bit_reductions_agree_on_scripted_draws() {
    // The inverse of odd `n` modulo 2^64, by Newton's iteration.
    let inverse = |n: u64| {
        let mut inv = n;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(n.wrapping_mul(inv)));
        }
        assert_eq!(n.wrapping_mul(inv), 1);
        inv
    };
    let run64 = |draws: &[u64], n: u32| {
        let mut i = 0;
        let mut next = || {
            i += 1;
            draws[i - 1]
        };
        let n = u64::from(n);
        let value = if n & n.wrapping_sub(1) == 0 {
            next() & n.wrapping_sub(1)
        } else {
            let wide = |x: u64| u128::from(x) * u128::from(n);
            let mut p = wide(next());
            if (p as u64) < n {
                let thresh = n.wrapping_neg() % n;
                while (p as u64) < thresh {
                    p = wide(next());
                }
            }
            (p >> 64) as u64
        };
        (value as u32, i)
    };
    let run32 = |draws: &[u64], n: u32| {
        let mut i = 0;
        let value = dcrd_uint32n_32bit(
            || {
                i += 1;
                draws[i - 1]
            },
            n,
        );
        (value, i)
    };

    let mut rng = dcroxide_testutil::SplitMix64(0x3332_6269_7473);
    let mut checked_rejections = 0;
    for n in [
        3u32,
        5,
        7,
        1000,
        0x5555_5555,
        (1 << 31) - 1,
        (1 << 31) + 1,
        u32::MAX,
        u32::MAX - 2,
        0,
        1,
        1 << 20,
    ] {
        for _ in 0..500 {
            let draws: Vec<u64> = (0..4).map(|_| rng.next_u64()).collect();
            assert_eq!(run32(&draws, n), run64(&draws, n), "bound {n}");
        }
        if n & n.wrapping_sub(1) == 0 || n % 2 == 0 {
            continue;
        }
        let n64 = u64::from(n);
        let thresh = n64.wrapping_neg() % n64;
        if thresh == 0 {
            continue;
        }
        // Rejected draws: zero, and the draw whose product's low half is
        // `thresh - 1`.  Then the draw at `thresh`, kept after one draw.
        let below = (thresh - 1).wrapping_mul(inverse(n64));
        let at = thresh.wrapping_mul(inverse(n64));
        for draws in [
            vec![0, rng.next_u64(), rng.next_u64()],
            vec![below, 0, rng.next_u64()],
            vec![below, below, rng.next_u64()],
            vec![at, 0, 0],
        ] {
            let got = run32(&draws, n);
            assert_eq!(got, run64(&draws, n), "bound {n}, draws {draws:x?}");
            if got.1 > 1 {
                checked_rejections += 1;
            }
        }
    }
    assert!(checked_rejections > 0);
}

/// `uint32` and `int32` read four stream bytes, not eight, as dcrd's
/// `Uint32` does (`uniform.go:47-51`): two of them consume one `uint64`.
#[test]
fn uint32_and_int32_draw_four_bytes() {
    let seed = [59u8; 32];
    let mut got = Prng::from_seed(seed);
    let mut want = Prng::from_seed(seed);
    let x = want.uint64();
    assert_eq!(got.uint32(), x as u32);
    assert_eq!(got.int32(), ((x >> 32) as u32 & 0x7fff_ffff) as i32);
    assert_eq!(got.uint64(), want.uint64());
}

/// `int64` keeps 63 bits of a draw and `int` the word less its sign bit;
/// each consumes eight bytes.
#[test]
fn int64_and_int_mask_one_draw() {
    let seed = [61u8; 32];
    let mut got = Prng::from_seed(seed);
    let mut want = Prng::from_seed(seed);
    for _ in 0..64 {
        assert_eq!(got.int64(), (want.uint64() & (u64::MAX >> 1)) as i64);
        let w = want.uint64() as usize;
        assert_eq!(got.int(), (w << 1 >> 1) as isize);
        assert!(got.int() >= 0);
        want.uint64();
    }
}

/// `int32n` and `int64n` reduce as `uint32n` and `uint64n` do, and
/// `uint_n` is `uint64n` of the word.
#[test]
fn bounded_signed_and_word_draws_are_the_unsigned_reductions() {
    let seed = [67u8; 32];
    let mut got = Prng::from_seed(seed);
    let mut want = Prng::from_seed(seed);
    for n in [1i32, 2, 3, 1000, i32::MAX] {
        assert_eq!(got.int32n(n), want.uint32n(n as u32) as i32);
    }
    for n in [1i64, 3, 1 << 40, i64::MAX] {
        assert_eq!(got.int64n(n), want.uint64n(n as u64) as i64);
    }
    for n in [0usize, 1, 7, usize::MAX] {
        assert_eq!(got.uint_n(n), want.uint64n(n as u64) as usize);
    }
    assert_eq!(got.uint64(), want.uint64());
}

/// Non-positive bounds panic with dcrd's messages before drawing
/// (`uniform.go:160-162`, `:176-178`).
#[test]
#[should_panic(expected = "rand: invalid argument to Int32N")]
fn int32n_rejects_a_non_positive_bound_as_dcrd_does() {
    Prng::from_seed([71u8; 32]).int32n(-5);
}

/// See `int32n_rejects_a_non_positive_bound_as_dcrd_does`.
#[test]
#[should_panic(expected = "rand: invalid argument to Int64N")]
fn int64n_rejects_a_non_positive_bound_as_dcrd_does() {
    Prng::from_seed([73u8; 32]).int64n(0);
}

/// The process-wide functions answer within their bounds; the lock is
/// held for the whole call, which no single-threaded test can observe,
/// so this checks only that each reaches the generator.
#[test]
fn the_global_functions_draw_within_their_bounds() {
    use dcroxide_crypto::rand;
    for _ in 0..100 {
        assert!(rand::uint32n(7) < 7);
        assert!(rand::uint64n(1 << 40) < 1 << 40);
        assert!((0..9).contains(&rand::int32n(9)));
        assert!((0..9).contains(&rand::int64n(9)));
        assert!(rand::int32() >= 0);
        assert!(rand::int64() >= 0);
        assert!(rand::int() >= 0);
        assert!(rand::uint_n(3) < 3);
        let _ = rand::uint32();
    }
}
