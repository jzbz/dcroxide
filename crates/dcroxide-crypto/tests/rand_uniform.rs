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
