// SPDX-License-Identifier: ISC
//! Shared by the `crypto/rand` tests: the operations dcrd's `PRNG`
//! exposes, run on dcroxide's `Prng` and rendered as the oracle's
//! `rand_draws` renders them, and the seeds whose first draw takes the
//! rejection branch of a 32-bit reduction.

// Test-harness arithmetic over bounded values.
#![allow(clippy::arithmetic_side_effects, dead_code)]

use std::fmt::Write as _;
use std::panic::{AssertUnwindSafe, catch_unwind};

use dcroxide_crypto::rand::Prng;

/// One `rand_draws` operation: the code byte `tools/oracle/cryptorand.go`
/// gives the dcrd method, and its argument.
#[derive(Clone, Copy, Debug)]
pub struct Op {
    /// The method's code.
    pub code: u8,
    /// Its argument, which methods without a bound ignore.
    pub arg: u64,
}

/// `PRNG.Uint32`.
pub const UINT32: u8 = 1;
/// `PRNG.Uint64`.
pub const UINT64: u8 = 2;
/// `PRNG.Uint32N(uint32(arg))`.
pub const UINT32N: u8 = 3;
/// `PRNG.Uint64N(arg)`.
pub const UINT64N: u8 = 4;
/// `PRNG.Int32`.
pub const INT32: u8 = 5;
/// `PRNG.Int32N(int32(arg))`.
pub const INT32N: u8 = 6;
/// `PRNG.Int64`.
pub const INT64: u8 = 7;
/// `PRNG.Int64N(int64(arg))`.
pub const INT64N: u8 = 8;
/// `PRNG.Int`.
pub const INT: u8 = 9;
/// `PRNG.IntN(int(arg))`; the tests pass only arguments below 2^63,
/// since `Prng::int_n` takes a `usize` and a negative bound has no
/// counterpart.
pub const INTN: u8 = 10;
/// `PRNG.UintN(uint(arg))`.
pub const UINTN: u8 = 11;
/// `PRNG.Duration(time.Duration(arg))`.
pub const DURATION: u8 = 12;
/// `PRNG.Read` of `arg` bytes.
pub const READ: u8 = 13;

/// The `rand_draws` request for `seed` and `ops`.
pub fn request(seed: &[u8; 32], ops: &[Op]) -> Vec<u8> {
    let mut req = seed.to_vec();
    for op in ops {
        req.push(op.code);
        req.extend_from_slice(&op.arg.to_be_bytes());
    }
    req
}

/// The text of a panic's payload.
fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "<non-string panic>".to_owned())
}

/// One operation on `p`, rendered as the oracle renders dcrd's.
fn draw(p: &mut Prng, op: Op) -> String {
    let arg = op.arg;
    let run = |p: &mut Prng| -> String {
        match op.code {
            UINT32 => p.uint32().to_string(),
            UINT64 => p.uint64().to_string(),
            UINT32N => p.uint32n(arg as u32).to_string(),
            UINT64N => p.uint64n(arg).to_string(),
            INT32 => p.int32().to_string(),
            INT32N => p.int32n(arg as u32 as i32).to_string(),
            INT64 => p.int64().to_string(),
            INT64N => p.int64n(arg as i64).to_string(),
            INT => p.int().to_string(),
            INTN => {
                assert!(arg < 1 << 63, "a negative IntN bound has no counterpart");
                p.int_n(arg as usize).to_string()
            }
            UINTN => p.uint_n(arg as usize).to_string(),
            DURATION => p.duration(arg as i64).to_string(),
            READ => {
                let mut buf = vec![0u8; arg as usize];
                p.read(&mut buf);
                buf.iter().fold(String::new(), |mut s, b| {
                    let _ = write!(s, "{b:02x}");
                    s
                })
            }
            code => panic!("unknown operation {code}"),
        }
    };
    match catch_unwind(AssertUnwindSafe(|| run(p))) {
        Ok(out) => out,
        Err(payload) => format!("panic: {}", panic_text(&*payload)),
    }
}

/// dcroxide's answer to a `rand_draws` request: one line per operation,
/// then `next=` and one more `uint64`.
pub fn ours(seed: &[u8; 32], ops: &[Op]) -> String {
    let mut p = Prng::from_seed(*seed);
    let mut out = String::new();
    for &op in ops {
        out.push_str(&draw(&mut p, op));
        out.push('\n');
    }
    let _ = write!(out, "next={}", p.uint64());
    out
}

/// The 32-byte seed numbered `i`: `i` little-endian, then zeros.
pub fn numbered_seed(i: u64) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&i.to_le_bytes());
    seed
}

/// Whether Go's 32-bit `Uint32N(n)` enters its rejection test on the draw
/// `x` (`lo < n`), and whether it then rejects it (`lo < 2^64 mod n`).
pub fn enters_and_rejects(x: u64, n: u32) -> (bool, bool) {
    if n & n.wrapping_sub(1) == 0 {
        return (false, false);
    }
    let n = u64::from(n);
    let lo = x.wrapping_mul(n);
    (lo < n, lo < n.wrapping_neg() % n)
}

/// Bounds below `limit` for which the draw `x` enters the rejection test
/// of a 32-bit reduction: denominators of the best rational
/// approximations of `x / 2^64` (the convergents and the semiconvergents
/// between them) and their small multiples, kept where the condition
/// holds.  `x * n mod 2^64` is below `n` only when `n * x / 2^64` lies
/// within `n / 2^64` above an integer, and the best approximations are
/// where such `n` are found; the condition is checked directly, so the
/// search cannot report a bound that does not qualify.
pub fn entering_bounds(x: u64, limit: u64) -> Vec<u32> {
    let mut found = std::collections::BTreeSet::new();
    let (mut num, mut den) = (u128::from(x), 1u128 << 64);
    let (mut q_prev2, mut q_prev1) = (1u128, 0u128);
    while den != 0 {
        let a = num / den;
        (num, den) = (den, num - a * den);
        for j in 1..=a.min(4096) {
            let s = j * q_prev1 + q_prev2;
            if s == 0 || s >= u128::from(limit) {
                continue;
            }
            for m in 1..=64u128 {
                let n = m * s;
                if n < u128::from(limit) && enters_and_rejects(x, n as u32).0 {
                    found.insert(n as u32);
                }
            }
        }
        let q = a * q_prev1 + q_prev2;
        if q >= u128::from(limit) {
            break;
        }
        (q_prev2, q_prev1) = (q_prev1, q);
    }
    found.into_iter().collect()
}

/// The first `want` cases, by seed number, whose first draw a 32-bit
/// reduction below `limit` rejects (`rejected` true) or tests and accepts
/// (`rejected` false): (seed, bound) pairs, one bound per seed.
pub fn reduction_edge_cases(want: usize, limit: u64, rejected: bool) -> Vec<([u8; 32], u32)> {
    let mut out = Vec::new();
    for i in 0..1_000_000u64 {
        if out.len() == want {
            break;
        }
        let seed = numbered_seed(i);
        let x = Prng::from_seed(seed).uint64();
        if let Some(&n) = entering_bounds(x, limit)
            .iter()
            .find(|&&n| enters_and_rejects(x, n).1 == rejected)
        {
            out.push((seed, n));
        }
    }
    assert_eq!(
        out.len(),
        want,
        "the search must find every case it is asked for"
    );
    out
}
