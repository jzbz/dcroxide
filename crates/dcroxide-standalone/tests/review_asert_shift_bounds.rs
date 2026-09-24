// SPDX-License-Identifier: ISC
//! The port's ASERT calculation takes the clamp directly once the shift
//! count reaches 8192 in either direction, where dcrd always shifts and
//! then clamps (`blockchain/standalone/pow.go` `CalcASERTDiff`).  The
//! frozen vectors only reach shifts in [-240, 256] and the oracle
//! differential draws offsets within 20 half-lives, so nothing else
//! drives either early return.  Simnet and regnet reach the positive one
//! whenever the chain runs about 13.7 hours behind schedule.
//!
//! Every expected value below came from dcrd's `CalcASERTDiff` at the
//! parity pin (b9634e01), fed the same arguments.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_chaincfg::{Params, mainnet_params, regnet_params, simnet_params, testnet3_params};
use dcroxide_standalone::{BigInt, Sign, calc_asert_diff};
use dcroxide_testutil::{SplitMix64, oracle_or_skip};

/// The height delta every row uses.
const HEIGHT_DELTA: i64 = 1000;

fn pow_limit(params: &Params) -> BigInt {
    BigInt::from_bytes_be(Sign::Plus, &params.pow_limit.to_be_bytes())
}

/// The time delta whose exponent has integer part `shifts + 16` (so the
/// shift left after the `-16` fold is exactly `shifts`) plus `rem`
/// seconds of fractional part.
fn time_delta_for(target_secs: i64, half_life: i64, shifts: i64, rem: i64) -> i64 {
    HEIGHT_DELTA * target_secs + (shifts + 16) * half_life + rem
}

/// Mainnet and simnet from their DCP0011 start bits, on both sides of
/// both bounds, with and without a fractional exponent.  dcrd returns
/// the network limit for every positive row and 1 for every negative
/// row: the whole of each shortcut's claim.
#[test]
fn asert_shift_shortcut_matches_dcrd_on_real_networks() {
    for params in [mainnet_params(), simnet_params()] {
        let limit = pow_limit(&params);
        let target = params.target_time_per_block_secs;
        let half_life = params.work_diff_v2_half_life_secs;
        let start = params.work_diff_v2_blake3_start_bits;
        for shifts in [
            8190, 8191, 8192, 8193, 8194, -8190, -8191, -8192, -8193, -8194,
        ] {
            let want = if shifts > 0 {
                params.pow_limit_bits
            } else {
                0x0101_0000
            };
            for rem in [0, half_life / 2] {
                let dt = time_delta_for(target, half_life, shifts, rem);
                let got = calc_asert_diff(start, &limit, target, dt, HEIGHT_DELTA, half_life);
                assert_eq!(
                    got, want,
                    "{}: shifts={shifts} rem={rem} dt={dt}: got {got:08x}, want {want:08x}",
                    params.name
                );
            }
        }
    }
}

/// The positive shortcut is only sound while the limit is below 2^8208,
/// the least value a 8192-bit shift can produce.  dcrd takes no such
/// shortcut, so past that bound the port must shift like dcrd does:
/// at 2^8209 - 1 a starting difficulty of 1 shifted by 8192 is 2^8208,
/// under the limit, and dcrd returns it rather than the limit.
#[test]
fn asert_shift_shortcut_is_exact_for_oversized_limits() {
    // (limit bit length, start bits, shifts, dcrd result) with a 1s
    // target, a 6s half life and no fractional exponent.
    const ROWS: [(u64, u32, i64, u32); 48] = [
        (8207, 0x01010000, 8190, 0x02400000),
        (8207, 0x01010000, 8191, 0x027fffff),
        (8207, 0x01010000, 8192, 0x027fffff),
        (8207, 0x01010000, 8193, 0x027fffff),
        (8207, 0x01010000, 8194, 0x027fffff),
        (8207, 0x01010000, 8250, 0x027fffff),
        (8207, 0x1d00ffff, 8190, 0x027fffff),
        (8207, 0x1d00ffff, 8191, 0x027fffff),
        (8207, 0x1d00ffff, 8192, 0x027fffff),
        (8207, 0x1d00ffff, 8193, 0x027fffff),
        (8207, 0x1d00ffff, 8194, 0x027fffff),
        (8207, 0x1d00ffff, 8250, 0x027fffff),
        (8208, 0x01010000, 8190, 0x02400000),
        (8208, 0x01010000, 8191, 0x03008000),
        (8208, 0x01010000, 8192, 0x0300ffff),
        (8208, 0x01010000, 8193, 0x0300ffff),
        (8208, 0x01010000, 8194, 0x0300ffff),
        (8208, 0x01010000, 8250, 0x0300ffff),
        (8208, 0x1d00ffff, 8190, 0x0300ffff),
        (8208, 0x1d00ffff, 8191, 0x0300ffff),
        (8208, 0x1d00ffff, 8192, 0x0300ffff),
        (8208, 0x1d00ffff, 8193, 0x0300ffff),
        (8208, 0x1d00ffff, 8194, 0x0300ffff),
        (8208, 0x1d00ffff, 8250, 0x0300ffff),
        (8209, 0x01010000, 8190, 0x02400000),
        (8209, 0x01010000, 8191, 0x03008000),
        (8209, 0x01010000, 8192, 0x03010000),
        (8209, 0x01010000, 8193, 0x0301ffff),
        (8209, 0x01010000, 8194, 0x0301ffff),
        (8209, 0x01010000, 8250, 0x0301ffff),
        (8209, 0x1d00ffff, 8190, 0x0301ffff),
        (8209, 0x1d00ffff, 8191, 0x0301ffff),
        (8209, 0x1d00ffff, 8192, 0x0301ffff),
        (8209, 0x1d00ffff, 8193, 0x0301ffff),
        (8209, 0x1d00ffff, 8194, 0x0301ffff),
        (8209, 0x1d00ffff, 8250, 0x0301ffff),
        (8300, 0x01010000, 8190, 0x02400000),
        (8300, 0x01010000, 8191, 0x03008000),
        (8300, 0x01010000, 8192, 0x03010000),
        (8300, 0x01010000, 8193, 0x03020000),
        (8300, 0x01010000, 8194, 0x03040000),
        (8300, 0x01010000, 8250, 0x0a040000),
        (8300, 0x1d00ffff, 8190, 0x0e0fffff),
        (8300, 0x1d00ffff, 8191, 0x0e0fffff),
        (8300, 0x1d00ffff, 8192, 0x0e0fffff),
        (8300, 0x1d00ffff, 8193, 0x0e0fffff),
        (8300, 0x1d00ffff, 8194, 0x0e0fffff),
        (8300, 0x1d00ffff, 8250, 0x0e0fffff),
    ];
    const TARGET: i64 = 1;
    const HALF_LIFE: i64 = 6;
    for (bits, start, shifts, want) in ROWS {
        let limit = (BigInt::from(1) << bits) - BigInt::from(1);
        let dt = time_delta_for(TARGET, HALF_LIFE, shifts, 0);
        let got = calc_asert_diff(start, &limit, TARGET, dt, HEIGHT_DELTA, HALF_LIFE);
        assert_eq!(
            got, want,
            "limit 2^{bits}-1 start={start:08x} shifts={shifts}: got {got:08x}, want {want:08x}"
        );
    }
}

/// Serialize a non-negative big integer to exactly 32 big-endian bytes.
fn big_to_be32(n: &BigInt) -> [u8; 32] {
    let (_, bytes) = n.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// Live against dcrd across all four networks: the exact boundary shift
/// counts, then random offsets up to 10,000 half lives either side of
/// the schedule, well past both bounds (Go shifts them cheaply).
#[test]
fn asert_far_off_schedule_matches_oracle() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("standalone-asert-shift-bounds");
    let networks = [
        mainnet_params(),
        testnet3_params(),
        simnet_params(),
        regnet_params(),
    ];

    let mut cases: Vec<(usize, i64, i64)> = Vec::new();
    for (net, params) in networks.iter().enumerate() {
        let target = params.target_time_per_block_secs;
        let half_life = params.work_diff_v2_half_life_secs;
        for shifts in [8191, 8192, 8193, -8191, -8192, -8193] {
            for rem in [0, half_life - 1] {
                let dt = time_delta_for(target, half_life, shifts, rem);
                cases.push((net, HEIGHT_DELTA, dt));
            }
        }
    }
    for _ in 0..400 {
        let net = rng.below(networks.len() as u64) as usize;
        let params = &networks[net];
        let half_life = params.work_diff_v2_half_life_secs;
        let height_delta = rng.below(500_000) as i64;
        let ideal = height_delta * params.target_time_per_block_secs;
        let span = half_life * 10_000;
        let offset = rng.below((span * 2) as u64 + 1) as i64 - span;
        cases.push((net, height_delta, ideal.saturating_add(offset)));
    }

    for (net, height_delta, time_delta) in cases {
        let params = &networks[net];
        let limit = pow_limit(params);
        let start_bits = params.work_diff_v2_blake3_start_bits;
        let target_secs = params.target_time_per_block_secs;
        let half_life = params.work_diff_v2_half_life_secs;
        let ours = format!(
            "{:08x}",
            calc_asert_diff(
                start_bits,
                &limit,
                target_secs,
                time_delta,
                height_delta,
                half_life,
            )
        );

        let mut req = Vec::new();
        req.extend_from_slice(&start_bits.to_be_bytes());
        req.extend_from_slice(&big_to_be32(&limit));
        req.extend_from_slice(&(target_secs as u64).to_be_bytes());
        req.extend_from_slice(&(time_delta as u64).to_be_bytes());
        req.extend_from_slice(&(height_delta as u64).to_be_bytes());
        req.extend_from_slice(&(half_life as u64).to_be_bytes());
        let theirs = oracle.call_ok("standalone_asert", &req);

        assert_eq!(
            ours, theirs,
            "ASERT divergence: net={} Δh={height_delta} Δt={time_delta}",
            params.name,
        );
    }
}
