// SPDX-License-Identifier: ISC
//! The CPU miner's proof-of-work solve core, ported from dcrd's
//! `internal/mining/cpuminer` package: the
//! `solveBlock` loop that searches the nonce and extra-nonce space of a
//! block header for a hash below the target difficulty.
//!
//! This is the pure, chain-free heart of the miner.  The surrounding
//! concurrency shell — the worker controller, the speed monitor, the
//! discrete `GenerateNBlocks` state machine, and the daemon wiring —
//! lives in the node crate, which drives this core over OS threads and
//! feeds it templates, a block-time updater, a cancellation predicate,
//! and a clock.

use core::sync::atomic::{AtomicU64, Ordering};

use dcroxide_chainhash::{Hash, hash_h};
use dcroxide_standalone::{Sign, compact_to_big};
use dcroxide_wire::{BlockHeader, MAX_BLOCK_HEADER_PAYLOAD};

/// The maximum nonce searched before advancing the extra nonce (dcrd
/// `maxNonce = ^uint32(0)`).
const MAX_NONCE: u32 = u32::MAX;

/// How often the speed stats are updated and the cancel/stale checks
/// run within the nonce loop (dcrd's `nonce%65535` cadence — note this
/// is 65535, not 65536).
const HASH_UPDATE_INTERVAL: u32 = 65535;

// The offsets of the fields the solve loop patches in the serialized
// header (dcrd's `timestampOffset`, `nonceSerOffset` and `enSerOffset`).
const TIMESTAMP_OFFSET: usize = 136;
const NONCE_SER_OFFSET: usize = 140;
const EN_SER_OFFSET: usize = 144;

/// Whether the proof-of-work hash, read as a little-endian 256-bit
/// number (dcrd `HashToUint256`), is at or below the target given as 32
/// big-endian bytes (dcrd's `n.LtEq(&targetDiff)`), without building a
/// big integer per hash.
fn hash_at_or_below(hash: &Hash, target_be: &[u8; 32]) -> bool {
    for (h, t) in hash.0.iter().rev().zip(target_be) {
        if h != t {
            return h < t;
        }
    }
    true
}

/// The hashing speed statistics the solve loop accumulates (dcrd
/// `speedStats`): the continuous miner's speed monitor reads these to
/// report the hash rate.  The discrete `generate` path accumulates them
/// too but does not report from them.
#[derive(Default)]
pub struct SpeedStats {
    /// The running total of proof-of-work hashes computed.
    pub total_hashes: AtomicU64,
    /// The running total of microseconds spent hashing.
    pub elapsed_micros: AtomicU64,
}

/// Fold the hashes computed since the last update into the shared speed
/// stats and reset the per-interval counters (dcrd's `updateSpeedStats`
/// closure).
fn accumulate(stats: &SpeedStats, hashes_completed: &mut u64, start: &mut u64, now: u64) {
    stats
        .total_hashes
        .fetch_add(*hashes_completed, Ordering::Relaxed);
    stats
        .elapsed_micros
        .fetch_add(now.wrapping_sub(*start), Ordering::Relaxed);
    *hashes_completed = 0;
    *start = now;
}

/// Search for a nonce, extra nonce, and timestamp that make the passed
/// header hash to a value at or below its target difficulty, mutating
/// the header in place with the tweaks (dcrd `CPUMiner.solveBlock`).
/// Returns `true` with the header ready for submission, or `false` when
/// `should_cancel` fires or the target bits cannot be decoded.
///
/// The caller injects the pieces the pure core cannot own:
/// - `en_offset`: the random extra-nonce offset for this attempt (dcrd
///   draws it from `rand.Uint64()` once per call).
/// - `is_blake3_pow_active`: selects the BLAKE3 pow hash over BLAKE-256
///   when the DCP0011 agenda is active.
/// - `update_block_time`: refreshes the header timestamp periodically
///   (dcrd `g.UpdateBlockTime`).
/// - `should_cancel`: the non-blocking quit/stale check (dcrd's
///   `ctx.Done` select).
/// - `now_micros`: a monotonic microsecond clock for the speed stats
///   (the core is `no_std`, so the clock is injected).
#[allow(clippy::too_many_arguments)]
pub fn solve_block(
    header: &mut BlockHeader,
    stats: &SpeedStats,
    is_blake3_pow_active: bool,
    en_offset: u64,
    update_block_time: &mut dyn FnMut(&mut BlockHeader),
    should_cancel: &mut dyn FnMut() -> bool,
    now_micros: &mut dyn FnMut() -> u64,
) -> bool {
    // Decode the target difficulty once.  dcrd bails out when the bits
    // are negative or overflow a uint256 (`DiffBitsToUint256`'s isNeg /
    // overflows); the overflow case is unreachable for a real
    // (at-or-below the pow limit) template, but is guarded to match
    // dcrd exactly — a target needing more than 256 bits would
    // otherwise be trivially "solved" by any hash on the first nonce.
    let target = compact_to_big(header.bits);
    if target.sign() == Sign::Minus || target.bits() > 256 {
        return false;
    }
    let mut target_be = [0u8; 32];
    let (_, magnitude) = target.to_bytes_be();
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "target.bits() <= 256 was checked above, so magnitude.len() <= 32"
    )]
    if target.sign() != Sign::NoSign {
        target_be[32 - magnitude.len()..].copy_from_slice(&magnitude);
    }

    // Choose the hash function depending on the active agendas.
    let pow_hash: fn(&[u8; MAX_BLOCK_HEADER_PAYLOAD]) -> Hash = if is_blake3_pow_active {
        BlockHeader::pow_hash_v2_of
    } else {
        |b| hash_h(b)
    };

    // Serialize the header once so only the specific bytes that need to
    // be updated are written in the loops below.
    let mut hdr_bytes = header.serialize();

    let mut hashes_completed: u64 = 0;
    let mut start = now_micros();

    // Iterate the entire extra-nonce range, relying on the wrapping add
    // of the offset exactly as the Go spec's defined overflow does; the
    // loop runs until a solution is found.
    let mut extra_nonce: u64 = 0;
    loop {
        // Update the extra nonce in the serialized header bytes directly
        // (the low eight bytes of the extra data, little endian), leaving
        // the rest of the field as the template produced it.
        let en = extra_nonce.wrapping_add(en_offset);
        hdr_bytes[EN_SER_OFFSET..EN_SER_OFFSET + 8].copy_from_slice(&en.to_le_bytes());

        // Search the whole nonce range.  The break sits at the end of
        // the block so the u32 nonce never wraps back to zero and
        // re-enters the range (dcrd's placement note).
        let mut nonce: u32 = 0;
        loop {
            // Periodically fold the speed stats and check for early
            // quit and a refreshed block time.
            if nonce > 0 && nonce.is_multiple_of(HASH_UPDATE_INTERVAL) {
                accumulate(stats, &mut hashes_completed, &mut start, now_micros());

                if should_cancel() {
                    return false;
                }

                update_block_time(header);

                // Update the time in the serialized header bytes directly
                // too since it might have changed.
                hdr_bytes[TIMESTAMP_OFFSET..TIMESTAMP_OFFSET + 4]
                    .copy_from_slice(&header.timestamp.to_le_bytes());
            }

            // Update the nonce in the serialized header bytes directly and
            // compute the header's proof-of-work hash.
            hdr_bytes[NONCE_SER_OFFSET..NONCE_SER_OFFSET + 4].copy_from_slice(&nonce.to_le_bytes());
            let hash = pow_hash(&hdr_bytes);
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "reset by accumulate at least every HASH_UPDATE_INTERVAL nonces"
            )]
            {
                hashes_completed += 1;
            }

            // Solved when the hash is at or below the target: update the
            // nonce and extra nonce fields in the header to the solution.
            if hash_at_or_below(&hash, &target_be) {
                header.extra_data[0..8].copy_from_slice(&en.to_le_bytes());
                header.nonce = nonce;
                accumulate(stats, &mut hashes_completed, &mut start, now_micros());
                return true;
            }

            if nonce == MAX_NONCE {
                accumulate(stats, &mut hashes_completed, &mut start, now_micros());
                break;
            }
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "nonce < MAX_NONCE, since the loop breaks at MAX_NONCE above"
            )]
            {
                nonce += 1;
            }
        }
        extra_nonce = extra_nonce.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A header at the simnet proof-of-work limit, which any nonce
    /// solves in a handful of iterations.
    fn easy_header() -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_block: dcroxide_chainhash::Hash::ZERO,
            merkle_root: dcroxide_chainhash::Hash::ZERO,
            stake_root: dcroxide_chainhash::Hash::ZERO,
            vote_bits: 0,
            final_state: [0u8; 6],
            voters: 0,
            fresh_stake: 0,
            revocations: 0,
            pool_size: 0,
            // The simnet/regnet pow limit bits — a very easy target.
            bits: 0x207f_ffff,
            sbits: 0,
            height: 1,
            size: 0,
            timestamp: 1_700_000_000,
            nonce: 0,
            extra_data: [0u8; 32],
            stake_version: 0,
        }
    }

    /// The solve core finds a proof of work that the standalone
    /// verifier accepts, under both the BLAKE-256 and BLAKE3 hashes.
    #[test]
    fn solve_finds_a_valid_proof_of_work() {
        for blake3 in [false, true] {
            let mut header = easy_header();
            let stats = SpeedStats::default();
            let mut clock = 0u64;
            let solved = solve_block(
                &mut header,
                &stats,
                blake3,
                0x0123_4567_89ab_cdef,
                &mut |_| {},
                &mut || false,
                &mut || {
                    clock += 1;
                    clock
                },
            );
            assert!(solved, "the easy target must be solved (blake3={blake3})");

            let pow_hash = if blake3 {
                header.pow_hash_v2()
            } else {
                header.pow_hash_v1()
            };
            assert!(
                dcroxide_standalone::check_proof_of_work_hash(&pow_hash, header.bits).is_ok(),
                "the solved header passes the pow check (blake3={blake3})"
            );
            // The extra data carries the winning extra nonce plus offset
            // in its low eight bytes.
            let en = u64::from_le_bytes(header.extra_data[0..8].try_into().unwrap());
            assert_eq!(
                en, 0x0123_4567_89ab_cdef,
                "extra nonce 0 plus the offset (blake3={blake3})"
            );
        }
    }

    /// A target whose bits decode to a value above 2^256 is rejected
    /// (dcrd's `overflows` guard), not treated as a trivially-easy
    /// target that any hash would satisfy on the first nonce.
    #[test]
    fn solve_rejects_an_overflowing_target() {
        let mut header = easy_header();
        // Mantissa 0x7fffff, exponent 34 -> ~2^271, positive sign.
        header.bits = 0x227f_ffff;
        let stats = SpeedStats::default();
        let solved = solve_block(
            &mut header,
            &stats,
            false,
            0,
            &mut |_| {},
            &mut || false,
            &mut || 0,
        );
        assert!(!solved, "an overflowing target is not solvable");
    }

    /// A cancel that fires drops out of the solve with `false`.  The
    /// header's bits are set so hard that no early nonce solves it, so
    /// the loop runs until the first cancel check.
    #[test]
    fn solve_cancels_at_the_first_check() {
        let mut header = easy_header();
        // A maximally hard target (mantissa 1, exponent 3) so the loop
        // reaches the first cancel check rather than solving.
        header.bits = 0x0300_0001;
        let stats = SpeedStats::default();
        let mut checks = 0u32;
        let solved = solve_block(
            &mut header,
            &stats,
            false,
            0,
            &mut |_| {},
            &mut || {
                checks += 1;
                true
            },
            &mut || 0,
        );
        assert!(!solved, "a cancelled solve returns false");
        assert_eq!(checks, 1, "cancel is checked once, at the first interval");
        assert!(
            stats.total_hashes.load(Ordering::Relaxed) >= u64::from(HASH_UPDATE_INTERVAL),
            "an interval of hashes ran before the cancel check"
        );
    }

    /// The block-time updater fires exactly on the nonce-interval
    /// boundary (pins the 65535 cadence).
    #[test]
    fn the_block_time_updates_on_the_interval() {
        let mut header = easy_header();
        header.bits = 0x0300_0001; // unsolvable, so the loop keeps going
        let stats = SpeedStats::default();
        let mut updates = 0u32;
        // Cancel after two intervals so the test terminates.
        let mut checks = 0u32;
        solve_block(
            &mut header,
            &stats,
            false,
            0,
            &mut |_| updates += 1,
            &mut || {
                checks += 1;
                checks >= 2
            },
            &mut || 0,
        );
        // The first interval: cancel checked (continues), block time
        // updated.  The second interval: cancel checked (returns) before
        // the block-time update.
        assert_eq!(checks, 2, "two interval boundaries were reached");
        assert_eq!(updates, 1, "block time updated once, before the cancel");
    }

    /// The loop hashes the header serialized once and patched in place,
    /// as dcrd's does, so a block time the updater refreshes has to be
    /// written into those bytes too.  With a target that no nonce in the
    /// first interval (or two) meets, the solution is found under the
    /// refreshed time, and the returned header must hash to it.
    #[test]
    fn a_refreshed_block_time_is_part_of_the_hashed_header() {
        // One hash in 2^16 meets this target; with extra nonce offset
        // zero the first solutions sit past the first block-time update:
        // nonce 144130 at the third timestamp under BLAKE-256, nonce
        // 68837 at the second under BLAKE3.
        for (blake3, want_nonce, want_bump) in [(false, 144_130u32, 2u32), (true, 68_837, 1)] {
            let mut header = easy_header();
            header.bits = 0x1f01_0000;
            let t0 = header.timestamp;
            let stats = SpeedStats::default();
            let solved = solve_block(
                &mut header,
                &stats,
                blake3,
                0,
                &mut |h| h.timestamp += 1,
                &mut || false,
                &mut || 0,
            );
            assert!(solved, "blake3={blake3}");
            assert_eq!(header.nonce, want_nonce, "blake3={blake3}");
            assert_eq!(header.timestamp, t0 + want_bump, "blake3={blake3}");
            let pow_hash = if blake3 {
                header.pow_hash_v2()
            } else {
                header.pow_hash_v1()
            };
            assert!(
                dcroxide_standalone::check_proof_of_work_hash(&pow_hash, header.bits).is_ok(),
                "the returned header hashes to the solution (blake3={blake3})"
            );
        }
    }

    /// The fixed-width comparison agrees with dcrd's uint256 `LtEq` over
    /// the hash read little endian, including equality and targets with
    /// leading zero bytes.
    #[test]
    fn the_target_comparison_matches_the_big_integer_one() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            state
        };
        for round in 0..4000u32 {
            let mut hash = [0u8; 32];
            for chunk in hash.chunks_mut(8) {
                chunk.copy_from_slice(&next().to_le_bytes());
            }
            // Leading zero bytes in the hash's high end, as real
            // proof-of-work hashes have.
            let zeros = (next() % 33) as usize;
            for b in hash.iter_mut().rev().take(zeros) {
                *b = 0;
            }
            let hash = Hash(hash);
            let bits = match round % 3 {
                // A target equal to the hash itself when it fits.
                0 => dcroxide_standalone::big_to_compact(&dcroxide_standalone::hash_to_big(&hash)),
                _ => (((next() % 0x20) as u32) << 24) | (next() as u32 & 0x007f_ffff),
            };
            let target = compact_to_big(bits);
            if target.sign() == Sign::Minus || target.bits() > 256 {
                continue;
            }
            let mut target_be = [0u8; 32];
            let (_, magnitude) = target.to_bytes_be();
            if target.sign() != Sign::NoSign {
                target_be[32 - magnitude.len()..].copy_from_slice(&magnitude);
            }
            assert_eq!(
                hash_at_or_below(&hash, &target_be),
                dcroxide_standalone::hash_to_big(&hash) <= target,
                "round {round}: hash {hash}, bits {bits:08x}"
            );
        }

        // Exact equality at every byte position, and one above it.
        for shift in 0..30usize {
            let mut hash = [0u8; 32];
            hash[shift..shift + 3].copy_from_slice(&[0x56, 0x34, 0x12]);
            let at = Hash(hash);
            let target = dcroxide_standalone::hash_to_big(&at);
            let bits = dcroxide_standalone::big_to_compact(&target);
            assert_eq!(compact_to_big(bits), target, "shift {shift}");
            let (_, magnitude) = target.to_bytes_be();
            let mut target_be = [0u8; 32];
            target_be[32 - magnitude.len()..].copy_from_slice(&magnitude);
            assert!(hash_at_or_below(&at, &target_be), "shift {shift}");
            hash[shift] = 0x57;
            assert!(!hash_at_or_below(&Hash(hash), &target_be), "shift {shift}");
        }
    }
}
