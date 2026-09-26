// SPDX-License-Identifier: ISC
//! The legacy difficulty retargeting algorithms (dcrd
//! internal/blockchain `difficulty.go`): the exponentially-weighted
//! BLAKE-256 work difficulty, the BLAKE3 (DCP0011) difficulty from an
//! anchor, and both stake difficulty algorithms (the original and the
//! DCP0001 replacement).
//!
//! dcrd computes these by walking `blockNode` parent pointers; this
//! port abstracts the walk behind [`ChainView`], a height-indexed view
//! of the branch ending at the node being extended.  The RPC-only
//! `EstimateNextStakeDifficulty` variants live here too
//! ([`estimate_next_stake_difficulty_v1`] and
//! [`estimate_next_stake_difficulty_v2`]); the agenda-driven selectors
//! (which algorithm applies at a given block) and the BLAKE3 anchor
//! search live with the threshold-state helpers in
//! [`crate::agendas`].

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use dcroxide_chaincfg::Params;
use dcroxide_standalone::{BigInt, Sign, big_to_compact, calc_asert_diff, compact_to_big};

/// The height on testnet version 3 at which max difficulty semantics
/// activated (dcrd `testNet3MaxDiffActivationHeight`).
pub const TESTNET3_MAX_DIFF_ACTIVATION_HEIGHT: i64 = 962928;

/// The per-node data the difficulty algorithms consume (the used subset
/// of dcrd's `blockNode`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DiffNode {
    /// Block height.
    pub height: i64,
    /// Header timestamp as unix seconds.
    pub timestamp: i64,
    /// Compact proof-of-work difficulty target.
    pub bits: u32,
    /// Stake difficulty in atoms.
    pub sbits: i64,
    /// Live ticket pool size.
    pub pool_size: u32,
    /// Number of new tickets in the block.
    pub fresh_stake: u8,
}

/// A height-indexed view of the branch of block nodes ending at the
/// block being extended, replacing dcrd's parent-pointer walks.
///
/// The `*blake3*anchor*` methods expose dcrd chain.go's two cached
/// DCP0011 anchor nodes (`cachedBlake3WorkDiffAnchor` and
/// `cachedBlake3WorkDiffCandidateAnchor`).  The defaults hold nothing,
/// which is dcrd before its first contextual BLAKE3 difficulty
/// calculation; the live chain's view overrides them.  Unlike the
/// stake version memoization this is not result-invariant: once the
/// confirmed anchor is set, dcrd's `checkDifficultyPositional` holds
/// headers to the ASERT difficulty alone.
pub trait ChainView {
    /// The node at the given height along this branch, or `None` when
    /// the height is negative or unknown.
    fn node(&self, height: i64) -> Option<DiffNode>;

    /// The height of the cached confirmed BLAKE3 anchor when there is
    /// one and it is an ancestor of (or is) the node at the given
    /// height along this branch (dcrd
    /// `cachedBlake3WorkDiffAnchor.Load()` plus `IsAncestorOf`).
    fn blake3_anchor_cached(&self, _height: i64) -> Option<i64> {
        None
    }

    /// Record the node at the given height along this branch as the
    /// confirmed BLAKE3 anchor (dcrd
    /// `cachedBlake3WorkDiffAnchor.Store`).
    fn cache_blake3_anchor(&self, _height: i64) {}

    /// The height of the cached candidate BLAKE3 anchor when there is
    /// one and it is an ancestor of (or is) the node at the given
    /// height along this branch (dcrd
    /// `cachedBlake3WorkDiffCandidateAnchor.Load()` plus
    /// `IsAncestorOf`).
    fn blake3_candidate_anchor_cached(&self, _height: i64) -> Option<i64> {
        None
    }

    /// Record the node at the given height along this branch as the
    /// candidate BLAKE3 anchor (dcrd
    /// `cachedBlake3WorkDiffCandidateAnchor.Store`).
    fn cache_blake3_candidate_anchor(&self, _height: i64) {}
}

/// Whether the parameters are test network version 3's (dcrd
/// `isTestNet3`).
pub(crate) fn is_testnet3(params: &Params) -> bool {
    params.net == dcroxide_wire::CurrencyNet::TEST_NET3
}

/// The maximum-difficulty target imposed on testnet (dcrd's
/// `minTestNetTarget`, powLimit >> 6), or `None` off testnet3.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "BigInt shift by the constant 6 (Go big.Int.Rsh): arbitrary precision cannot overflow"
)]
fn min_testnet_target(params: &Params) -> Option<BigInt> {
    if !is_testnet3(params) {
        return None;
    }
    let pow_limit = BigInt::from_bytes_be(Sign::Plus, &params.pow_limit.to_be_bytes());
    Some(pow_limit >> 6u32)
}

/// Go's lossy `big.Int.Int64`: the low 64 bits of the magnitude with
/// the sign applied.
pub(crate) fn lossy_i64(n: &BigInt) -> i64 {
    let low = n.iter_u64_digits().next().unwrap_or(0) as i64;
    if n.sign() == Sign::Minus {
        low.wrapping_neg()
    } else {
        low
    }
}

/// Search backwards for the last block that did not have the special
/// testnet minimum difficulty (dcrd `findPrevTestNetDifficulty`).
pub fn find_prev_testnet_difficulty(
    view: &impl ChainView,
    start_height: i64,
    params: &Params,
) -> u32 {
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "chain parameters: 144 * 20 = 2880 on mainnet and testnet3, 8 * 4 on simnet and regnet"
    )]
    let blocks_per_retarget = params.work_diff_window_size * params.work_diff_windows;

    let mut iter = view.node(start_height);
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "blocks_per_retarget is 2880 or 32, a product of positive chain parameters, never 0 or -1; node.height >= 1 at the decrement: view.node yields no negative height and 0 takes the other arm"
    )]
    while let Some(node) = iter {
        if node.height % blocks_per_retarget == 0 || node.bits != params.pow_limit_bits {
            break;
        }
        iter = if node.height == 0 {
            None
        } else {
            view.node(node.height - 1)
        };
    }

    match iter {
        Some(node) => node.bits,
        None => params.pow_limit_bits,
    }
}

/// Calculate the required BLAKE-256 difficulty for the block after the
/// given previous node using the exponentially-weighted average scheme
/// (dcrd `calcNextBlake256Diff`).
pub fn calc_next_blake256_diff(
    view: &impl ChainView,
    prev_node: &DiffNode,
    new_block_time_unix: i64,
    params: &Params,
) -> u32 {
    // Get the old difficulty.
    let old_diff = prev_node.bits;
    let old_diff_big = compact_to_big(prev_node.bits);

    // The next difficulty only changes on window boundaries.
    let next_height = prev_node.height.wrapping_add(1);
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "work_diff_window_size is a positive chain parameter (144 or 8), never 0 or -1"
    )]
    if next_height % params.work_diff_window_size != 0 {
        // For networks that support it, allow special reduction of the
        // required difficulty once too much time has elapsed without
        // mining a block.
        if params.reduce_min_difficulty
            && (!is_testnet3(params) || next_height < TESTNET3_MAX_DIFF_ACTIVATION_HEIGHT)
        {
            let reduction_time = params.min_diff_reduction_time_secs;
            let allow_min_time = prev_node.timestamp.wrapping_add(reduction_time);
            if new_block_time_unix > allow_min_time {
                return params.pow_limit_bits;
            }

            // The block was mined within the desired timeframe, so
            // return the difficulty for the last block which did not
            // have the special minimum difficulty rule applied.
            return find_prev_testnet_difficulty(view, prev_node.height, params);
        }

        return old_diff;
    }

    // Declare some useful variables.
    let raf_big = BigInt::from(params.retarget_adjustment_factor);
    // dcrd `difficulty.go:90`.  `check_proof_of_work` rejects bits
    // carrying the sign bit, so this numerator cannot be negative and
    // the two rules cannot differ here; routed through the shared helper
    // anyway rather than leaving one of the three on a different rule.
    let next_diff_big_min = go_big_div(&compact_to_big(prev_node.bits), &raf_big);
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "BigInt product (Go big.Int.Mul): arbitrary precision cannot overflow"
    )]
    let next_diff_big_max = compact_to_big(prev_node.bits) * &raf_big;

    let alpha = params.work_diff_alpha;

    // Number of nodes to traverse while calculating difficulty.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "chain parameters: 144 * 20 = 2880 on mainnet and testnet3, 8 * 4 on simnet and regnet"
    )]
    let nodes_to_traverse = params.work_diff_window_size * params.work_diff_windows;

    // Initialize bigInt slice for the percentage changes for each
    // window period above or below the target.
    let mut window_changes = vec![BigInt::from(0); params.work_diff_windows as usize];

    // Regress through all of the previous blocks and store the percent
    // changes per window period; use bigInts to emulate 64.32 bit fixed
    // point.
    let mut older_time: i64;
    let mut window_period: i64 = 0;
    let mut weights: u64 = 0;
    let mut old_node = *prev_node;
    let mut recent_time = prev_node.timestamp;
    let mut i: i64 = 0;
    loop {
        // Store and reset after reaching the end of every window
        // period.
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "window bookkeeping bounded by the chain parameters: work_diff_window_size is positive (144 or 8), never 0 or -1; window_period < work_diff_windows, so each shift is at most work_diff_windows * work_diff_alpha = 20 * 1 = 20 < 64, weights sums at most 20 distinct powers of two (below 2^21) and window_period ends at most 20; the BigInt shifts cannot overflow"
        )]
        if i % params.work_diff_window_size == 0 && i != 0 {
            older_time = old_node.timestamp;
            let mut time_difference = recent_time.wrapping_sub(older_time);

            // Just assume we're at the target (no change) if we've
            // gone all the way back to the genesis block.
            if old_node.height == 0 {
                time_difference = params.target_timespan_secs;
            }

            let mut time_dif_big = BigInt::from(time_difference);
            time_dif_big <<= 32u32; // Add padding
            let target_temp = BigInt::from(params.target_timespan_secs);

            // dcrd `difficulty.go:126`.  The window time difference is
            // signed, so this is where the rules part.
            let mut window_adjusted = go_big_div(&time_dif_big, &target_temp);

            // Weight it exponentially.  Be aware that this could at
            // some point overflow if alpha or the number of blocks
            // used is really large.
            window_adjusted <<= ((params.work_diff_windows - window_period) * alpha) as u32;

            // Sum up all the different weights incrementally.
            weights += 1u64 << (((params.work_diff_windows - window_period) * alpha) as u32);

            // Store it in the slice.
            window_changes[window_period as usize] = window_adjusted;

            window_period += 1;
            recent_time = older_time;
        }

        if i == nodes_to_traverse {
            break; // Exit for loop when we hit the end.
        }

        // Get the previous node while staying at the genesis block as
        // needed.
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "old_node.height > 0 is checked first"
        )]
        if old_node.height > 0
            && let Some(parent) = view.node(old_node.height - 1)
        {
            old_node = parent;
        }
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "i < nodes_to_traverse (at most 144 * 20 = 2880): the loop breaks at equality above"
        )]
        {
            i += 1;
        }
    }

    // Sum up the weighted window periods.
    let mut weighted_sum = BigInt::from(0);
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "BigInt sum (Go big.Int.Add): arbitrary precision cannot overflow"
    )]
    for change in &window_changes {
        weighted_sum += change;
    }

    // Divide by the sum of all weights (dcrd `difficulty.go:163`).  The
    // weighted sum inherits the sign of the window differences above, so
    // this parts too.
    let weights_big = BigInt::from(weights as i64);
    let weighted_sum_div = go_big_div(&weighted_sum, &weights_big);

    // Multiply by the old difficulty to get the new difficulty.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "BigInt product (Go big.Int.Mul): arbitrary precision cannot overflow"
    )]
    let mut next_diff_big = weighted_sum_div * &old_diff_big;
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "BigInt shift by the constant 32 (Go big.Int.Rsh, which also rounds toward negative infinity): arbitrary precision cannot overflow"
    )]
    {
        next_diff_big >>= 32u32; // Remove padding
    }

    // Check to see if we're over the limits for the maximum allowable
    // retarget; if we are, return the maximum or minimum except in the
    // case that oldDiff is zero.
    let zero = BigInt::from(0);
    if old_diff_big == zero {
        // This should never really happen, but in case it does...
    } else if next_diff_big == zero {
        next_diff_big = BigInt::from_bytes_be(Sign::Plus, &params.pow_limit.to_be_bytes());
    } else if next_diff_big > next_diff_big_max {
        next_diff_big = next_diff_big_max;
    } else if next_diff_big < next_diff_big_min {
        next_diff_big = next_diff_big_min;
    }

    // Limit new value to the proof of work limit.
    let pow_limit = BigInt::from_bytes_be(Sign::Plus, &params.pow_limit.to_be_bytes());
    if next_diff_big > pow_limit {
        next_diff_big = pow_limit;
    }

    // Impose the maximum testnet difficulty after the activation
    // height.
    if let Some(min_target) = min_testnet_target(params)
        && next_diff_big < min_target
        && (!is_testnet3(params) || next_height >= TESTNET3_MAX_DIFF_ACTIVATION_HEIGHT)
    {
        next_diff_big = min_target;
    }

    // Convert the difficulty to the compact representation and return
    // it.
    big_to_compact(&next_diff_big)
}

/// Calculate the required BLAKE3 (DCP0011) difficulty for the block
/// after the given previous node using the given anchor node (dcrd
/// `calcNextBlake3DiffFromAnchor`).  The anchor is the final block of
/// the rule change interval before the agenda activated (block one on
/// networks where the agenda is forced active); locating it requires
/// the threshold-state machinery and lives in [`crate::agendas`].
pub fn calc_next_blake3_diff_from_anchor(
    prev_node: &DiffNode,
    anchor: &DiffNode,
    params: &Params,
) -> u32 {
    // Calculate the time and height deltas as the difference between
    // the provided block and the anchor.
    let time_delta = prev_node.timestamp.wrapping_sub(anchor.timestamp);
    let height_delta = prev_node.height.wrapping_sub(anchor.height);

    let pow_limit = BigInt::from_bytes_be(Sign::Plus, &params.pow_limit.to_be_bytes());
    let mut next_diff = calc_asert_diff(
        params.work_diff_v2_blake3_start_bits,
        &pow_limit,
        params.target_time_per_block_secs,
        time_delta,
        height_delta,
        params.work_diff_v2_half_life_secs,
    );

    // Impose the maximum testnet difficulty.
    if let Some(min_target) = min_testnet_target(params) {
        let min_bits = big_to_compact(&min_target);
        if next_diff < min_bits {
            next_diff = min_bits;
        }
    }
    next_diff
}

/// Combine the two adjustment factors into one difficulty per dcrd's
/// 64.32 fixed point arithmetic (dcrd `mergeDifficulty`).
#[allow(
    clippy::arithmetic_side_effects,
    reason = "BigInt shifts by the constant 32 and a BigInt product (Go math/big): arbitrary precision cannot overflow"
)]
pub fn merge_difficulty(old_diff: i64, new_diff1: i64, new_diff2: i64) -> i64 {
    let new_diff1_big = BigInt::from(new_diff1);
    let mut new_diff2_big = BigInt::from(new_diff2);
    new_diff2_big <<= 32u32;

    let old_diff_big = BigInt::from(old_diff);
    let old_diff_big_lsh = BigInt::from(old_diff) << 32u32;

    // Divide the two changes; the result, in fixed point form, is in
    // the divisor.
    let new_diff1_big = go_big_div(&old_diff_big_lsh, &new_diff1_big);
    let new_diff2_big = go_big_div(&new_diff2_big, &old_diff_big);

    // Precision multiply, then divide, then multiply by the original
    // difficulty and shed the padding.
    let mut summed_change = new_diff2_big;
    summed_change <<= 32u32;
    summed_change = go_big_div(&summed_change, &new_diff1_big);
    summed_change *= &old_diff_big;
    summed_change >>= 32u32;

    lossy_i64(&summed_change)
}

/// Clamp a candidate next stake difficulty to the maximum retarget per
/// dcrd's repeated pattern in `calcNextRequiredStakeDifficultyV1`.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "max_retarget is the chain parameter retarget_adjustment_factor (4 on every network, so max_retarget - 1 = 3 and old_diff / max_retarget divides by a positive constant); old_diff is nonzero because both callers return first when it is 0, and candidate is nonzero past the first arm; neither candidate / old_diff nor old_diff / candidate can be i64::MIN / -1: old_diff is at least minimum_stake_diff on any branch whose headers all passed the stake-difficulty check, and for an unchecked sbits (fast_add skips that check for assumed-valid ancestors) the callers derive every candidate as (W * old_diff) >> 32 with 0 < W < 2^58, or as merge_difficulty of two such clamped values, so old_diff = -1 gives |candidate| < 2^26 and old_diff = i64::MIN gives a multiple of 2^31, never -1"
)]
fn clamp_v1_retarget(old_diff: i64, candidate: i64, max_retarget: i64) -> i64 {
    if candidate == 0 {
        old_diff / max_retarget
    } else if candidate / old_diff > (max_retarget - 1) {
        old_diff.wrapping_mul(max_retarget)
    } else if old_diff / candidate > (max_retarget - 1) {
        old_diff / max_retarget
    } else {
        candidate
    }
}

/// Calculate the required stake difficulty for the block after the
/// given node using the original algorithm (dcrd
/// `calcNextRequiredStakeDifficultyV1`).
pub fn calc_next_required_stake_difficulty_v1(
    view: &impl ChainView,
    cur_node: Option<&DiffNode>,
    params: &Params,
) -> i64 {
    let alpha = params.stake_diff_alpha;
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "coinbase_maturity is a u16, so this is at most 65536"
    )]
    let stake_diff_start_height = i64::from(params.coinbase_maturity) + 1;
    let max_retarget = params.retarget_adjustment_factor;
    let ticket_pool_weight = i64::from(params.ticket_pool_size_weight);
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "chain parameters: 144 * 20 = 2880 on mainnet and testnet3, 8 * 8 on simnet and regnet"
    )]
    let nodes_to_traverse = params.stake_diff_window_size * params.stake_diff_windows;

    // Number of nodes to traverse while calculating difficulty.
    let Some(cur_node) = cur_node else {
        return params.minimum_stake_diff;
    };
    if cur_node.height < stake_diff_start_height {
        return params.minimum_stake_diff;
    }

    // Get the old difficulty; if we aren't at a block height where it
    // changes, just return this.
    let old_diff = cur_node.sbits;
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "stake_diff_window_size is a positive chain parameter (144 or 8), never 0 or -1"
    )]
    if cur_node.height.wrapping_add(1) % params.stake_diff_window_size != 0 {
        return old_diff;
    }

    // The target size of the ticketPool in live tickets.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "product of two u16 chain parameters, below 2^32"
    )]
    let target_for_ticket_pool =
        i64::from(params.tickets_per_block) * i64::from(params.ticket_pool_size);

    // Initialize bigInt slice for the percentage changes for each
    // window period above or below the target.
    let mut window_changes = vec![BigInt::from(0); params.stake_diff_windows as usize];

    // Regress through all of the previous blocks and store the percent
    // changes per window period.
    let mut old_node = *cur_node;
    let mut window_period: i64 = 0;
    let mut weights: u64 = 0;
    let mut i: i64 = 0;
    loop {
        // Store and reset after reaching the end of every window
        // period.
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "window bookkeeping bounded by the chain parameters: i + 1 <= nodes_to_traverse (at most 144 * 20 = 2880) over a positive stake_diff_window_size (144 or 8), never 0 or -1; pool_size_skew is below 2^49 (a u32 pool size less a target below 2^32, times the u16 weight, plus the target); the BigInt division has a numerator of at least 1 << 32, so truncation equals Go's Euclidean big.Int.Div, over the positive tickets_per_block * ticket_pool_size; window_period < stake_diff_windows, so each shift is at most 20 * 1 = 20 < 64, weights stays below 2^21 and window_period ends at most 20; the BigInt shifts cannot overflow"
        )]
        if (i + 1) % params.stake_diff_window_size == 0 {
            let mut pool_size_skew = (i64::from(old_node.pool_size) - target_for_ticket_pool)
                * ticket_pool_weight
                + target_for_ticket_pool;

            // Watch for divide by zero.
            if pool_size_skew <= 0 {
                pool_size_skew = 1;
            }

            let mut cur_pool_size_temp = BigInt::from(pool_size_skew);
            cur_pool_size_temp <<= 32u32; // Add padding
            let target_temp = BigInt::from(target_for_ticket_pool);

            let mut window_adjusted = cur_pool_size_temp / target_temp;

            // Weight it exponentially.
            window_adjusted <<= ((params.stake_diff_windows - window_period) * alpha) as u32;

            // Sum up all the different weights incrementally.
            weights += 1u64 << (((params.stake_diff_windows - window_period) * alpha) as u32);

            // Store it in the slice.
            window_changes[window_period as usize] = window_adjusted;
            window_period += 1;
        }

        #[allow(
            clippy::arithmetic_side_effects,
            reason = "i < nodes_to_traverse (at most 144 * 20 = 2880) until this breaks"
        )]
        if (i + 1) == nodes_to_traverse {
            break; // Exit for loop when we hit the end.
        }

        // Get the previous node while staying at the genesis block as
        // needed.
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "old_node.height > 0 is checked first"
        )]
        if old_node.height > 0
            && let Some(parent) = view.node(old_node.height - 1)
        {
            old_node = parent;
        }
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "i < nodes_to_traverse (at most 144 * 20 = 2880): the loop breaks at equality above"
        )]
        {
            i += 1;
        }
    }

    // Sum up the weighted window periods.
    let mut weighted_sum = BigInt::from(0);
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "BigInt sum (Go big.Int.Add): arbitrary precision cannot overflow"
    )]
    for change in &window_changes {
        weighted_sum += change;
    }

    // Divide by the sum of all weights, multiply by the old stake
    // difficulty, and shed the padding.
    let weights_big = BigInt::from(weights as i64);
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "BigInt division: weighted_sum sums non-negative window changes, so truncating / equals Go's Euclidean big.Int.Div, and weights is a nonzero sum of powers of two"
    )]
    let weighted_sum_div = weighted_sum / weights_big;
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "BigInt product (Go big.Int.Mul): arbitrary precision cannot overflow"
    )]
    let mut next_diff_big = weighted_sum_div * BigInt::from(old_diff);
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "BigInt shift by the constant 32 (Go big.Int.Rsh): arbitrary precision cannot overflow"
    )]
    {
        next_diff_big >>= 32u32;
    }
    let next_diff_ticket_pool = lossy_i64(&next_diff_big);

    // Check to see if we're over the limits for the maximum allowable
    // retarget.
    if old_diff == 0 {
        // This should never really happen, but in case it does...
        return next_diff_ticket_pool;
    }
    let next_diff_ticket_pool = clamp_v1_retarget(old_diff, next_diff_ticket_pool, max_retarget);

    // The target number of new SStx per block for any given window
    // period.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "chain parameters: 144 * 5 = 720 on mainnet and testnet3, 8 * 5 on simnet and regnet"
    )]
    let target_for_window = params.stake_diff_window_size * i64::from(params.tickets_per_block);

    // Regress through all of the previous blocks and store the percent
    // changes per window period of fresh stake.
    let mut old_node = *cur_node;
    let mut window_fresh_stake: i64 = 0;
    let mut window_period: i64 = 0;
    let mut weights: u64 = 0;
    let mut i: i64 = 0;
    loop {
        // Add the fresh stake into the store for this window period.
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "reset every window, so at most stake_diff_window_size * u8::MAX = 144 * 255 before the reset"
        )]
        {
            window_fresh_stake += i64::from(old_node.fresh_stake);
        }

        // Store and reset after reaching the end of every window
        // period.
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "window bookkeeping bounded by the chain parameters: i + 1 <= nodes_to_traverse (at most 144 * 20 = 2880) over a positive stake_diff_window_size (144 or 8), never 0 or -1; the BigInt division has a numerator of at least 1 << 32, so truncation equals Go's Euclidean big.Int.Div, over the positive stake_diff_window_size * tickets_per_block; window_period < stake_diff_windows, so each shift is at most 20 * 1 = 20 < 64, weights stays below 2^21 and window_period ends at most 20; the BigInt shifts cannot overflow"
        )]
        if (i + 1) % params.stake_diff_window_size == 0 {
            // Watch for divide by zero.
            if window_fresh_stake <= 0 {
                window_fresh_stake = 1;
            }

            let mut fresh_temp = BigInt::from(window_fresh_stake);
            fresh_temp <<= 32u32; // Add padding
            let target_temp = BigInt::from(target_for_window);

            let mut window_adjusted = fresh_temp / target_temp;

            // Weight it exponentially.
            window_adjusted <<= ((params.stake_diff_windows - window_period) * alpha) as u32;

            // Sum up all the different weights incrementally.
            weights += 1u64 << (((params.stake_diff_windows - window_period) * alpha) as u32);

            // Store it in the slice.
            window_changes[window_period as usize] = window_adjusted;
            window_fresh_stake = 0;
            window_period += 1;
        }

        #[allow(
            clippy::arithmetic_side_effects,
            reason = "i < nodes_to_traverse (at most 144 * 20 = 2880) until this breaks"
        )]
        if (i + 1) == nodes_to_traverse {
            break; // Exit for loop when we hit the end.
        }

        // Get the previous node while staying at the genesis block as
        // needed.
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "old_node.height > 0 is checked first"
        )]
        if old_node.height > 0
            && let Some(parent) = view.node(old_node.height - 1)
        {
            old_node = parent;
        }
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "i < nodes_to_traverse (at most 144 * 20 = 2880): the loop breaks at equality above"
        )]
        {
            i += 1;
        }
    }

    // Sum up the weighted window periods.
    let mut weighted_sum = BigInt::from(0);
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "BigInt sum (Go big.Int.Add): arbitrary precision cannot overflow"
    )]
    for change in &window_changes {
        weighted_sum += change;
    }

    // Divide by the sum of all weights, multiply by the old stake
    // difficulty, and shed the padding.
    let weights_big = BigInt::from(weights as i64);
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "BigInt division: weighted_sum sums non-negative window changes, so truncating / equals Go's Euclidean big.Int.Div, and weights is a nonzero sum of powers of two"
    )]
    let weighted_sum_div = weighted_sum / weights_big;
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "BigInt product (Go big.Int.Mul): arbitrary precision cannot overflow"
    )]
    let mut next_diff_big = weighted_sum_div * BigInt::from(old_diff);
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "BigInt shift by the constant 32 (Go big.Int.Rsh): arbitrary precision cannot overflow"
    )]
    {
        next_diff_big >>= 32u32;
    }
    let next_diff_fresh_stake = lossy_i64(&next_diff_big);

    // Check to see if we're over the limits for the maximum allowable
    // retarget.
    let next_diff_fresh_stake = clamp_v1_retarget(old_diff, next_diff_fresh_stake, max_retarget);

    // Average the two differences using scaled multiplication.
    let next_diff = merge_difficulty(old_diff, next_diff_ticket_pool, next_diff_fresh_stake);

    // Check to see if we're over the limits for the maximum allowable
    // retarget.
    let next_diff = clamp_v1_retarget(old_diff, next_diff, max_retarget);

    // If the next diff is below the network minimum, set the required
    // stake difficulty to the minimum.
    if next_diff < params.minimum_stake_diff {
        return params.minimum_stake_diff;
    }
    next_diff
}

/// A close estimate of the coin supply at the given height (dcrd
/// `estimateSupply`).
#[allow(
    clippy::arithmetic_side_effects,
    reason = "subsidy_reduction_interval and div_subsidy are positive chain parameters, and subsidy only shrinks from base_subsidy (x100/101 per interval), so each term is at most subsidy_reduction_interval * base_subsidy < 2^45, subsidy * mul_subsidy < 2^43, and supply stays below block_one_subsidy + interval * base_subsidy * 101 < 2^52 on every network"
)]
pub fn estimate_supply(params: &Params, height: i64) -> i64 {
    if height <= 0 {
        return 0;
    }

    // Estimate the supply by calculating the full block subsidy for
    // each reduction interval and multiplying it the number of blocks
    // in the interval then adding the subsidy produced by number of
    // blocks in the current interval.
    let mut supply = params.block_one_subsidy();
    let reductions = height / params.subsidy_reduction_interval;
    let mut subsidy = params.base_subsidy;
    for _ in 0..reductions {
        supply += params.subsidy_reduction_interval * subsidy;
        subsidy *= params.mul_subsidy;
        subsidy /= params.div_subsidy;
    }
    supply += (1 + height % params.subsidy_reduction_interval) * subsidy;

    // Blocks 0 and 1 have special subsidy amounts that have already
    // been added above, so remove what their subsidies would have
    // normally been which were also added above.
    supply -= params.base_subsidy * 2;

    supply
}

/// The number of tickets purchased in the most recent specified number
/// of blocks from the node at the given height going backwards (dcrd
/// `sumPurchasedTickets`).
pub fn sum_purchased_tickets(
    view: &impl ChainView,
    start_height: Option<i64>,
    num_to_sum: i64,
) -> i64 {
    let Some(mut height) = start_height else {
        return 0;
    };
    let mut num_purchased: i64 = 0;
    let mut num_traversed: i64 = 0;
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "height >= 1 at the decrement (view.node yields no negative height and 0 breaks first) and num_traversed < num_to_sum by the loop condition"
    )]
    while num_traversed < num_to_sum {
        let Some(node) = view.node(height) else {
            break;
        };
        num_purchased = num_purchased.wrapping_add(i64::from(node.fresh_stake));
        if height == 0 {
            break;
        }
        height -= 1;
        num_traversed += 1;
    }
    num_purchased
}

/// Calculate the required stake difficulty using the DCP0001 algorithm
/// given the pool size estimates (dcrd `calcNextStakeDiffV2`).
pub fn calc_next_stake_diff_v2(
    params: &Params,
    next_height: i64,
    cur_diff: i64,
    prev_pool_size_all: i64,
    cur_pool_size_all: i64,
) -> i64 {
    // Shorter version of various parameter for convenience.
    let votes_per_block = i64::from(params.tickets_per_block);
    let ticket_pool_size = i64::from(params.ticket_pool_size);
    let ticket_maturity = i64::from(params.ticket_maturity);

    // Calculate the difficulty by multiplying the old stake difficulty
    // with two ratios that represent a force to counteract the relative
    // change in the pool size (Fc) and a restorative force to push the
    // pool size towards the target value (Fr).
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "u16 chain parameters: at most 65535 * (65535 + 65535) < 2^33"
    )]
    let target_pool_size_all = votes_per_block * (ticket_pool_size + ticket_maturity);
    let cur_pool_size_all_big = BigInt::from(cur_pool_size_all);
    let mut next_diff_big = BigInt::from(cur_diff);
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "BigInt products (Go big.Int.Mul): arbitrary precision cannot overflow"
    )]
    {
        next_diff_big *= &cur_pool_size_all_big;
        next_diff_big *= &cur_pool_size_all_big;
    }
    next_diff_big = go_big_div(&next_diff_big, &BigInt::from(prev_pool_size_all));
    next_diff_big = go_big_div(&next_diff_big, &BigInt::from(target_pool_size_all));

    // Limit the new stake difficulty between the minimum allowed stake
    // difficulty and a maximum value that is relative to the total
    // supply.
    let mut next_diff = lossy_i64(&next_diff_big);
    let estimated_supply = estimate_supply(params, next_height);
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "ticket_pool_size is a positive u16 chain parameter (8192, 1024 or 64), never 0 or -1"
    )]
    let maximum_stake_diff = estimated_supply / ticket_pool_size;
    if next_diff > maximum_stake_diff {
        next_diff = maximum_stake_diff;
    }
    if next_diff < params.minimum_stake_diff {
        next_diff = params.minimum_stake_diff;
    }
    next_diff
}

/// Calculate the required stake difficulty for the block after the
/// given node using the DCP0001 algorithm (dcrd
/// `calcNextRequiredStakeDifficultyV2`).
pub fn calc_next_required_stake_difficulty_v2(
    view: &impl ChainView,
    cur_node: Option<&DiffNode>,
    params: &Params,
) -> i64 {
    // Stake difficulty before any tickets could possibly be purchased
    // is the minimum value.
    let next_height = match cur_node {
        Some(node) => node.height.wrapping_add(1),
        None => 0,
    };
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "coinbase_maturity is a u16, so this is at most 65536"
    )]
    let stake_diff_start_height = i64::from(params.coinbase_maturity) + 1;
    if next_height < stake_diff_start_height {
        return params.minimum_stake_diff;
    }
    let cur_node = cur_node.expect("next_height >= start height implies a node");

    // Return the previous block's difficulty requirements if the next
    // block is not at a difficulty retarget interval.
    let interval_size = params.stake_diff_window_size;
    let cur_diff = cur_node.sbits;
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "stake_diff_window_size is a positive chain parameter (144 or 8), never 0 or -1"
    )]
    if next_height % interval_size != 0 {
        return cur_diff;
    }

    // Get the pool size and number of tickets that were immature at the
    // previous retarget interval.
    let mut prev_pool_size: i64 = 0;
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "next_height >= stake_diff_start_height >= 1 past the return above and interval_size is 144 or 8, so this is at least -interval_size"
    )]
    let prev_retarget_height = next_height - interval_size - 1;
    let prev_retarget_node = if prev_retarget_height >= 0 {
        view.node(prev_retarget_height)
    } else {
        None
    };
    if let Some(node) = &prev_retarget_node {
        prev_pool_size = i64::from(node.pool_size);
    }
    let ticket_maturity = i64::from(params.ticket_maturity);
    let prev_immature_tickets =
        sum_purchased_tickets(view, prev_retarget_node.map(|n| n.height), ticket_maturity);

    // Return the existing ticket price for the first few intervals to
    // avoid division by zero and encourage initial pool population.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "a u32 pool size plus the u8 fresh stake of at most ticket_maturity (a u16) blocks, below 2^33"
    )]
    let prev_pool_size_all = prev_pool_size + prev_immature_tickets;
    if prev_pool_size_all == 0 {
        return cur_diff;
    }

    // Count the number of currently immature tickets.
    let immature_tickets = sum_purchased_tickets(view, Some(cur_node.height), ticket_maturity);

    // Calculate and return the final next required difficulty.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "a u32 pool size plus the u8 fresh stake of at most ticket_maturity (a u16) blocks, below 2^33"
    )]
    let cur_pool_size_all = i64::from(cur_node.pool_size) + immature_tickets;
    calc_next_stake_diff_v2(
        params,
        next_height,
        cur_diff,
        prev_pool_size_all,
        cur_pool_size_all,
    )
}

/// A chain view that overlays fabricated nodes on top of a base view
/// (the fake blockchain dcrd's original stake difficulty estimator
/// builds on the current tip).
struct OverlayView<'a, V: ChainView> {
    inner: &'a V,
    base_height: i64,
    overlay: &'a [DiffNode],
}

impl<V: ChainView> ChainView for OverlayView<'_, V> {
    fn node(&self, height: i64) -> Option<DiffNode> {
        if height > self.base_height {
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "height > base_height >= stake_diff_start_height >= 1 (its one constructor runs past that check), so the difference is in 1..=i64::MAX and the decrement stays non-negative"
            )]
            let idx = usize::try_from(height - self.base_height - 1).ok()?;
            return self.overlay.get(idx).copied();
        }
        self.inner.node(height)
    }
}

/// Estimate the next stake difficulty using the original algorithm by
/// pretending the given number of tickets will be purchased in the
/// remainder of the interval, or the maximum possible number when the
/// flag is set (dcrd `estimateNextStakeDifficultyV1`).
pub fn estimate_next_stake_difficulty_v1(
    view: &impl ChainView,
    cur_node: Option<&DiffNode>,
    tickets_in_window: i64,
    use_max_tickets: bool,
    params: &Params,
) -> Result<i64, String> {
    let alpha = params.stake_diff_alpha;
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "coinbase_maturity is a u16, so this is at most 65536"
    )]
    let stake_diff_start_height = i64::from(params.coinbase_maturity) + 1;
    let max_retarget = params.retarget_adjustment_factor;
    let ticket_pool_weight = i64::from(params.ticket_pool_size_weight);

    // Number of nodes to traverse while calculating difficulty.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "chain parameters: 144 * 20 = 2880 on mainnet and testnet3, 8 * 8 on simnet and regnet"
    )]
    let nodes_to_traverse = params.stake_diff_window_size * params.stake_diff_windows;

    // Genesis block. Block at height 1 has these parameters.
    let Some(cur_node) = cur_node else {
        return Ok(params.minimum_stake_diff);
    };
    if cur_node.height < stake_diff_start_height {
        return Ok(params.minimum_stake_diff);
    }

    // Create a fake blockchain on top of the current best node with
    // the number of freshly purchased tickets as indicated by the
    // user.
    let old_diff = cur_node.sbits;
    let mut tickets_in_window = tickets_in_window;
    let mut fakes: Vec<DiffNode> = Vec::new();
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "stake_diff_window_size is a positive chain parameter (144 or 8), never 0 or -1; cur_node.height is in stake_diff_start_height..=u32::MAX (a u32 header field), so next_adj_height is at most u32::MAX + 144, next_adj_height - cur_node.height is in 1..=144 and max_tickets is at most 144 * u8::MAX; the height range starts at most at u32::MAX + 1; the subtraction arm runs only when tickets_to_insert >= max_fresh_stake_per_block >= 0"
    )]
    if cur_node.height.wrapping_add(1) % params.stake_diff_window_size != 0 {
        let next_adj_height =
            (cur_node.height / params.stake_diff_window_size + 1) * params.stake_diff_window_size;
        let max_tickets =
            (next_adj_height - cur_node.height) * i64::from(params.max_fresh_stake_per_block);

        // If the user has indicated that the automatically calculated
        // maximum amount of tickets should be used, plug that in here.
        if use_max_tickets {
            tickets_in_window = max_tickets;
        }

        // Double check to make sure there isn't too much.
        if tickets_in_window > max_tickets {
            return Err(format!(
                "too much fresh stake to be used in evaluation requested; \
                 max {max_tickets}, got {tickets_in_window}"
            ));
        }

        // Insert all the tickets into bogus nodes that will be used to
        // calculate the next difficulty below.
        let mut tickets_to_insert = tickets_in_window;
        for height in (cur_node.height + 1)..next_adj_height {
            // Insert the fake fresh stake into each block, decrementing
            // the amount we need to use each time until we hit 0.
            let fresh_stake = if i64::from(params.max_fresh_stake_per_block) > tickets_to_insert {
                let fresh = tickets_to_insert as u8;
                tickets_to_insert = 0;
                fresh
            } else {
                tickets_to_insert -= i64::from(params.max_fresh_stake_per_block);
                params.max_fresh_stake_per_block
            };

            // Use a constant pool size for the estimate, since this has
            // much less fluctuation than the fresh stake.
            fakes.push(DiffNode {
                height,
                timestamp: 0,
                bits: 0,
                sbits: 0,
                pool_size: cur_node.pool_size,
                fresh_stake,
            });
        }
    }
    let top_node = fakes.last().copied().unwrap_or(*cur_node);
    let est_view = OverlayView {
        inner: view,
        base_height: cur_node.height,
        overlay: &fakes,
    };

    // The target size of the ticketPool in live tickets.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "product of two u16 chain parameters, below 2^32"
    )]
    let target_for_ticket_pool =
        i64::from(params.tickets_per_block) * i64::from(params.ticket_pool_size);

    // Initialize bigInt slice for the percentage changes for each
    // window period above or below the target.
    let mut window_changes = vec![BigInt::from(0); params.stake_diff_windows as usize];

    // Regress through all of the previous blocks and store the percent
    // changes per window period.
    let mut old_node = top_node;
    let mut window_period: i64 = 0;
    let mut weights: u64 = 0;
    let mut i: i64 = 0;
    loop {
        // Store and reset after reaching the end of every window
        // period.
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "window bookkeeping bounded by the chain parameters: i + 1 <= nodes_to_traverse (at most 144 * 20 = 2880) over a positive stake_diff_window_size (144 or 8), never 0 or -1; pool_size_skew is below 2^49 (a u32 pool size less a target below 2^32, times the u16 weight, plus the target); the BigInt division has a numerator of at least 1 << 32, so truncation equals Go's Euclidean big.Int.Div, over the positive tickets_per_block * ticket_pool_size; window_period < stake_diff_windows, so each shift is at most 20 * 1 = 20 < 64, weights stays below 2^21 and window_period ends at most 20; the BigInt shifts cannot overflow"
        )]
        if (i + 1) % params.stake_diff_window_size == 0 {
            let mut pool_size_skew = (i64::from(old_node.pool_size) - target_for_ticket_pool)
                * ticket_pool_weight
                + target_for_ticket_pool;

            // Watch for divide by zero.
            if pool_size_skew <= 0 {
                pool_size_skew = 1;
            }

            let mut cur_pool_size_temp = BigInt::from(pool_size_skew);
            cur_pool_size_temp <<= 32u32; // Add padding
            let target_temp = BigInt::from(target_for_ticket_pool);

            let mut window_adjusted = cur_pool_size_temp / target_temp;

            // Weight it exponentially.
            window_adjusted <<= ((params.stake_diff_windows - window_period) * alpha) as u32;

            // Sum up all the different weights incrementally.
            weights += 1u64 << (((params.stake_diff_windows - window_period) * alpha) as u32);

            // Store it in the slice.
            window_changes[window_period as usize] = window_adjusted;
            window_period += 1;
        }

        #[allow(
            clippy::arithmetic_side_effects,
            reason = "i < nodes_to_traverse (at most 144 * 20 = 2880) until this breaks"
        )]
        if (i + 1) == nodes_to_traverse {
            break; // Exit for loop when we hit the end.
        }

        // Get the previous node while staying at the genesis block as
        // needed.
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "old_node.height > 0 is checked first"
        )]
        if old_node.height > 0
            && let Some(parent) = est_view.node(old_node.height - 1)
        {
            old_node = parent;
        }
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "i < nodes_to_traverse (at most 144 * 20 = 2880): the loop breaks at equality above"
        )]
        {
            i += 1;
        }
    }

    // Sum up the weighted window periods.
    let mut weighted_sum = BigInt::from(0);
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "BigInt sum (Go big.Int.Add): arbitrary precision cannot overflow"
    )]
    for change in &window_changes {
        weighted_sum += change;
    }

    // Divide by the sum of all weights, multiply by the old stake
    // difficulty, and shed the padding.
    let weights_big = BigInt::from(weights as i64);
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "BigInt division: weighted_sum sums non-negative window changes, so truncating / equals Go's Euclidean big.Int.Div, and weights is a nonzero sum of powers of two"
    )]
    let weighted_sum_div = weighted_sum / weights_big;
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "BigInt product (Go big.Int.Mul): arbitrary precision cannot overflow"
    )]
    let mut next_diff_big = weighted_sum_div * BigInt::from(old_diff);
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "BigInt shift by the constant 32 (Go big.Int.Rsh): arbitrary precision cannot overflow"
    )]
    {
        next_diff_big >>= 32u32;
    }
    let next_diff_ticket_pool = lossy_i64(&next_diff_big);

    // Check to see if we're over the limits for the maximum allowable
    // retarget.
    if old_diff == 0 {
        // This should never really happen, but in case it does...
        return Ok(next_diff_ticket_pool);
    }
    let next_diff_ticket_pool = clamp_v1_retarget(old_diff, next_diff_ticket_pool, max_retarget);

    // The target number of new SStx per block for any given window
    // period.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "chain parameters: 144 * 5 = 720 on mainnet and testnet3, 8 * 5 on simnet and regnet"
    )]
    let target_for_window = params.stake_diff_window_size * i64::from(params.tickets_per_block);

    // Regress through all of the previous blocks and store the percent
    // changes per window period of fresh stake.
    let mut old_node = top_node;
    let mut window_fresh_stake: i64 = 0;
    let mut window_period: i64 = 0;
    let mut weights: u64 = 0;
    let mut i: i64 = 0;
    loop {
        // Add the fresh stake into the store for this window period.
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "reset every window, so at most stake_diff_window_size * u8::MAX = 144 * 255 before the reset"
        )]
        {
            window_fresh_stake += i64::from(old_node.fresh_stake);
        }

        // Store and reset after reaching the end of every window
        // period.
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "window bookkeeping bounded by the chain parameters: i + 1 <= nodes_to_traverse (at most 144 * 20 = 2880) over a positive stake_diff_window_size (144 or 8), never 0 or -1; the BigInt division has a numerator of at least 1 << 32, so truncation equals Go's Euclidean big.Int.Div, over the positive stake_diff_window_size * tickets_per_block; window_period < stake_diff_windows, so each shift is at most 20 * 1 = 20 < 64, weights stays below 2^21 and window_period ends at most 20; the BigInt shifts cannot overflow"
        )]
        if (i + 1) % params.stake_diff_window_size == 0 {
            // Watch for divide by zero.
            if window_fresh_stake <= 0 {
                window_fresh_stake = 1;
            }

            let mut fresh_temp = BigInt::from(window_fresh_stake);
            fresh_temp <<= 32u32; // Add padding
            let target_temp = BigInt::from(target_for_window);

            let mut window_adjusted = fresh_temp / target_temp;

            // Weight it exponentially.
            window_adjusted <<= ((params.stake_diff_windows - window_period) * alpha) as u32;

            // Sum up all the different weights incrementally.
            weights += 1u64 << (((params.stake_diff_windows - window_period) * alpha) as u32);

            // Store it in the slice.
            window_changes[window_period as usize] = window_adjusted;
            window_fresh_stake = 0;
            window_period += 1;
        }

        #[allow(
            clippy::arithmetic_side_effects,
            reason = "i < nodes_to_traverse (at most 144 * 20 = 2880) until this breaks"
        )]
        if (i + 1) == nodes_to_traverse {
            break; // Exit for loop when we hit the end.
        }

        // Get the previous node while staying at the genesis block as
        // needed.
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "old_node.height > 0 is checked first"
        )]
        if old_node.height > 0
            && let Some(parent) = est_view.node(old_node.height - 1)
        {
            old_node = parent;
        }
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "i < nodes_to_traverse (at most 144 * 20 = 2880): the loop breaks at equality above"
        )]
        {
            i += 1;
        }
    }

    // Sum up the weighted window periods.
    let mut weighted_sum = BigInt::from(0);
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "BigInt sum (Go big.Int.Add): arbitrary precision cannot overflow"
    )]
    for change in &window_changes {
        weighted_sum += change;
    }

    // Divide by the sum of all weights, multiply by the old stake
    // difficulty, and shed the padding.
    let weights_big = BigInt::from(weights as i64);
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "BigInt division: weighted_sum sums non-negative window changes, so truncating / equals Go's Euclidean big.Int.Div, and weights is a nonzero sum of powers of two"
    )]
    let weighted_sum_div = weighted_sum / weights_big;
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "BigInt product (Go big.Int.Mul): arbitrary precision cannot overflow"
    )]
    let mut next_diff_big = weighted_sum_div * BigInt::from(old_diff);
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "BigInt shift by the constant 32 (Go big.Int.Rsh): arbitrary precision cannot overflow"
    )]
    {
        next_diff_big >>= 32u32;
    }
    let next_diff_fresh_stake = lossy_i64(&next_diff_big);

    // Check to see if we're over the limits for the maximum allowable
    // retarget.
    let next_diff_fresh_stake = clamp_v1_retarget(old_diff, next_diff_fresh_stake, max_retarget);

    // Average the two differences using scaled multiplication.
    let next_diff = merge_difficulty(old_diff, next_diff_ticket_pool, next_diff_fresh_stake);

    // Check to see if we're over the limits for the maximum allowable
    // retarget.
    let next_diff = clamp_v1_retarget(old_diff, next_diff, max_retarget);

    // If the next diff is below the network minimum, set the required
    // stake difficulty to the minimum.
    if next_diff < params.minimum_stake_diff {
        return Ok(params.minimum_stake_diff);
    }
    Ok(next_diff)
}

/// Estimate the next stake difficulty using the DCP0001 algorithm by
/// pretending the given number of tickets will be purchased in the
/// remainder of the interval, or the maximum possible number when the
/// flag is set (dcrd `estimateNextStakeDifficultyV2`).
pub fn estimate_next_stake_difficulty_v2(
    view: &impl ChainView,
    cur_node: Option<&DiffNode>,
    new_tickets: i64,
    use_max_tickets: bool,
    params: &Params,
) -> Result<i64, String> {
    // Calculate the next retarget interval height.
    let cur_height = cur_node.map_or(0, |n| n.height);
    let ticket_maturity = i64::from(params.ticket_maturity);
    let interval_size = params.stake_diff_window_size;
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "interval_size is a positive chain parameter (144 or 8), never 0 or -1, and cur_height is 0 or a node height, so the remainder is in 0..interval_size and this is in 1..=interval_size"
    )]
    let blocks_until_retarget = interval_size - cur_height % interval_size;
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "cur_height is 0 or a node height, at most u32::MAX (a u32 header field), and blocks_until_retarget is at most 144"
    )]
    let next_retarget_height = cur_height + blocks_until_retarget;

    // Calculate the maximum possible number of tickets that could be
    // sold in the remainder of the interval and potentially override
    // the number of new tickets to include in the estimate per the
    // user-specified flag.
    let max_tickets_per_block = i64::from(params.max_fresh_stake_per_block);
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "blocks_until_retarget is in 1..=interval_size, so at most 143 * u8::MAX"
    )]
    let max_remaining_tickets = (blocks_until_retarget - 1) * max_tickets_per_block;
    let mut new_tickets = new_tickets;
    if use_max_tickets {
        new_tickets = max_remaining_tickets;
    }

    // Ensure the specified number of tickets is not too high.
    if new_tickets > max_remaining_tickets {
        return Err(format!(
            "unable to create an estimated stake difficulty with {new_tickets} \
             tickets since it is more than the maximum remaining of \
             {max_remaining_tickets}"
        ));
    }

    // Stake difficulty before any tickets could possibly be purchased
    // is the minimum value.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "coinbase_maturity is a u16, so this is at most 65536"
    )]
    let stake_diff_start_height = i64::from(params.coinbase_maturity) + 1;
    if next_retarget_height < stake_diff_start_height {
        return Ok(params.minimum_stake_diff);
    }
    let cur_node = cur_node.expect("past the stake difficulty start height implies a node");

    // Get the pool size and number of tickets that were immature at
    // the previous retarget interval.
    //
    // NOTE: Since the stake difficulty must be calculated based on
    // existing blocks, it is always calculated for the block after a
    // given block, so the information for the previous retarget
    // interval must be retrieved relative to the block just before it
    // to coincide with how it was originally calculated.
    let mut prev_pool_size: i64 = 0;
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "next_retarget_height is in 1..=u32::MAX + 144 and interval_size is 144 or 8"
    )]
    let prev_retarget_height = next_retarget_height - interval_size - 1;
    let prev_retarget_node = view.node(prev_retarget_height);
    if let Some(node) = &prev_retarget_node {
        prev_pool_size = i64::from(node.pool_size);
    }
    let prev_immature_tickets =
        sum_purchased_tickets(view, prev_retarget_node.map(|n| n.height), ticket_maturity);

    // Return the existing ticket price for the first few intervals to
    // avoid division by zero and encourage initial pool population.
    let cur_diff = cur_node.sbits;
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "a u32 pool size plus the u8 fresh stake of at most ticket_maturity (a u16) blocks, below 2^33"
    )]
    let prev_pool_size_all = prev_pool_size + prev_immature_tickets;
    if prev_pool_size_all == 0 {
        return Ok(cur_diff);
    }

    // Calculate the number of tickets that will still be immature at
    // the next retarget based on the known (non-estimated) data.
    //
    // Note that when the interval size is larger than the ticket
    // maturity, the current height might be before the maturity floor
    // (the point after which the remaining tickets will remain
    // immature).  There are therefore no possible remaining immature
    // tickets from the blocks that are not being estimated in that
    // case.
    let mut remaining_immature_tickets: i64 = 0;
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "next_retarget_height is in 1..=u32::MAX + 144 and ticket_maturity is a u16"
    )]
    let next_maturity_floor = next_retarget_height - ticket_maturity - 1;
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "cur_height > next_maturity_floor = cur_height + blocks_until_retarget - ticket_maturity - 1, so the difference is in 1..=ticket_maturity"
    )]
    if cur_height > next_maturity_floor {
        remaining_immature_tickets = sum_purchased_tickets(
            view,
            Some(cur_node.height),
            cur_height - next_maturity_floor,
        );
    }

    // Add the number of tickets that will still be immature at the
    // next retarget based on the estimated data.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "u16 * u8 chain parameters, below 2^24"
    )]
    let max_immature_tickets = ticket_maturity * max_tickets_per_block;
    if new_tickets > max_immature_tickets {
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "the fresh stake of at most ticket_maturity blocks (below 2^24) plus max_immature_tickets (below 2^24)"
        )]
        {
            remaining_immature_tickets += max_immature_tickets;
        }
    } else {
        remaining_immature_tickets = remaining_immature_tickets.wrapping_add(new_tickets);
    }

    // Calculate the number of tickets that will mature in the
    // remainder of the interval based on the known (non-estimated)
    // data.
    //
    // NOTE: The pool size in the block headers does not include the
    // tickets maturing at the height in which they mature since they
    // are not eligible for selection until the next block, so exclude
    // them by starting one block before the next maturity floor.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "next_maturity_floor >= 1 - 65535 - 1 (next_retarget_height >= 1, ticket_maturity a u16)"
    )]
    let mut final_maturing_height = next_maturity_floor - 1;
    if final_maturing_height > cur_height {
        final_maturing_height = cur_height;
    }
    let final_maturing_node = view.node(final_maturing_height);
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "cur_height >= 0 and ticket_maturity is a u16"
    )]
    let first_maturing_height = cur_height - ticket_maturity;
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "final_maturing_height is min(next_maturity_floor - 1, cur_height) and next_maturity_floor - 1 >= cur_height - ticket_maturity - 1, so it is in first_maturing_height - 1..=first_maturing_height + ticket_maturity and this is in 0..=ticket_maturity + 1"
    )]
    let mut maturing_tickets = sum_purchased_tickets(
        view,
        final_maturing_node.map(|n| n.height),
        final_maturing_height - first_maturing_height + 1,
    );

    // Add the number of tickets that will mature based on the
    // estimated data.
    //
    // Note that when the ticket maturity is greater than or equal to
    // the interval size, the current height will always be after the
    // maturity floor.  There are therefore no possible maturing
    // estimated tickets in that case.
    if cur_height < next_maturity_floor {
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "cur_height < next_maturity_floor <= cur_height + interval_size - 1, so this is in 0..interval_size"
        )]
        let maturing_estimate_nodes = next_maturity_floor - cur_height - 1;
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "maturing_estimate_nodes is in 0..interval_size, so at most 143 * u8::MAX"
        )]
        let mut maturing_estimated_tickets = max_tickets_per_block * maturing_estimate_nodes;
        if maturing_estimated_tickets > new_tickets {
            maturing_estimated_tickets = new_tickets;
        }
        maturing_tickets = maturing_tickets.wrapping_add(maturing_estimated_tickets);
    }

    // Calculate the number of votes that will occur during the
    // remainder of the interval.
    let stake_validation_height = params.stake_validation_height;
    let mut pending_votes: i64 = 0;
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "blocks_until_retarget is in 1..=interval_size, and next_retarget_height > stake_validation_height > cur_height puts their difference in 1..blocks_until_retarget, so pending_votes is at most 144 * 65535"
    )]
    if next_retarget_height > stake_validation_height {
        let mut voting_blocks = blocks_until_retarget - 1;
        if cur_height < stake_validation_height {
            voting_blocks = next_retarget_height - stake_validation_height;
        }
        let votes_per_block = i64::from(params.tickets_per_block);
        pending_votes = voting_blocks * votes_per_block;
    }

    // Calculate what the pool size would be as of the next interval.
    let cur_pool_size = i64::from(cur_node.pool_size);
    let estimated_pool_size = cur_pool_size
        .wrapping_add(maturing_tickets)
        .wrapping_sub(pending_votes);
    let estimated_pool_size_all = estimated_pool_size.wrapping_add(remaining_immature_tickets);

    // Calculate and return the final estimated difficulty.
    Ok(calc_next_stake_diff_v2(
        params,
        next_retarget_height,
        cur_diff,
        prev_pool_size_all,
        estimated_pool_size_all,
    ))
}

/// Go's `big.Int.Div`: Euclidean division, where the remainder is never
/// negative (`math/big`'s `Div` documentation).
///
/// num-bigint's `/` truncates toward zero, which agrees with this for
/// every non-negative numerator and differs by exactly one when the
/// numerator is negative and the division is inexact.  dcrd's
/// exponentially-weighted retarget divides a signed window time
/// difference, so the two rules part on any window whose blocks span a
/// net-negative time, and the exponential weight then amplifies that
/// difference before it reaches the compact bits.
///
/// dcrd's choice is deliberate rather than incidental: ASERT divides
/// with the truncating `Quo` (`blockchain/standalone/pow.go:343`), so
/// both rules appear in the same codebase, each where it is meant.
///
/// The file's other divisions keep `/`: their numerators are provably
/// non-negative.  The stake algorithms clamp their pool-size skew to at
/// least 1 before dividing, and the stake EMA sums those clamped terms.
/// `merge_difficulty`, `calc_next_stake_diff_v2` and
/// `validate::calc_ticket_return_amounts` divide with this too.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "BigInt quotient, remainder and unit step (Go math/big): arbitrary precision cannot overflow, and a zero divisor panics here as it does in Go's big.Int.Div"
)]
pub(crate) fn go_big_div(x: &BigInt, y: &BigInt) -> BigInt {
    let q = x / y;
    let r = x % y;
    if r.sign() == Sign::Minus {
        if y.sign() == Sign::Minus {
            q + 1
        } else {
            q - 1
        }
    } else {
        q
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(x: i64, y: i64) -> i64 {
        let q = go_big_div(&BigInt::from(x), &BigInt::from(y));
        i64::try_from(q).expect("fits")
    }

    /// Go's `Div` against hand-checked values, including the two places
    /// it is not simply "floor": a negative divisor.
    ///
    /// Not a discriminator for the retarget change -- it exists so a
    /// later sign slip in the shim is caught here rather than in a
    /// chain vector.
    #[test]
    fn go_big_div_is_euclidean() {
        // Exact division agrees with every rule.
        assert_eq!(d(6, 3), 2);
        assert_eq!(d(-6, 3), -2);
        assert_eq!(d(6, -3), -2);
        assert_eq!(d(-6, -3), 2);

        // Inexact with a positive divisor: floor, one below truncation.
        assert_eq!(d(7, 3), 2);
        assert_eq!(d(-7, 3), -3, "truncation would give -2");

        // Inexact with a negative divisor: the remainder must stay
        // non-negative, so this rounds *up*, where floor rounds down.
        assert_eq!(d(7, -3), -2, "floor would give -3");
        assert_eq!(d(-7, -3), 3, "floor would give 2");

        // The retarget's own shape: a padded negative window time over
        // mainnet's target timespan.
        assert_eq!(d(-1i64 << 32, 43200), -99421, "truncation gives -99420");
    }

    /// dcrd's `mergeDifficulty` divides with `big.Int.Div` (Euclidean)
    /// at all three of its divisions.  The expected values are dcrd's
    /// own function run on these inputs; truncating `/` gives the
    /// values in the messages.  A negative fresh-stake change reaches
    /// the second division with a negative numerator, a negative old
    /// difficulty reaches the first, and the third inherits either.
    /// Positive inputs, the common case, agree under both rules, so the
    /// last case pins that nothing moved there.
    #[test]
    fn merge_difficulty_divides_as_go() {
        assert_eq!(
            merge_difficulty(300000000, 1200000000, -75000001),
            -300000005,
            "truncation gives -300000004"
        );
        assert_eq!(
            merge_difficulty(517465105, 1719199658, -464532170),
            -1543337978,
            "truncation gives -1543337977"
        );
        assert_eq!(
            merge_difficulty(-95323850, 2210689492, 1018408203),
            -23618268784,
            "truncation gives -23618268911"
        );
        assert_eq!(merge_difficulty(200000000, 800000000, 50000000), 200000000);
    }

    /// dcrd's `calcNextStakeDiffV2` divides with `big.Int.Div`
    /// (Euclidean) at both of its divisions.  The numerator carries the
    /// sign of the current difficulty, so the rules part only for a
    /// negative one (an sbits no stake-difficulty check vetted), and
    /// the result shows it once `Int64` keeps the low 64 bits of a
    /// quotient past 2^63, which lands this one inside the clamp range.
    /// The expected values are dcrd's own function run on these inputs
    /// with the mainnet parameters; truncating `/` gives the value in
    /// the message.  The last case pins a positive difficulty, where
    /// the two rules agree.
    #[test]
    fn calc_next_stake_diff_v2_divides_as_go() {
        let params = dcroxide_chaincfg::mainnet_params();
        assert_eq!(
            calc_next_stake_diff_v2(&params, 1000000, -3546182403, 40960, 3000000000),
            6257380983,
            "truncation gives 6257380984"
        );
        assert_eq!(
            calc_next_stake_diff_v2(&params, 1000000, 10000000000, 40960, 41500),
            9954336917
        );
    }
}
