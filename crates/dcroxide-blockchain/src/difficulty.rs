// SPDX-License-Identifier: ISC
//! The legacy difficulty retargeting algorithms (dcrd
//! internal/blockchain `difficulty.go`): the exponentially-weighted
//! BLAKE-256 work difficulty, the BLAKE3 (DCP0011) difficulty from an
//! anchor, and both stake difficulty algorithms (the original and the
//! DCP0001 replacement).
//!
//! dcrd computes these by walking `blockNode` parent pointers; this
//! port abstracts the walk behind [`ChainView`], a height-indexed view
//! of the branch ending at the node being extended.  The agenda-driven
//! selectors (which algorithm applies at a given block) live with the
//! threshold-state machinery in the chain engine; the RPC-only
//! `EstimateNextStakeDifficulty` variants are deferred with it.

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
pub trait ChainView {
    /// The node at the given height along this branch, or `None` when
    /// the height is negative or unknown.
    fn node(&self, height: i64) -> Option<DiffNode>;
}

/// The magic value of test network version 3 (wire `TestNet3`).
pub(crate) const TESTNET3_NET: u32 = 0xb194aa75;

pub(crate) fn is_testnet3(params: &Params) -> bool {
    params.net.0 == TESTNET3_NET
}

/// The maximum-difficulty target imposed on testnet (dcrd's
/// `minTestNetTarget`, powLimit >> 6), or `None` off testnet3.
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
    let blocks_per_retarget = params.work_diff_window_size * params.work_diff_windows;

    let mut iter = view.node(start_height);
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
    let next_height = prev_node.height + 1;
    if next_height % params.work_diff_window_size != 0 {
        // For networks that support it, allow special reduction of the
        // required difficulty once too much time has elapsed without
        // mining a block.
        if params.reduce_min_difficulty
            && (!is_testnet3(params) || next_height < TESTNET3_MAX_DIFF_ACTIVATION_HEIGHT)
        {
            let reduction_time = params.min_diff_reduction_time_secs;
            let allow_min_time = prev_node.timestamp + reduction_time;
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
    let next_diff_big_min = compact_to_big(prev_node.bits) / &raf_big;
    let next_diff_big_max = compact_to_big(prev_node.bits) * &raf_big;

    let alpha = params.work_diff_alpha;

    // Number of nodes to traverse while calculating difficulty.
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
        if i % params.work_diff_window_size == 0 && i != 0 {
            older_time = old_node.timestamp;
            let mut time_difference = recent_time - older_time;

            // Just assume we're at the target (no change) if we've
            // gone all the way back to the genesis block.
            if old_node.height == 0 {
                time_difference = params.target_timespan_secs;
            }

            let mut time_dif_big = BigInt::from(time_difference);
            time_dif_big <<= 32u32; // Add padding
            let target_temp = BigInt::from(params.target_timespan_secs);

            let mut window_adjusted = time_dif_big / target_temp;

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
        if old_node.height > 0 {
            if let Some(parent) = view.node(old_node.height - 1) {
                old_node = parent;
            }
        }
        i += 1;
    }

    // Sum up the weighted window periods.
    let mut weighted_sum = BigInt::from(0);
    for change in &window_changes {
        weighted_sum += change;
    }

    // Divide by the sum of all weights.
    let weights_big = BigInt::from(weights as i64);
    let weighted_sum_div = weighted_sum / weights_big;

    // Multiply by the old difficulty to get the new difficulty.
    let mut next_diff_big = weighted_sum_div * &old_diff_big;
    next_diff_big >>= 32u32; // Remove padding

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
    if let Some(min_target) = min_testnet_target(params) {
        if next_diff_big < min_target
            && (!is_testnet3(params) || next_height >= TESTNET3_MAX_DIFF_ACTIVATION_HEIGHT)
        {
            next_diff_big = min_target;
        }
    }

    // Convert the difficulty to the compact representation and return
    // it.
    big_to_compact(&next_diff_big)
}

/// Calculate the required BLAKE3 (DCP0011) difficulty for the block
/// after the given previous node using the given anchor node (dcrd
/// `calcNextBlake3DiffFromAnchor`).  The anchor is the first block for
/// which the agenda is always active; locating it requires the
/// threshold-state machinery and lives with the chain engine.
pub fn calc_next_blake3_diff_from_anchor(
    prev_node: &DiffNode,
    anchor: &DiffNode,
    params: &Params,
) -> u32 {
    // Calculate the time and height deltas as the difference between
    // the provided block and the anchor.
    let time_delta = prev_node.timestamp - anchor.timestamp;
    let height_delta = prev_node.height - anchor.height;

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
pub fn merge_difficulty(old_diff: i64, new_diff1: i64, new_diff2: i64) -> i64 {
    let new_diff1_big = BigInt::from(new_diff1);
    let mut new_diff2_big = BigInt::from(new_diff2);
    new_diff2_big <<= 32u32;

    let old_diff_big = BigInt::from(old_diff);
    let old_diff_big_lsh = BigInt::from(old_diff) << 32u32;

    // Divide the two changes; the result, in fixed point form, is in
    // the divisor.
    let new_diff1_big = old_diff_big_lsh / new_diff1_big;
    let new_diff2_big = new_diff2_big / &old_diff_big;

    // Precision multiply, then divide, then multiply by the original
    // difficulty and shed the padding.
    let mut summed_change = new_diff2_big;
    summed_change <<= 32u32;
    summed_change /= new_diff1_big;
    summed_change *= &old_diff_big;
    summed_change >>= 32u32;

    lossy_i64(&summed_change)
}

/// Clamp a candidate next stake difficulty to the maximum retarget per
/// dcrd's repeated pattern in `calcNextRequiredStakeDifficultyV1`.
fn clamp_v1_retarget(old_diff: i64, candidate: i64, max_retarget: i64) -> i64 {
    if candidate == 0 {
        old_diff / max_retarget
    } else if candidate / old_diff > (max_retarget - 1) {
        old_diff * max_retarget
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
    let stake_diff_start_height = i64::from(params.coinbase_maturity) + 1;
    let max_retarget = params.retarget_adjustment_factor;
    let ticket_pool_weight = i64::from(params.ticket_pool_size_weight);
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
    if (cur_node.height + 1) % params.stake_diff_window_size != 0 {
        return old_diff;
    }

    // The target size of the ticketPool in live tickets.
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

        if (i + 1) == nodes_to_traverse {
            break; // Exit for loop when we hit the end.
        }

        // Get the previous node while staying at the genesis block as
        // needed.
        if old_node.height > 0 {
            if let Some(parent) = view.node(old_node.height - 1) {
                old_node = parent;
            }
        }
        i += 1;
    }

    // Sum up the weighted window periods.
    let mut weighted_sum = BigInt::from(0);
    for change in &window_changes {
        weighted_sum += change;
    }

    // Divide by the sum of all weights, multiply by the old stake
    // difficulty, and shed the padding.
    let weights_big = BigInt::from(weights as i64);
    let weighted_sum_div = weighted_sum / weights_big;
    let mut next_diff_big = weighted_sum_div * BigInt::from(old_diff);
    next_diff_big >>= 32u32;
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
        window_fresh_stake += i64::from(old_node.fresh_stake);

        // Store and reset after reaching the end of every window
        // period.
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

        if (i + 1) == nodes_to_traverse {
            break; // Exit for loop when we hit the end.
        }

        // Get the previous node while staying at the genesis block as
        // needed.
        if old_node.height > 0 {
            if let Some(parent) = view.node(old_node.height - 1) {
                old_node = parent;
            }
        }
        i += 1;
    }

    // Sum up the weighted window periods.
    let mut weighted_sum = BigInt::from(0);
    for change in &window_changes {
        weighted_sum += change;
    }

    // Divide by the sum of all weights, multiply by the old stake
    // difficulty, and shed the padding.
    let weights_big = BigInt::from(weights as i64);
    let weighted_sum_div = weighted_sum / weights_big;
    let mut next_diff_big = weighted_sum_div * BigInt::from(old_diff);
    next_diff_big >>= 32u32;
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
    while num_traversed < num_to_sum {
        let Some(node) = view.node(height) else {
            break;
        };
        num_purchased += i64::from(node.fresh_stake);
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
    let target_pool_size_all = votes_per_block * (ticket_pool_size + ticket_maturity);
    let cur_pool_size_all_big = BigInt::from(cur_pool_size_all);
    let mut next_diff_big = BigInt::from(cur_diff);
    next_diff_big *= &cur_pool_size_all_big;
    next_diff_big *= &cur_pool_size_all_big;
    next_diff_big /= BigInt::from(prev_pool_size_all);
    next_diff_big /= BigInt::from(target_pool_size_all);

    // Limit the new stake difficulty between the minimum allowed stake
    // difficulty and a maximum value that is relative to the total
    // supply.
    let mut next_diff = lossy_i64(&next_diff_big);
    let estimated_supply = estimate_supply(params, next_height);
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
        Some(node) => node.height + 1,
        None => 0,
    };
    let stake_diff_start_height = i64::from(params.coinbase_maturity) + 1;
    if next_height < stake_diff_start_height {
        return params.minimum_stake_diff;
    }
    let cur_node = cur_node.expect("next_height >= start height implies a node");

    // Return the previous block's difficulty requirements if the next
    // block is not at a difficulty retarget interval.
    let interval_size = params.stake_diff_window_size;
    let cur_diff = cur_node.sbits;
    if next_height % interval_size != 0 {
        return cur_diff;
    }

    // Get the pool size and number of tickets that were immature at the
    // previous retarget interval.
    let mut prev_pool_size: i64 = 0;
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
    let prev_pool_size_all = prev_pool_size + prev_immature_tickets;
    if prev_pool_size_all == 0 {
        return cur_diff;
    }

    // Count the number of currently immature tickets.
    let immature_tickets = sum_purchased_tickets(view, Some(cur_node.height), ticket_maturity);

    // Calculate and return the final next required difficulty.
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
    let stake_diff_start_height = i64::from(params.coinbase_maturity) + 1;
    let max_retarget = params.retarget_adjustment_factor;
    let ticket_pool_weight = i64::from(params.ticket_pool_size_weight);

    // Number of nodes to traverse while calculating difficulty.
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
    if (cur_node.height + 1) % params.stake_diff_window_size != 0 {
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

        if (i + 1) == nodes_to_traverse {
            break; // Exit for loop when we hit the end.
        }

        // Get the previous node while staying at the genesis block as
        // needed.
        if old_node.height > 0 {
            if let Some(parent) = est_view.node(old_node.height - 1) {
                old_node = parent;
            }
        }
        i += 1;
    }

    // Sum up the weighted window periods.
    let mut weighted_sum = BigInt::from(0);
    for change in &window_changes {
        weighted_sum += change;
    }

    // Divide by the sum of all weights, multiply by the old stake
    // difficulty, and shed the padding.
    let weights_big = BigInt::from(weights as i64);
    let weighted_sum_div = weighted_sum / weights_big;
    let mut next_diff_big = weighted_sum_div * BigInt::from(old_diff);
    next_diff_big >>= 32u32;
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
        window_fresh_stake += i64::from(old_node.fresh_stake);

        // Store and reset after reaching the end of every window
        // period.
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

        if (i + 1) == nodes_to_traverse {
            break; // Exit for loop when we hit the end.
        }

        // Get the previous node while staying at the genesis block as
        // needed.
        if old_node.height > 0 {
            if let Some(parent) = est_view.node(old_node.height - 1) {
                old_node = parent;
            }
        }
        i += 1;
    }

    // Sum up the weighted window periods.
    let mut weighted_sum = BigInt::from(0);
    for change in &window_changes {
        weighted_sum += change;
    }

    // Divide by the sum of all weights, multiply by the old stake
    // difficulty, and shed the padding.
    let weights_big = BigInt::from(weights as i64);
    let weighted_sum_div = weighted_sum / weights_big;
    let mut next_diff_big = weighted_sum_div * BigInt::from(old_diff);
    next_diff_big >>= 32u32;
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
    let blocks_until_retarget = interval_size - cur_height % interval_size;
    let next_retarget_height = cur_height + blocks_until_retarget;

    // Calculate the maximum possible number of tickets that could be
    // sold in the remainder of the interval and potentially override
    // the number of new tickets to include in the estimate per the
    // user-specified flag.
    let max_tickets_per_block = i64::from(params.max_fresh_stake_per_block);
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
    let next_maturity_floor = next_retarget_height - ticket_maturity - 1;
    if cur_height > next_maturity_floor {
        remaining_immature_tickets = sum_purchased_tickets(
            view,
            Some(cur_node.height),
            cur_height - next_maturity_floor,
        );
    }

    // Add the number of tickets that will still be immature at the
    // next retarget based on the estimated data.
    let max_immature_tickets = ticket_maturity * max_tickets_per_block;
    if new_tickets > max_immature_tickets {
        remaining_immature_tickets += max_immature_tickets;
    } else {
        remaining_immature_tickets += new_tickets;
    }

    // Calculate the number of tickets that will mature in the
    // remainder of the interval based on the known (non-estimated)
    // data.
    //
    // NOTE: The pool size in the block headers does not include the
    // tickets maturing at the height in which they mature since they
    // are not eligible for selection until the next block, so exclude
    // them by starting one block before the next maturity floor.
    let mut final_maturing_height = next_maturity_floor - 1;
    if final_maturing_height > cur_height {
        final_maturing_height = cur_height;
    }
    let final_maturing_node = view.node(final_maturing_height);
    let first_maturing_height = cur_height - ticket_maturity;
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
        let maturing_estimate_nodes = next_maturity_floor - cur_height - 1;
        let mut maturing_estimated_tickets = max_tickets_per_block * maturing_estimate_nodes;
        if maturing_estimated_tickets > new_tickets {
            maturing_estimated_tickets = new_tickets;
        }
        maturing_tickets += maturing_estimated_tickets;
    }

    // Calculate the number of votes that will occur during the
    // remainder of the interval.
    let stake_validation_height = params.stake_validation_height;
    let mut pending_votes: i64 = 0;
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
    let estimated_pool_size = cur_pool_size + maturing_tickets - pending_votes;
    let estimated_pool_size_all = estimated_pool_size + remaining_immature_tickets;

    // Calculate and return the final estimated difficulty.
    Ok(calc_next_stake_diff_v2(
        params,
        next_retarget_height,
        cur_diff,
        prev_pool_size_all,
        estimated_pool_size_all,
    ))
}
