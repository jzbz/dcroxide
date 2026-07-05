// SPDX-License-Identifier: ISC
//! Stake version tallying and related interval math (dcrd
//! internal/blockchain `stakeversion.go`, plus `calcWantHeight` and the
//! past-median-time calculation the threshold state machine consumes).
//!
//! Like the difficulty port, dcrd's parent-pointer walks are abstracted
//! behind a height-indexed view.  dcrd's per-hash memoization caches
//! are result-invariant and not reproduced.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use dcroxide_chaincfg::Params;

/// The number of previous blocks a past median time considers (dcrd
/// `medianTimeBlocks`).
pub const MEDIAN_TIME_BLOCKS: usize = 11;

/// The per-node data the stake version calculations consume (the used
/// subset of dcrd's `blockNode`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VersionNode {
    /// Block height.
    pub height: i64,
    /// Header timestamp as unix seconds.
    pub timestamp: i64,
    /// Block (header) version.
    pub block_version: i32,
    /// Stake version committed by the header.
    pub stake_version: u32,
    /// The vote versions carried by the votes in the block.
    pub vote_versions: Vec<u32>,
}

/// A height-indexed view of the branch of block nodes ending at the
/// block being extended.
pub trait VersionChainView {
    /// The node at the given height along this branch, or `None` when
    /// the height is negative or unknown.
    fn node(&self, height: i64) -> Option<VersionNode>;
}

/// The height of the final block in the interval that occurred before
/// the provided height (dcrd `calcWantHeight`); the first interval
/// after the stake validation height is one block shorter.
pub fn calc_want_height(stake_validation_height: i64, interval: i64, height: i64) -> i64 {
    let interval_offset = stake_validation_height % interval;
    let adjusted_height = height - interval_offset - 1;
    (adjusted_height - ((adjusted_height + 1) % interval)) + interval_offset
}

/// The median time of the previous few blocks at the given height
/// (dcrd `blockNode.CalcPastMedianTime`), preserving dcrd's
/// simple-middle-element behavior for even counts near genesis.
pub fn calc_past_median_time(view: &impl VersionChainView, height: i64) -> i64 {
    let mut timestamps = Vec::with_capacity(MEDIAN_TIME_BLOCKS);
    let mut h = height;
    for _ in 0..MEDIAN_TIME_BLOCKS {
        let Some(node) = view.node(h) else {
            break;
        };
        timestamps.push(node.timestamp);
        if h == 0 {
            break;
        }
        h -= 1;
    }
    timestamps.sort_unstable();
    timestamps[timestamps.len() / 2]
}

/// The final node of the previous stake version interval, or `None`
/// before one exists (dcrd `findStakeVersionPriorNode`).
fn find_stake_version_prior_height(prev_height: i64, params: &Params) -> Option<i64> {
    let svh = params.stake_validation_height;
    let svi = params.stake_version_interval;
    let next_height = prev_height + 1;
    if next_height < svh + svi {
        return None;
    }
    Some(calc_want_height(svh, svi, next_height))
}

/// Whether the given minimum stake version was met by the majority of
/// headers over the previous interval (dcrd `isStakeMajorityVersion`).
pub fn is_stake_majority_version(
    view: &impl VersionChainView,
    min_ver: u32,
    prev_height: i64,
    params: &Params,
) -> bool {
    let Some(start) = find_stake_version_prior_height(prev_height, params) else {
        return min_ver == 0;
    };

    let mut version_count: i32 = 0;
    let mut h = start;
    for _ in 0..params.stake_version_interval {
        let Some(node) = view.node(h) else {
            break;
        };
        if node.stake_version >= min_ver {
            version_count += 1;
        }
        if h == 0 {
            break;
        }
        h -= 1;
    }

    let num_required = params.stake_version_interval as i32 * params.stake_majority_multiplier
        / params.stake_majority_divisor;
    version_count >= num_required
}

/// The header stake version a supermajority of the previous interval
/// committed to, or `None` when no version reached a majority (dcrd
/// `calcPriorStakeVersion`; the nil-node case yields `Some(0)`).
pub fn calc_prior_stake_version(
    view: &impl VersionChainView,
    prev_height: i64,
    params: &Params,
) -> Option<u32> {
    let Some(start) = find_stake_version_prior_height(prev_height, params) else {
        return Some(0);
    };

    let mut versions: BTreeMap<u32, i32> = BTreeMap::new();
    let mut h = start;
    for _ in 0..params.stake_version_interval {
        let Some(node) = view.node(h) else {
            break;
        };
        *versions.entry(node.stake_version).or_insert(0) += 1;
        if h == 0 {
            break;
        }
        h -= 1;
    }

    // At most one version can reach the supermajority, so dcrd's
    // random map iteration order is immaterial.
    let num_required = params.stake_version_interval as i32 * params.stake_majority_multiplier
        / params.stake_majority_divisor;
    versions
        .into_iter()
        .find(|(_, count)| *count >= num_required)
        .map(|(version, _)| version)
}

/// The version of the votes in the stake version interval ending at the
/// given height, or `None` when no version reached a majority (dcrd
/// `calcVoterVersionInterval`).  Must be called with the final node of
/// an interval, like dcrd asserts.
pub fn calc_voter_version_interval(
    view: &impl VersionChainView,
    interval_end_height: i64,
    params: &Params,
) -> Option<u32> {
    let svh = params.stake_validation_height;
    let svi = params.stake_version_interval;
    let expected = calc_want_height(svh, svi, interval_end_height + 1);
    assert!(
        interval_end_height == expected && expected >= svh,
        "calcVoterVersionInterval must be called with the final node in a stake \
         version interval"
    );

    let mut versions: BTreeMap<u32, i32> = BTreeMap::new();
    let mut total_votes_found: i32 = 0;
    let mut h = interval_end_height;
    for _ in 0..svi {
        let Some(node) = view.node(h) else {
            break;
        };
        total_votes_found += node.vote_versions.len() as i32;
        for v in &node.vote_versions {
            *versions.entry(*v).or_insert(0) += 1;
        }
        if h == 0 {
            break;
        }
        h -= 1;
    }

    let num_required =
        total_votes_found * params.stake_majority_multiplier / params.stake_majority_divisor;
    versions
        .into_iter()
        .find(|(_, count)| *count >= num_required)
        .map(|(version, _)| version)
}

/// The last majority vote version walking backwards one interval at a
/// time, plus the height of the interval-final node it was found at
/// (dcrd `calcVoterVersion`); `(0, None)` when none is found.
pub fn calc_voter_version(
    view: &impl VersionChainView,
    prev_height: i64,
    params: &Params,
) -> (u32, Option<i64>) {
    let mut node_height = find_stake_version_prior_height(prev_height, params);
    while let Some(h) = node_height {
        if h < params.stake_validation_height || view.node(h).is_none() {
            break;
        }
        if let Some(version) = calc_voter_version_interval(view, h, params) {
            return (version, Some(h));
        }
        let next = h - params.stake_version_interval;
        node_height = if next >= 0 { Some(next) } else { None };
    }
    (0, None)
}

/// Whether a majority of the last few block header versions meet the
/// given minimum (dcrd `isMajorityVersion`).
pub fn is_majority_version(
    view: &impl VersionChainView,
    min_ver: i32,
    start_height: Option<i64>,
    num_required: u64,
    params: &Params,
) -> bool {
    let mut num_found: u64 = 0;
    let mut height = start_height;
    let mut i: u64 = 0;
    while i < params.block_upgrade_num_to_check && num_found < num_required {
        let Some(h) = height else {
            break;
        };
        let Some(node) = view.node(h) else {
            break;
        };
        if node.block_version >= min_ver {
            num_found += 1;
        }
        height = if h > 0 { Some(h - 1) } else { None };
        i += 1;
    }
    num_found >= num_required
}

/// The expected stake version for the block after the given node (dcrd
/// `calcStakeVersion`).
pub fn calc_stake_version(view: &impl VersionChainView, prev_height: i64, params: &Params) -> u32 {
    let (mut version, node_height) = calc_voter_version(view, prev_height, params);
    if version == 0 || node_height.is_none() {
        return 0;
    }
    let node_height = node_height.expect("checked above");

    // Note that dcrd's nil-ancestor branch here records a zero in its
    // cache without returning; the subsequent majority check over the
    // missing node then yields false anyway, which this preserves by
    // simply passing the missing start along.
    let start_interval_height = calc_want_height(
        params.stake_validation_height,
        params.stake_version_interval,
        node_height,
    ) + 1;
    let start_height = if start_interval_height >= 0 && start_interval_height <= node_height {
        view.node(start_interval_height).map(|n| n.height)
    } else {
        None
    };

    // The passed stake version expects the block version to be equal or
    // greater than the version in which stake voting was activated.
    if !is_majority_version(
        view,
        3,
        start_height,
        params.block_reject_num_required,
        params,
    ) {
        return 0;
    }

    if is_stake_majority_version(view, version, node_height, params) {
        if let Some(prior_version) = calc_prior_stake_version(view, node_height, params) {
            if prior_version > version {
                version = prior_version;
            }
        }
    }
    version
}
