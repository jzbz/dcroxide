// SPDX-License-Identifier: ISC
//! dcrd's subsidy test vectors, ported from blockchain/standalone
//! `subsidy_test.go` at the pinned tag: the full calculation tables
//! (mechanically extracted into `data/subsidy_vectors.txt`), the four
//! total-supply schedule walks, and sparse cache-access equivalence.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_standalone::{SubsidyCache, SubsidyParams, SubsidySplitVariant};

/// Mock mainnet subsidy parameters matching dcrd's mockMainNetParams.
#[derive(Copy, Clone)]
struct MockMainNetParams;

impl SubsidyParams for MockMainNetParams {
    fn block_one_subsidy(&self) -> i64 {
        168_000_000_000_000
    }
    fn base_subsidy_value(&self) -> i64 {
        3_119_582_664
    }
    fn subsidy_reduction_multiplier(&self) -> i64 {
        100
    }
    fn subsidy_reduction_divisor(&self) -> i64 {
        101
    }
    fn subsidy_reduction_interval_blocks(&self) -> i64 {
        6144
    }
    fn work_subsidy_proportion(&self) -> u16 {
        6
    }
    fn stake_subsidy_proportion(&self) -> u16 {
        3
    }
    fn treasury_subsidy_proportion(&self) -> u16 {
        1
    }
    fn stake_validation_begin_height(&self) -> i64 {
        4096
    }
    fn votes_per_block(&self) -> u16 {
        5
    }
}

const NO_TREASURY: bool = false;
const WITH_TREASURY: bool = true;

fn parse_variant(s: &str) -> SubsidySplitVariant {
    match s {
        "SSVOriginal" => SubsidySplitVariant::Original,
        "SSVDCP0010" => SubsidySplitVariant::Dcp0010,
        "SSVDCP0012" => SubsidySplitVariant::Dcp0012,
        other => panic!("unknown split variant {other}"),
    }
}

/// dcrd TestSubsidyCacheCalcs and TestSubsidyCacheCalcsTreasury, replayed
/// from the mechanically extracted tables.
#[test]
fn subsidy_cache_calc_tables() {
    let data = include_str!("data/subsidy_vectors.txt");
    let mut rows = 0usize;
    for line in data.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        // A fresh cache per row, exactly like dcrd's test.
        let mut cache = SubsidyCache::new(MockMainNetParams);
        match fields[0] {
            "calc" => {
                let height: i64 = fields[1].parse().expect("height");
                let votes: u16 = fields[2].parse().expect("votes");
                let variant = parse_variant(fields[3]);
                let want_full: i64 = fields[4].parse().expect("full");
                let want_work: i64 = fields[5].parse().expect("work");
                let want_vote: i64 = fields[6].parse().expect("vote");
                let want_treasury: i64 = fields[7].parse().expect("treasury");

                assert_eq!(cache.calc_block_subsidy(height), want_full, "{line}: full");
                assert_eq!(
                    cache.calc_work_subsidy_v3(height, votes, variant),
                    want_work,
                    "{line}: work"
                );
                assert_eq!(
                    cache.calc_stake_vote_subsidy_v3(height, variant),
                    want_vote,
                    "{line}: vote"
                );
                assert_eq!(
                    cache.calc_treasury_subsidy(height, votes, NO_TREASURY),
                    want_treasury,
                    "{line}: treasury"
                );
            }
            "calct" => {
                let height: i64 = fields[1].parse().expect("height");
                let votes: u16 = fields[2].parse().expect("votes");
                let want_full: i64 = fields[3].parse().expect("full");
                let want_work: i64 = fields[4].parse().expect("work");
                let want_vote: i64 = fields[5].parse().expect("vote");
                let want_treasury: i64 = fields[6].parse().expect("treasury");

                assert_eq!(cache.calc_block_subsidy(height), want_full, "{line}: full");
                assert_eq!(
                    cache.calc_work_subsidy(height, votes),
                    want_work,
                    "{line}: work"
                );
                assert_eq!(
                    cache.calc_stake_vote_subsidy(height),
                    want_vote,
                    "{line}: vote"
                );
                assert_eq!(
                    cache.calc_treasury_subsidy(height, votes, WITH_TREASURY),
                    want_treasury,
                    "{line}: treasury"
                );
            }
            other => panic!("unknown row tag {other}"),
        }
        rows += 1;
    }
    assert_eq!(rows, 82, "expected all extracted table rows");
}

/// dcrd TestTotalSubsidy: walking the entire reduction schedule with the
/// original split must produce the expected total supply.
#[test]
fn total_subsidy_original() {
    let params = MockMainNetParams;
    let reduction_interval = params.subsidy_reduction_interval_blocks();
    let stake_validation_height = params.stake_validation_begin_height();
    let votes_per_block = params.votes_per_block();

    let mut cache = SubsidyCache::new(params);
    let mut subsidy_sum = |height: i64| -> i64 {
        let work = cache.calc_work_subsidy(height, votes_per_block);
        let vote = cache.calc_stake_vote_subsidy(height) * i64::from(votes_per_block);
        let treasury = cache.calc_treasury_subsidy(height, votes_per_block, NO_TREASURY);
        work + vote + treasury
    };

    let mut total_subsidy = params.block_one_subsidy();
    let mut reduction_num: i64 = 0;
    loop {
        if reduction_num == 0 {
            // Account for the blocks up to the point voting begins,
            // ignoring the first two special blocks, then the rest of
            // the first interval once voting begins.
            let non_voting_blocks = stake_validation_height - 2;
            total_subsidy += subsidy_sum(2) * non_voting_blocks;

            let voting_blocks = reduction_interval - stake_validation_height;
            total_subsidy += subsidy_sum(stake_validation_height) * voting_blocks;
            reduction_num += 1;
            continue;
        }

        let subsidy_calc_height = reduction_num * reduction_interval;
        let sum = subsidy_sum(subsidy_calc_height);
        if sum == 0 {
            break;
        }
        total_subsidy += sum * reduction_interval;
        reduction_num += 1;
    }

    assert_eq!(total_subsidy, 2_099_999_999_800_912);
}

/// dcrd TestTotalSubsidyTreasury: the treasury-agenda payout rules must
/// not change the total supply.
#[test]
fn total_subsidy_treasury() {
    let params = MockMainNetParams;
    let reduction_interval = params.subsidy_reduction_interval_blocks();
    let stake_validation_height = params.stake_validation_begin_height();
    let votes_per_block = params.votes_per_block();

    let mut cache = SubsidyCache::new(params);
    let mut subsidy_sum = |height: i64| -> i64 {
        let work = cache.calc_work_subsidy(height, votes_per_block);
        let vote = cache.calc_stake_vote_subsidy(height) * i64::from(votes_per_block);
        let treasury = cache.calc_treasury_subsidy(height, votes_per_block, WITH_TREASURY);
        work + vote + treasury
    };

    let mut total_subsidy = params.block_one_subsidy();
    let mut reduction_num: i64 = 0;
    loop {
        if reduction_num == 0 {
            let non_voting_blocks = stake_validation_height - 2;
            total_subsidy += subsidy_sum(2) * non_voting_blocks;

            let voting_blocks = reduction_interval - stake_validation_height;
            total_subsidy += subsidy_sum(stake_validation_height) * voting_blocks;
            reduction_num += 1;
            continue;
        }

        let subsidy_calc_height = reduction_num * reduction_interval;
        let sum = subsidy_sum(subsidy_calc_height);
        if sum == 0 {
            break;
        }
        total_subsidy += sum * reduction_interval;
        reduction_num += 1;
    }

    assert_eq!(total_subsidy, 2_099_999_999_800_912);
}

/// dcrd TestTotalSubsidyDCP0010: the DCP0010 split changeover at the
/// estimated activation height keeps the total supply as expected.
#[test]
fn total_subsidy_dcp0010() {
    let params = MockMainNetParams;
    let reduction_interval = params.subsidy_reduction_interval_blocks();
    let stake_validation_height = params.stake_validation_begin_height();
    let votes_per_block = params.votes_per_block();

    let mut cache = SubsidyCache::new(params);
    let mut subsidy_sum = |height: i64, use_dcp0010: bool| -> i64 {
        let work = cache.calc_work_subsidy_v2(height, votes_per_block, use_dcp0010);
        let vote =
            cache.calc_stake_vote_subsidy_v2(height, use_dcp0010) * i64::from(votes_per_block);
        let treasury = cache.calc_treasury_subsidy(height, votes_per_block, NO_TREASURY);
        work + vote + treasury
    };

    let mut total_subsidy = params.block_one_subsidy();
    let mut reduction_num: i64 = 0;
    loop {
        if reduction_num == 0 {
            let non_voting_blocks = stake_validation_height - 2;
            total_subsidy += subsidy_sum(2, false) * non_voting_blocks;

            let voting_blocks = reduction_interval - stake_validation_height;
            total_subsidy += subsidy_sum(stake_validation_height, false) * voting_blocks;
            reduction_num += 1;
            continue;
        }

        // The estimated DCP0010 activation height for testing purposes
        // is the 104th reduction interval on mainnet (638976).
        let subsidy_calc_height = reduction_num * reduction_interval;
        let use_dcp0010 = subsidy_calc_height >= reduction_interval * 104;
        let sum = subsidy_sum(subsidy_calc_height, use_dcp0010);
        if sum == 0 {
            break;
        }
        total_subsidy += sum * reduction_interval;
        reduction_num += 1;
    }

    assert_eq!(total_subsidy, 2_100_000_000_015_952);
}

/// dcrd TestTotalSubsidyDCP0012: both split changeovers (DCP0010 at
/// 657280 and estimated DCP0012 at 782208) keep the total supply as
/// expected, including the partial intervals.
#[test]
fn total_subsidy_dcp0012() {
    let params = MockMainNetParams;
    let reduction_interval = params.subsidy_reduction_interval_blocks();
    let stake_validation_height = params.stake_validation_begin_height();
    let votes_per_block = params.votes_per_block();

    let mut cache = SubsidyCache::new(params);
    let mut subsidy_sum = |height: i64, split_variant: SubsidySplitVariant| -> i64 {
        let work = cache.calc_work_subsidy_v3(height, votes_per_block, split_variant);
        let vote =
            cache.calc_stake_vote_subsidy_v3(height, split_variant) * i64::from(votes_per_block);
        let treasury = cache.calc_treasury_subsidy(height, votes_per_block, NO_TREASURY);
        work + vote + treasury
    };

    const DCP0010_ACTIVATION_HEIGHT: i64 = 657280;
    const ESTIMATED_DCP0012_ACTIVATION_HEIGHT: i64 = 782208;

    let mut total_subsidy = params.block_one_subsidy();
    let mut reduction_num: i64 = 0;
    loop {
        if reduction_num == 0 {
            let non_voting_blocks = stake_validation_height - 2;
            total_subsidy += subsidy_sum(2, SubsidySplitVariant::Original) * non_voting_blocks;

            let voting_blocks = reduction_interval - stake_validation_height;
            total_subsidy +=
                subsidy_sum(stake_validation_height, SubsidySplitVariant::Original) * voting_blocks;
            reduction_num += 1;
            continue;
        }

        // Account for partial intervals with subsidy split changes.
        let mut subsidy_calc_height = reduction_num * reduction_interval;
        let change = if reduction_num == DCP0010_ACTIVATION_HEIGHT / reduction_interval {
            Some((
                DCP0010_ACTIVATION_HEIGHT,
                SubsidySplitVariant::Original,
                SubsidySplitVariant::Dcp0010,
            ))
        } else if reduction_num == ESTIMATED_DCP0012_ACTIVATION_HEIGHT / reduction_interval {
            Some((
                ESTIMATED_DCP0012_ACTIVATION_HEIGHT,
                SubsidySplitVariant::Dcp0010,
                SubsidySplitVariant::Dcp0012,
            ))
        } else {
            None
        };
        if let Some((activation_height, split_before, split_after)) = change {
            // Blocks up to the point the subsidy split changed, then the
            // remaining blocks in the interval after the change.
            let pre_change_blocks = activation_height - subsidy_calc_height;
            total_subsidy += subsidy_sum(subsidy_calc_height, split_before) * pre_change_blocks;

            subsidy_calc_height = activation_height;
            let remaining_blocks = reduction_interval - pre_change_blocks;
            total_subsidy += subsidy_sum(subsidy_calc_height, split_after) * remaining_blocks;
            reduction_num += 1;
            continue;
        }

        let split_variant = if subsidy_calc_height >= ESTIMATED_DCP0012_ACTIVATION_HEIGHT {
            SubsidySplitVariant::Dcp0012
        } else if subsidy_calc_height >= DCP0010_ACTIVATION_HEIGHT {
            SubsidySplitVariant::Dcp0010
        } else {
            SubsidySplitVariant::Original
        };
        let sum = subsidy_sum(subsidy_calc_height, split_variant);
        if sum == 0 {
            break;
        }
        total_subsidy += sum * reduction_interval;
        reduction_num += 1;
    }

    assert_eq!(total_subsidy, 2_099_999_998_387_408);
}

/// Sparse, out-of-order cache access must produce identical results to
/// sequential access (the moral equivalent of dcrd's
/// TestCalcBlockSubsidySparseCaching, which validates that the interval
/// cache is result-invariant).
#[test]
fn sparse_cache_access_equivalence() {
    let params = MockMainNetParams;
    let interval = params.subsidy_reduction_interval_blocks();

    // Heights chosen to hit far-future intervals first, then earlier
    // ones, then in-between values, mirroring dcrd's scenarios.
    let heights = [
        interval * 2 + 1,
        interval * 12 + 1,
        interval * 6 + 1,
        1,
        interval * 240 + 1,
        interval * 120 + 1,
        interval * 900 + 1,
        interval - 1,
        interval,
        interval + 1,
    ];

    let mut sparse = SubsidyCache::new(params);
    let sparse_results: Vec<i64> = heights
        .iter()
        .map(|&h| sparse.calc_block_subsidy(h))
        .collect();

    for (&height, &sparse_result) in heights.iter().zip(&sparse_results) {
        // A fresh cache queried directly must agree.
        let mut fresh = SubsidyCache::new(params);
        assert_eq!(
            fresh.calc_block_subsidy(height),
            sparse_result,
            "height {height}"
        );
    }
}
