// SPDX-License-Identifier: ISC
//! Block, work, vote, and treasury subsidy calculations (dcrd
//! blockchain/standalone `subsidy.go`).

use alloc::collections::BTreeMap;

/// The subsidy parameters required when calculating block and vote
/// subsidies, typically well-defined and unique per network (dcrd
/// `SubsidyParams`).
pub trait SubsidyParams {
    /// The total subsidy of block height 1 (initial coin distribution).
    fn block_one_subsidy(&self) -> i64;
    /// The starting base max potential subsidy for mined blocks.  Must
    /// be at most 140,739,635,871,744 atoms (MaxInt64/MaxUint16) or
    /// incorrect results will occur due to int64 overflow.
    fn base_subsidy_value(&self) -> i64;
    /// The multiplier for the exponential subsidy reduction.
    fn subsidy_reduction_multiplier(&self) -> i64;
    /// The divisor for the exponential subsidy reduction.
    fn subsidy_reduction_divisor(&self) -> i64;
    /// The reduction interval in blocks.
    fn subsidy_reduction_interval_blocks(&self) -> i64;
    /// The pre-DCP0010 PoW proportion of the subsidy split (a ratio to
    /// the sum of the three proportions, e.g. 6 of 6+3+1 => 60%).
    fn work_subsidy_proportion(&self) -> u16;
    /// The pre-DCP0010 PoS proportion of the subsidy split.
    fn stake_subsidy_proportion(&self) -> u16;
    /// The treasury proportion of the subsidy split.
    fn treasury_subsidy_proportion(&self) -> u16;
    /// The height at which votes become required to extend a block.
    fn stake_validation_begin_height(&self) -> i64;
    /// The maximum number of votes a block must contain to receive the
    /// full subsidy once voting begins.
    fn votes_per_block(&self) -> u16;
}

/// The available variants for subsidy split calculations (dcrd
/// `SubsidySplitVariant`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SubsidySplitVariant {
    /// The original split in effect at launch: 60% PoW, 30% PoS, 10%
    /// Treasury.
    Original,
    /// The modified split specified by DCP0010: 10% PoW, 80% PoS, 10%
    /// Treasury.
    Dcp0010,
    /// The modified split specified by DCP0012: 1% PoW, 89% PoS, 10%
    /// Treasury.
    Dcp0012,
}

/// Efficient access to consensus-critical subsidy calculations,
/// including the max potential subsidy for given block heights and the
/// proportional PoW, per-vote PoS, and treasury subsidies (dcrd
/// `SubsidyCache`).
///
/// Divergence from dcrd: dcrd guards its interval cache with an RWMutex
/// for concurrent use; this port requires `&mut self` instead.  The
/// cache is a pure result-invariant memoization, so calculated values
/// are unaffected.
pub struct SubsidyCache<P: SubsidyParams> {
    /// Cached subsidies keyed by reduction interval; interval 0 is
    /// seeded with the base subsidy.
    cache: BTreeMap<u64, i64>,
    /// The subsidy parameters to use during calculation.
    params: P,
    /// The minimum number of votes required for a block to be
    /// considered valid by consensus.
    min_votes_required: u16,
    /// The sum of the PoW, PoS, and Treasury proportions.
    total_proportions: u16,
}

impl<P: SubsidyParams> SubsidyCache<P> {
    /// Create and initialize a new subsidy cache (dcrd
    /// `NewSubsidyCache`).
    pub fn new(params: P) -> SubsidyCache<P> {
        let mut cache = BTreeMap::new();
        cache.insert(0, params.base_subsidy_value());

        SubsidyCache {
            min_votes_required: (params.votes_per_block() / 2) + 1,
            total_proportions: params.work_subsidy_proportion()
                + params.stake_subsidy_proportion()
                + params.treasury_subsidy_proportion(),
            cache,
            params,
        }
    }

    /// The subsidy parameters this cache was created with.
    pub fn params(&self) -> &P {
        &self.params
    }

    /// The max potential subsidy for a block at the provided height,
    /// reduced over time and then split proportionally between PoW,
    /// PoS, and the Treasury (dcrd `CalcBlockSubsidy`):
    ///
    /// ```text
    /// subsidy := BaseSubsidyValue()
    /// for i := 0; i < (height / SubsidyReductionIntervalBlocks()); i++ {
    ///   subsidy *= SubsidyReductionMultiplier()
    ///   subsidy /= SubsidyReductionDivisor()
    /// }
    /// ```
    pub fn calc_block_subsidy(&mut self, height: i64) -> i64 {
        // Negative block heights are invalid and produce no subsidy.
        // Block 0 is the genesis block and produces no subsidy.
        // Block 1 subsidy is special as it is used for initial token
        // distribution.
        if height <= 0 {
            return 0;
        }
        if height == 1 {
            return self.params.block_one_subsidy();
        }

        // Calculate the reduction interval associated with the requested
        // height and attempt to look it up in cache.
        let req_interval = (height / self.params.subsidy_reduction_interval_blocks()) as u64;
        if let Some(&cached) = self.cache.get(&req_interval) {
            return cached;
        }

        // Find the latest cached interval prior to the requested one to
        // use as a starting point for the calculation (interval 0 is
        // always seeded).  When the subsidy is already exhausted there,
        // every later interval is zero as well.
        let (&start_interval, &start_subsidy) = self
            .cache
            .range(..=req_interval)
            .next_back()
            .expect("interval 0 is always cached");
        if start_subsidy == 0 {
            return 0;
        }

        // Finally, calculate the subsidy by applying the appropriate
        // number of reductions per the starting and requested interval.
        let reduction_multiplier = self.params.subsidy_reduction_multiplier();
        let reduction_divisor = self.params.subsidy_reduction_divisor();
        let mut subsidy = start_subsidy;
        let mut cache_interval = req_interval;
        let needed_intervals = req_interval - start_interval;
        for i in 0..needed_intervals {
            subsidy *= reduction_multiplier;
            subsidy /= reduction_divisor;

            // Stop once no further reduction is possible.  This ensures
            // a bounded computation for large requested intervals and
            // that all future requests for intervals at or after the
            // final reduction interval return 0 without recalculating.
            if subsidy == 0 {
                cache_interval = start_interval + i + 1;
                break;
            }
        }

        // Update the cache for the requested interval or the interval in
        // which the subsidy became zero when applicable.
        self.cache.insert(cache_interval, subsidy);
        subsidy
    }

    /// The proof-of-work subsidy for the given proportion; the shared
    /// logic behind the three public work-subsidy variants (dcrd
    /// `calcWorkSubsidy`).
    fn calc_work_subsidy_inner(
        &mut self,
        height: i64,
        voters: u16,
        proportion: u16,
        total_proportions: u16,
    ) -> i64 {
        // The first block has special subsidy rules.
        if height == 1 {
            return self.params.block_one_subsidy();
        }

        // The subsidy is zero if there are not enough voters once voting
        // begins.  A block without enough voters will fail to validate
        // anyway.
        let stake_validation_height = self.params.stake_validation_begin_height();
        if height >= stake_validation_height && voters < self.min_votes_required {
            return 0;
        }

        // Calculate the full block subsidy and reduce it according to
        // the PoW proportion.
        let mut subsidy = self.calc_block_subsidy(height);
        subsidy *= i64::from(proportion);
        subsidy /= i64::from(total_proportions);

        // Ignore any potential subsidy reductions due to the number of
        // votes prior to the point voting begins.
        if height < stake_validation_height {
            return subsidy;
        }

        // Adjust for the number of voters.
        (i64::from(voters) * subsidy) / i64::from(self.params.votes_per_block())
    }

    /// The proof-of-work subsidy using the split in effect prior to
    /// DCP0010 (dcrd `CalcWorkSubsidy`; deprecated there in favor of the
    /// V3 variant).
    pub fn calc_work_subsidy(&mut self, height: i64, voters: u16) -> i64 {
        let proportion = self.params.work_subsidy_proportion();
        let total = self.total_proportions;
        self.calc_work_subsidy_inner(height, voters, proportion, total)
    }

    /// The proof-of-work subsidy using either the original split or the
    /// DCP0010 split per the provided flag (dcrd `CalcWorkSubsidyV2`;
    /// deprecated there in favor of the V3 variant).
    pub fn calc_work_subsidy_v2(&mut self, height: i64, voters: u16, use_dcp0010: bool) -> i64 {
        if !use_dcp0010 {
            return self.calc_work_subsidy(height, voters);
        }

        // The work subsidy proportion defined in DCP0010 is 10%.  Thus
        // it is 1 since 1/10 = 10%.
        const WORK_SUBSIDY_PROPORTION: u16 = 1;
        const TOTAL_PROPORTIONS: u16 = 10;
        self.calc_work_subsidy_inner(height, voters, WORK_SUBSIDY_PROPORTION, TOTAL_PROPORTIONS)
    }

    /// The proof-of-work subsidy using the split determined by the
    /// provided variant (dcrd `CalcWorkSubsidyV3`).
    pub fn calc_work_subsidy_v3(
        &mut self,
        height: i64,
        voters: u16,
        split_variant: SubsidySplitVariant,
    ) -> i64 {
        match split_variant {
            SubsidySplitVariant::Dcp0010 => {
                // The work subsidy proportion defined in DCP0010 is 10%.
                const WORK_SUBSIDY_PROPORTION: u16 = 10;
                const TOTAL_PROPORTIONS: u16 = 100;
                self.calc_work_subsidy_inner(
                    height,
                    voters,
                    WORK_SUBSIDY_PROPORTION,
                    TOTAL_PROPORTIONS,
                )
            }
            SubsidySplitVariant::Dcp0012 => {
                // The work subsidy proportion defined in DCP0012 is 1%.
                const WORK_SUBSIDY_PROPORTION: u16 = 1;
                const TOTAL_PROPORTIONS: u16 = 100;
                self.calc_work_subsidy_inner(
                    height,
                    voters,
                    WORK_SUBSIDY_PROPORTION,
                    TOTAL_PROPORTIONS,
                )
            }
            // Treat unknown subsidy split variants as the original.
            SubsidySplitVariant::Original => self.calc_work_subsidy(height, voters),
        }
    }

    /// The subsidy for a single stake vote for the given proportion; the
    /// shared logic behind the three public vote-subsidy variants (dcrd
    /// `calcStakeVoteSubsidy`).
    fn calc_stake_vote_subsidy_inner(
        &mut self,
        height: i64,
        proportion: u16,
        total_proportions: u16,
    ) -> i64 {
        // Votes have no subsidy prior to the point voting begins.  The
        // minus one accounts for the fact that vote subsidy are,
        // unfortunately, based on the height that is being voted on as
        // opposed to the block in which they are included.
        if height < self.params.stake_validation_begin_height() - 1 {
            return 0;
        }

        // Calculate the full block subsidy and reduce it according to
        // the stake proportion.  Then divide it by the number of votes
        // per block to arrive at the amount per vote.
        let mut subsidy = self.calc_block_subsidy(height);
        subsidy *= i64::from(proportion);
        subsidy /= i64::from(total_proportions) * i64::from(self.params.votes_per_block());

        subsidy
    }

    /// The subsidy for a single stake vote using the split in effect
    /// prior to DCP0010 (dcrd `CalcStakeVoteSubsidy`; deprecated there
    /// in favor of the V3 variant).
    pub fn calc_stake_vote_subsidy(&mut self, height: i64) -> i64 {
        let proportion = self.params.stake_subsidy_proportion();
        let total = self.total_proportions;
        self.calc_stake_vote_subsidy_inner(height, proportion, total)
    }

    /// The subsidy for a single stake vote using either the original
    /// split or the DCP0010 split per the provided flag (dcrd
    /// `CalcStakeVoteSubsidyV2`; deprecated there in favor of the V3
    /// variant).
    pub fn calc_stake_vote_subsidy_v2(&mut self, height: i64, use_dcp0010: bool) -> i64 {
        if !use_dcp0010 {
            return self.calc_stake_vote_subsidy(height);
        }

        // The stake vote subsidy proportion defined in DCP0010 is 80%.
        // Thus it is 8 since 8/10 = 80%.
        const VOTE_SUBSIDY_PROPORTION: u16 = 8;
        const TOTAL_PROPORTIONS: u16 = 10;
        self.calc_stake_vote_subsidy_inner(height, VOTE_SUBSIDY_PROPORTION, TOTAL_PROPORTIONS)
    }

    /// The subsidy for a single stake vote using the split determined by
    /// the provided variant (dcrd `CalcStakeVoteSubsidyV3`).
    pub fn calc_stake_vote_subsidy_v3(
        &mut self,
        height: i64,
        split_variant: SubsidySplitVariant,
    ) -> i64 {
        match split_variant {
            SubsidySplitVariant::Dcp0010 => {
                // The stake vote subsidy proportion defined in DCP0010 is
                // 80%.
                const VOTE_SUBSIDY_PROPORTION: u16 = 80;
                const TOTAL_PROPORTIONS: u16 = 100;
                self.calc_stake_vote_subsidy_inner(
                    height,
                    VOTE_SUBSIDY_PROPORTION,
                    TOTAL_PROPORTIONS,
                )
            }
            SubsidySplitVariant::Dcp0012 => {
                // The stake vote subsidy proportion defined in DCP0012 is
                // 89%.
                const VOTE_SUBSIDY_PROPORTION: u16 = 89;
                const TOTAL_PROPORTIONS: u16 = 100;
                self.calc_stake_vote_subsidy_inner(
                    height,
                    VOTE_SUBSIDY_PROPORTION,
                    TOTAL_PROPORTIONS,
                )
            }
            SubsidySplitVariant::Original => self.calc_stake_vote_subsidy(height),
        }
    }

    /// The subsidy required to go to the treasury for a block (dcrd
    /// `CalcTreasurySubsidy`).  When the treasury agenda is active, the
    /// rule changes from paying a proportion based on the number of
    /// votes to always paying the full subsidy.
    pub fn calc_treasury_subsidy(
        &mut self,
        height: i64,
        voters: u16,
        is_treasury_enabled: bool,
    ) -> i64 {
        // The first two blocks have special subsidy rules.
        if height <= 1 {
            return 0;
        }

        // The subsidy is zero if there are not enough voters once voting
        // begins.  A block without enough voters will fail to validate
        // anyway.
        let stake_validation_height = self.params.stake_validation_begin_height();
        if height >= stake_validation_height && voters < self.min_votes_required {
            return 0;
        }

        // Calculate the full block subsidy and reduce it according to
        // the treasury proportion.
        let mut subsidy = self.calc_block_subsidy(height);
        subsidy *= i64::from(self.params.treasury_subsidy_proportion());
        subsidy /= i64::from(self.total_proportions);

        // Ignore any potential subsidy reductions due to the number of
        // votes prior to the point voting begins or if treasury is
        // enabled.
        if height < stake_validation_height || is_treasury_enabled {
            return subsidy;
        }

        // Adjust for the number of voters.
        (i64::from(voters) * subsidy) / i64::from(self.params.votes_per_block())
    }
}
