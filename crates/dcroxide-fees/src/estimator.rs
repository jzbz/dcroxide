// SPDX-License-Identifier: ISC

//! The fee estimator from dcrd's `internal/fees` `estimator.go`:
//! historical confirmation tracking over exponentially spaced fee
//! rate buckets with decaying moving averages, and the median fee
//! estimation over a target confirmation window.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use dcroxide_chainhash::Hash;
use dcroxide_stake::TxType;

/// The default multiplier used to find the largest fee bucket,
/// starting at the minimum fee (dcrd `DefaultMaxBucketFeeMultiplier`).
pub const DEFAULT_MAX_BUCKET_FEE_MULTIPLIER: i64 = 100;

/// The default number of confirmation ranges to track (dcrd
/// `DefaultMaxConfirmations`).
pub const DEFAULT_MAX_CONFIRMATIONS: u32 = 32;

/// The default multiplier between two consecutive fee rate buckets
/// (dcrd `DefaultFeeRateStep`).
pub const DEFAULT_FEE_RATE_STEP: f64 = 1.1;

/// The default value used to decay old transactions from the
/// estimator (dcrd `defaultDecay`).
const DEFAULT_DECAY: f64 = 0.998;

/// The upper bound of how many confirmation ranges can be used (dcrd
/// `maxAllowedConfirms`).
const MAX_ALLOWED_CONFIRMS: u32 = 788;

/// The per-confirmation-range counters of a fee bucket (dcrd
/// `txConfirmStatBucketCount`).
#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub struct TxConfirmStatBucketCount {
    /// The (decayed) transaction count.
    pub tx_count: f64,
    /// The (decayed) fee sum.
    pub fee_sum: f64,
}

/// A fee bucket's confirmation statistics (dcrd
/// `txConfirmStatBucket`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TxConfirmStatBucket {
    /// The per-confirmation-range counters.
    pub confirmed: Vec<TxConfirmStatBucketCount>,
    /// The total confirmed count.
    pub confirm_count: f64,
    /// The total fee sum.
    pub fee_sum: f64,
}

/// The configuration parameters for a fee estimator (dcrd
/// `EstimatorConfig`; the database file and bucket replacement options
/// belong to the persistence plumbing).
#[derive(Clone, Debug)]
pub struct EstimatorConfig {
    /// The maximum number of confirmation ranges to check.
    pub max_confirms: u32,
    /// The fee rate of the lowest tracked bucket, in atoms/KB.
    pub min_bucket_fee: i64,
    /// The fee rate of the highest tracked bucket; must be higher than
    /// the minimum.
    pub max_bucket_fee: i64,
    /// An additional bucket fee rate to track; ignored unless it lies
    /// between the minimum and maximum.
    pub extra_bucket_fee: i64,
    /// The multiplier between consecutive fee rate buckets; must be
    /// greater than 1.
    pub fee_rate_step: f64,
}

/// The tracked mempool entry (dcrd `memPoolTxDesc`).
#[derive(Copy, Clone, Debug)]
struct MemPoolTxDesc {
    added_height: i64,
    fees: f64,
}

/// The errors from the median fee estimation (dcrd's estimate
/// errors).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EstimateFeeError {
    /// The target confirmation range is not positive.
    NonPositiveTarget,
    /// The requested confirmation range is higher than tracked (dcrd
    /// `ErrTargetConfTooLarge`).
    TargetConfTooLarge {
        /// The maximum tracked confirmation range.
        max_confirms: i32,
        /// The requested confirmation range.
        req_confirms: i32,
    },
    /// No bucket with the minimum required success percentage was
    /// found (dcrd `ErrNoSuccessPctBucketFound`).
    NoSuccessPctBucketFound,
    /// Not enough transactions have been seen for an estimate (dcrd
    /// `ErrNotEnoughTxsForEstimate`).
    NotEnoughTxsForEstimate,
}

/// The fee estimator (dcrd `Estimator`; the leveldb handle and lock
/// are plumbing).
pub struct Estimator {
    /// The upper bounds for each fee bucket, the last being +inf.
    pub bucket_fee_bounds: Vec<f64>,
    /// The confirmed statistics by bucket.
    pub buckets: Vec<TxConfirmStatBucket>,
    /// The mempool statistics by bucket.
    pub mem_pool: Vec<TxConfirmStatBucket>,
    mem_pool_txs: BTreeMap<[u8; 32], MemPoolTxDesc>,
    max_confirms: i32,
    decay: f64,
    best_height: i64,
}

impl Estimator {
    /// A new empty estimator for the given configuration (dcrd
    /// `NewEstimator`).
    pub fn new(cfg: &EstimatorConfig) -> Result<Estimator, String> {
        // Sanity check the config.
        if cfg.max_bucket_fee <= cfg.min_bucket_fee {
            return Err("maximum bucket fee should not be lower than minimum bucket fee".into());
        }
        if cfg.fee_rate_step <= 1.0 {
            return Err("fee rate step should not be <= 1.0".into());
        }
        if cfg.min_bucket_fee <= 0 {
            return Err("minimum bucket fee rate cannot be <= 0".into());
        }
        if cfg.max_confirms > MAX_ALLOWED_CONFIRMS {
            return Err(format!(
                "confirmation count requested ({}) larger than maximum allowed ({})",
                cfg.max_confirms, MAX_ALLOWED_CONFIRMS
            ));
        }

        let max_confirms = cfg.max_confirms;
        let max = cfg.max_bucket_fee as f64;
        let extra_bucket_fee = cfg.extra_bucket_fee as f64;
        let mut bucket_fees: Vec<f64> = Vec::new();
        let mut prev_f = 0.0f64;
        let mut f = cfg.min_bucket_fee as f64;
        while f < max {
            if f > extra_bucket_fee && prev_f < extra_bucket_fee {
                // Add the extra bucket fee for tracking.
                bucket_fees.push(extra_bucket_fee);
            }
            bucket_fees.push(f);
            prev_f = f;
            f *= cfg.fee_rate_step;
        }

        // The last bucket catches everything else, so it uses an
        // upper bound of +inf which any rate must be lower than.
        bucket_fees.push(f64::INFINITY);

        let nb_buckets = bucket_fees.len();
        let empty_bucket = || TxConfirmStatBucket {
            confirmed: vec![TxConfirmStatBucketCount::default(); max_confirms as usize],
            confirm_count: 0.0,
            fee_sum: 0.0,
        };
        Ok(Estimator {
            bucket_fee_bounds: bucket_fees,
            buckets: (0..nb_buckets).map(|_| empty_bucket()).collect(),
            mem_pool: (0..nb_buckets).map(|_| empty_bucket()).collect(),
            mem_pool_txs: BTreeMap::new(),
            max_confirms: max_confirms as i32,
            decay: DEFAULT_DECAY,
            best_height: -1,
        })
    }

    /// The bucket with the highest upper bound that is still lower
    /// than the rate (dcrd `lowerBucket`).
    fn lower_bucket(&self, rate: f64) -> i32 {
        self.bucket_fee_bounds.partition_point(|b| *b < rate) as i32
    }

    /// The confirmation range index for the given number of blocks to
    /// confirm (dcrd `confirmRange`).
    fn confirm_range(&self, blocks_to_confirm: i32) -> i32 {
        let idx = blocks_to_confirm - 1;
        if idx >= self.max_confirms {
            return self.max_confirms - 1;
        }
        idx
    }

    /// Decay the confirmed statistics and advance the mempool
    /// confirmation ranges for a newly mined block (dcrd
    /// `updateMovingAverages`).
    fn update_moving_averages(&mut self, new_height: i64) {
        // Decay the existing stats so that, over time, we rely on
        // more up to date information regarding fees.
        for bucket in &mut self.buckets {
            bucket.fee_sum *= self.decay;
            bucket.confirm_count *= self.decay;
            for conf in &mut bucket.confirmed {
                conf.fee_sum *= self.decay;
                conf.tx_count *= self.decay;
            }
        }

        // For unconfirmed (mempool) transactions, every transaction
        // will now take at least one additional block to confirm, so
        // move the stats up one confirmation range.
        for bucket in &mut self.mem_pool {
            // The last confirmation range represents all txs confirmed
            // at >= the initial max confirms, so the second to last
            // range is added into the last range.
            let c = bucket.confirmed.len() - 1;
            bucket.confirmed[c].tx_count += bucket.confirmed[c - 1].tx_count;
            bucket.confirmed[c].fee_sum += bucket.confirmed[c - 1].fee_sum;

            // For the other ranges, just move up the stats.
            for c in (1..bucket.confirmed.len() - 1).rev() {
                bucket.confirmed[c] = bucket.confirmed[c - 1];
            }

            // And finally, the very first confirmation range is zeroed
            // so brand new txs can be tracked.
            bucket.confirmed[0].tx_count = 0.0;
            bucket.confirmed[0].fee_sum = 0.0;
        }

        self.best_height = new_height;
    }

    /// Record a new mempool transaction (dcrd `newMemPoolTx`).
    fn new_mem_pool_tx(&mut self, bucket_idx: i32, fees: f64) {
        let conf = &mut self.mem_pool[bucket_idx as usize].confirmed[0];
        conf.fee_sum += fees;
        conf.tx_count += 1.0;
    }

    /// Move a mined transaction into the confirmed statistics (dcrd
    /// `newMinedTx`).
    fn new_mined_tx(&mut self, blocks_to_confirm: i32, rate: f64) {
        let bucket_idx = self.lower_bucket(rate);
        let confirm_idx = self.confirm_range(blocks_to_confirm);
        let bucket = &mut self.buckets[bucket_idx as usize];

        // Increase the counts for all confirmation ranges starting at
        // the first confirm index because it took at least this many
        // blocks for the tx to be mined.
        for conf in bucket.confirmed.iter_mut().skip(confirm_idx as usize) {
            conf.fee_sum += rate;
            conf.tx_count += 1.0;
        }
        bucket.confirm_count += 1.0;
        bucket.fee_sum += rate;
    }

    /// Remove a transaction from the mempool statistics (dcrd
    /// `removeFromMemPool`; a negative resulting count indicates an
    /// accounting error dcrd merely logs).
    fn remove_from_mem_pool(&mut self, blocks_in_mem_pool: i32, rate: f64) {
        let bucket_idx = self.lower_bucket(rate);
        let confirm_idx = self.confirm_range(blocks_in_mem_pool + 1);
        let conf = &mut self.mem_pool[bucket_idx as usize].confirmed[confirm_idx as usize];
        conf.fee_sum -= rate;
        conf.tx_count -= 1.0;
    }

    /// Estimate the median fee rate such that at least the given
    /// percentage of transactions in all tracked buckets with fee
    /// rates greater than or equal to the median were mined within the
    /// target confirmation window (dcrd `estimateMedianFee`).
    pub fn estimate_median_fee(
        &self,
        target_confs: i32,
        success_pct: f64,
    ) -> Result<f64, EstimateFeeError> {
        if target_confs <= 0 {
            return Err(EstimateFeeError::NonPositiveTarget);
        }

        const MIN_TX_COUNT: f64 = 1.0;

        // dcrd's comparison shape.
        #[allow(clippy::int_plus_one)]
        if target_confs - 1 >= self.max_confirms {
            return Err(EstimateFeeError::TargetConfTooLarge {
                max_confirms: self.max_confirms,
                req_confirms: target_confs,
            });
        }

        let start_idx = self.buckets.len() - 1;
        let confirm_range_idx = self.confirm_range(target_confs) as usize;

        let mut total_txs = 0.0f64;
        let mut confirmed_txs = 0.0f64;
        let mut best_buckets_stt = start_idx as i64;
        let mut best_buckets_end = start_idx as i64;
        let mut cur_buckets_end = start_idx as i64;

        let mut b = start_idx as i64;
        while b >= 0 {
            let bucket = &self.buckets[b as usize];
            total_txs += bucket.confirm_count;
            confirmed_txs += bucket.confirmed[confirm_range_idx].tx_count;

            // Add the mempool (unconfirmed) transactions to the total
            // tx count since a very large mempool for the given bucket
            // might mean that miners are reluctant to include these in
            // their mined blocks.
            total_txs += self.mem_pool[b as usize].confirmed[confirm_range_idx].tx_count;

            if total_txs > MIN_TX_COUNT {
                if confirmed_txs / total_txs < success_pct {
                    if cur_buckets_end == start_idx as i64 {
                        return Err(EstimateFeeError::NoSuccessPctBucketFound);
                    }
                    break;
                }

                best_buckets_stt = b;
                best_buckets_end = cur_buckets_end;
                cur_buckets_end = b - 1;
                total_txs = 0.0;
                confirmed_txs = 0.0;
            }
            b -= 1;
        }

        let mut tx_count = 0.0f64;
        for b in best_buckets_stt..=best_buckets_end {
            tx_count += self.buckets[b as usize].confirm_count;
        }
        if tx_count <= 0.0 {
            return Err(EstimateFeeError::NotEnoughTxsForEstimate);
        }
        tx_count /= 2.0;
        for b in best_buckets_stt..=best_buckets_end {
            let bucket = &self.buckets[b as usize];
            if bucket.confirm_count < tx_count {
                tx_count -= bucket.confirm_count;
            } else {
                let median = bucket.fee_sum / bucket.confirm_count;
                return Ok(median);
            }
        }

        unreachable!("this isn't supposed to be reached");
    }

    /// The suggested fee in atoms for a transaction to be confirmed
    /// within the target number of blocks with a high degree of
    /// certainty (dcrd `EstimateFee`).
    pub fn estimate_fee(&self, target_confs: i32) -> Result<i64, EstimateFeeError> {
        let mut rate = self.estimate_median_fee(target_confs, 0.95)?;

        rate = rate.round();
        if rate < self.bucket_fee_bounds[0] {
            // Prevent the public facing api from ever returning
            // something lower than the minimum fee.
            rate = self.bucket_fee_bounds[0];
        }

        Ok(rate as i64)
    }

    /// Establish the current best height after initializing the chain
    /// (dcrd `Enable`).
    pub fn enable(&mut self, best_height: i64) {
        self.best_height = best_height;
    }

    /// Whether the estimator is ready to accept new mined and mempool
    /// transactions (dcrd `IsEnabled`).
    pub fn is_enabled(&self) -> bool {
        self.best_height > -1
    }

    /// Account for a new mempool transaction with the given total fee
    /// in atoms and size in bytes (dcrd `AddMemPoolTransaction`).
    pub fn add_mem_pool_transaction(
        &mut self,
        tx_hash: &Hash,
        fee: i64,
        size: i64,
        tx_type: TxType,
    ) {
        if self.best_height < 0 {
            return;
        }

        if self.mem_pool_txs.contains_key(&tx_hash.0) {
            // We should not double count transactions.
            return;
        }

        // Ignore tspends for the purposes of fee estimation, since
        // they remain in the mempool for a long time and have special
        // rules about when they can be included in blocks.
        if tx_type == TxType::TSpend {
            return;
        }

        // Note the integer division before the multiplication: dcrd
        // deliberately downsamples rates below 0.001 DCR/KB towards
        // the minimum this way.
        let rate = (fee / size * 1000) as f64;

        if rate < self.bucket_fee_bounds[0] {
            // Transactions paying less than the current relaying fee
            // can only possibly be included in the high priority/zero
            // fee area of blocks, so they are explicitly not tracked.
            // This also naturally handles votes.
            return;
        }

        let desc = MemPoolTxDesc {
            added_height: self.best_height,
            fees: rate,
        };
        self.mem_pool_txs.insert(tx_hash.0, desc);
        let bucket_index = self.lower_bucket(rate);
        self.new_mem_pool_tx(bucket_index, rate);
    }

    /// Remove a mempool transaction from statistics tracking (dcrd
    /// `RemoveMemPoolTransaction`).
    pub fn remove_mem_pool_transaction(&mut self, tx_hash: &Hash) {
        let Some(desc) = self.mem_pool_txs.remove(&tx_hash.0) else {
            return;
        };
        self.remove_from_mem_pool((self.best_height - desc.added_height) as i32, desc.fees);
    }

    /// Move a tracked mempool transaction into a mined state (dcrd
    /// `processMinedTransaction`).
    fn process_mined_transaction(&mut self, block_height: i64, tx_hash: &Hash) {
        // Transactions that were not being tracked cannot be used for
        // estimation because that opens up the possibility of miners
        // introducing dummy, high fee transactions.
        let Some(desc) = self.mem_pool_txs.remove(&tx_hash.0) else {
            return;
        };

        self.remove_from_mem_pool((block_height - desc.added_height) as i32, desc.fees);

        if block_height <= desc.added_height {
            // This shouldn't usually happen but non positive
            // confirmation ranges cannot be accounted for in mined
            // transactions.
            return;
        }

        let mine_delay = (block_height - desc.added_height) as i32;
        self.new_mined_tx(mine_delay, desc.fees);
    }

    /// Process the transactions mined in a new block, given its height
    /// and the hashes of both transaction trees (dcrd `ProcessBlock`,
    /// which only consumes the height and transaction hashes of the
    /// passed block).
    pub fn process_block(&mut self, block_height: i64, tx_hashes: &[Hash], stx_hashes: &[Hash]) {
        if self.best_height < 0 {
            return;
        }

        if block_height <= self.best_height {
            // Reorgs are not explicitly tracked right now.
            return;
        }

        self.update_moving_averages(block_height);

        for tx_hash in tx_hashes {
            self.process_mined_transaction(block_height, tx_hash);
        }
        for stx_hash in stx_hashes {
            self.process_mined_transaction(block_height, stx_hash);
        }
    }
}

/// Serialize a bucket in dcrd's database row format: the confirm
/// count, the fee sum, then the per-range count and fee sum, all as
/// big-endian float bits (the encoding inside dcrd `updateDatabase`).
pub fn serialize_bucket(bucket: &TxConfirmStatBucket) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + bucket.confirmed.len() * 16);
    out.extend_from_slice(&bucket.confirm_count.to_bits().to_be_bytes());
    out.extend_from_slice(&bucket.fee_sum.to_bits().to_be_bytes());
    for conf in &bucket.confirmed {
        out.extend_from_slice(&conf.tx_count.to_bits().to_be_bytes());
        out.extend_from_slice(&conf.fee_sum.to_bits().to_be_bytes());
    }
    out
}

/// Deserialize a bucket from dcrd's database row format for the given
/// confirmation range count (the decoding inside dcrd
/// `loadFromDatabase`).
pub fn deserialize_bucket(data: &[u8], max_confirms: u32) -> Result<TxConfirmStatBucket, String> {
    if data.len() != 16 + max_confirms as usize * 16 {
        return Err("wrong size of data in bucket read from db".into());
    }
    let readf = |idx: usize| -> f64 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&data[idx * 8..idx * 8 + 8]);
        f64::from_bits(u64::from_be_bytes(bytes))
    };
    let mut bucket = TxConfirmStatBucket {
        confirm_count: readf(0),
        fee_sum: readf(1),
        confirmed: Vec::with_capacity(max_confirms as usize),
    };
    for i in 0..max_confirms as usize {
        bucket.confirmed.push(TxConfirmStatBucketCount {
            tx_count: readf(2 + i * 2),
            fee_sum: readf(3 + i * 2),
        });
    }
    Ok(bucket)
}
