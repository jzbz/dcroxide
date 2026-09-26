// SPDX-License-Identifier: ISC
//! dcrd's `AddMemPoolTransaction` computes the tracked rate as the
//! int64 expression `fee / size * 1000` (`estimator.go:790`), which Go
//! evaluates with two's-complement wrapping: `math.MinInt64 / -1` is
//! `math.MinInt64`, and the product by 1000 wraps.  Rust's `/` aborts
//! the process on `i64::MIN / -1` in every build profile, so the port
//! divides with `wrapping_div` and multiplies with `wrapping_mul`, as
//! Go does.

use dcroxide_chainhash::Hash;
use dcroxide_fees::{DEFAULT_FEE_RATE_STEP, DEFAULT_MAX_CONFIRMATIONS, Estimator, EstimatorConfig};
use dcroxide_stake::TxType;

fn estimator() -> Estimator {
    let mut est = Estimator::new(&EstimatorConfig {
        max_confirms: DEFAULT_MAX_CONFIRMATIONS,
        min_bucket_fee: 10_000,
        max_bucket_fee: 1_000_000,
        extra_bucket_fee: 100_000,
        fee_rate_step: DEFAULT_FEE_RATE_STEP,
    })
    .expect("valid config");
    est.enable(100);
    est
}

/// The transaction count and fee sum across every mempool bucket's
/// first confirmation range, where a newly added transaction lands.
fn tracked(est: &Estimator) -> (f64, f64) {
    est.mem_pool
        .iter()
        .fold((0.0, 0.0), |(count, fees), bucket| {
            (
                count + bucket.confirmed[0].tx_count,
                fees + bucket.confirmed[0].fee_sum,
            )
        })
}

#[test]
fn min_fee_over_minus_one_size_wraps_as_in_go() {
    let mut est = estimator();

    // Go: math.MinInt64 / -1 == math.MinInt64, and math.MinInt64 * 1000
    // wraps to 0, below the minimum bucket, so the transaction is not
    // tracked.  The port's plain `/` aborted here instead.
    est.add_mem_pool_transaction(&Hash([1; 32]), i64::MIN, -1, TxType::Regular);
    assert_eq!(tracked(&est), (0.0, 0.0));
}

#[test]
fn rate_product_wraps_as_in_go() {
    let mut est = estimator();

    // (2^61 + 50) * 1000 == 50_000 + 125 * 2^64, which Go's int64
    // multiplication wraps to a 50_000 atoms/KB rate inside the bucket
    // ladder, so the transaction is tracked at that rate.
    est.add_mem_pool_transaction(
        &Hash([2; 32]),
        2_305_843_009_213_694_002,
        1,
        TxType::Regular,
    );
    assert_eq!(tracked(&est), (1.0, 50_000.0));
}
