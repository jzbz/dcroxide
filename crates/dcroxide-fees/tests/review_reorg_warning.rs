// SPDX-License-Identifier: ISC
//! dcrd's `ProcessBlock` warns about every block at or below the
//! estimator's best height (`estimator.go:883-889`), as the first
//! new-chain blocks of a reorg are, and skips it.  The port skipped
//! them silently (review finding GAP01#5); it now hands the skipped
//! block back so the daemon logs dcrd's line under `FEES`.

use dcroxide_fees::{
    DEFAULT_FEE_RATE_STEP, DEFAULT_MAX_CONFIRMATIONS, Estimator, EstimatorConfig, StaleBlock,
};

fn estimator() -> Estimator {
    Estimator::new(&EstimatorConfig {
        max_confirms: DEFAULT_MAX_CONFIRMATIONS,
        min_bucket_fee: 10_000,
        max_bucket_fee: 1_000_000,
        extra_bucket_fee: 100_000,
        fee_rate_step: DEFAULT_FEE_RATE_STEP,
    })
    .expect("valid config")
}

#[test]
fn a_block_not_above_the_best_height_reports_dcrds_warning() {
    let mut est = estimator();

    // Before it is enabled the estimator returns first, without a
    // warning, as dcrd's `bestHeight < 0` check does.
    assert_eq!(est.process_block(5, &[], &[]), None);

    est.enable(1000);

    // A one-block reorg: the replacement arrives at the best height.
    let stale = est.process_block(1000, &[], &[]);
    assert_eq!(
        stale,
        Some(StaleBlock {
            height: 1000,
            best_height: 1000
        })
    );
    assert_eq!(
        stale.expect("stale").to_string(),
        "Trying to process mined transactions at block 1000 when previous best block was at \
         height 1000"
    );

    // Deeper reorgs warn for each new-chain block below the old tip.
    assert_eq!(
        est.process_block(999, &[], &[]),
        Some(StaleBlock {
            height: 999,
            best_height: 1000
        })
    );

    // The next height is processed and becomes the best height.
    assert_eq!(est.process_block(1001, &[], &[]), None);
    assert_eq!(
        est.process_block(1001, &[], &[]),
        Some(StaleBlock {
            height: 1001,
            best_height: 1001
        })
    );
}
