// SPDX-License-Identifier: ISC
//! The acceptance gauntlet borrows the candidate and copies it only to
//! rewrite its fraud proof data, as dcrd copies with
//! `dcrutil.NewTxDeepTxIns` (`mempool.go:1498-1520`).  The pool keeps
//! the corrected copy, while the caller's transaction, which is what
//! `ProcessTransaction` hands back for relay, stays as it was.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::{chain_from_init, error_kind, harness_policy, parse_tx};
use dcroxide_chaincfg::mainnet_params;
use dcroxide_mempool::TxPool;

#[test]
fn the_pool_stores_the_corrected_fraud_proof_and_relays_the_original() {
    let data = include_str!("data/txpool_vectors.txt");
    let mut lines = data.lines();
    let init: Vec<&str> = lines.next().expect("init row").split(' ').collect();
    let params = mainnet_params();
    let mut pool = TxPool::new(
        chain_from_init(&init),
        harness_policy(params.coinbase_maturity),
        &params,
    );

    // The battery's first acceptance spends the seed coinbase, which
    // the harness confirms at height 1 with block index 0xffffffff,
    // while the spend itself claims height 0 and index 0.
    let first: Vec<&str> = lines.next().expect("first row").split(' ').collect();
    assert_eq!(first[0], "pt");
    let tx = parse_tx(first[1]);
    let tx_hash = tx.tx_hash();
    assert_eq!((tx.tx_in[0].block_height, tx.tx_in[0].block_index), (0, 0));

    let accepted = pool
        .process_transaction_accepted(&tx, true, false, 0)
        .expect("accepted");
    assert_eq!(accepted.len(), 1);
    assert_eq!(accepted[0].0, tx_hash);
    assert_eq!(
        accepted[0].1, tx,
        "the accepted list carries the caller's transaction, as dcrd's does"
    );

    // The fraud proof fields are witness data, so the corrected copy
    // keeps the hash it is filed under.
    let stored = pool.fetch_transaction(&tx_hash).expect("in the pool");
    assert_eq!(stored.tx_hash(), tx_hash);
    assert_eq!(stored.tx_in[0].block_height, 1);
    assert_eq!(stored.tx_in[0].block_index, 0xffff_ffff);
    assert_eq!(stored.tx_in[0].value_in, tx.tx_in[0].value_in);
    assert_eq!(stored.tx_out, tx.tx_out);

    // The duplicate check runs off the hash the caller supplied.
    let err = pool
        .process_transaction(&tx, true, false, 0)
        .expect_err("already in the pool");
    assert_eq!(error_kind(&err), "ErrDuplicate");
    let err = pool
        .maybe_accept_transaction_pub(&stored, true)
        .expect_err("already in the pool");
    assert_eq!(error_kind(&err), "ErrDuplicate");
}
