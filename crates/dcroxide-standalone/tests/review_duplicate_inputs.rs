// SPDX-License-Identifier: ISC
//! The duplicate input verdict of `check_transaction_sanity` against
//! dcrd's own search (`tx.go:218-226`), which files every previous
//! outpoint in a map and reports the first one it finds there.
//!
//! The port searches small transactions pair by pair and files the
//! inputs of larger ones in a set, so the verdict has to be the map's
//! at every input count on both sides of that line, wherever the two
//! equal outpoints sit, and for outpoints that differ in one field
//! only, down to one bit of it.  The error is one constant, which names
//! no input.

// Test-harness arithmetic over small, bounded counts.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;

use dcroxide_chainhash::Hash;
use dcroxide_standalone as standalone;
use dcroxide_testutil::SplitMix64;
use dcroxide_wire::{MsgTx, OutPoint, TxIn, TxOut};
use standalone::ErrorKind;

const MAX_TX_SIZE: u64 = 393_216;

/// The search as it was before the pairwise one, which is dcrd's with
/// an ordered set for the map: whether an input's previous outpoint was
/// already filed by an earlier input.
fn has_duplicate_inputs_by_set(tx: &MsgTx) -> bool {
    let mut existing_tx_out: BTreeSet<([u8; 32], u32, i8)> = BTreeSet::new();
    for tx_in in &tx.tx_in {
        let key = (
            tx_in.previous_out_point.hash.0,
            tx_in.previous_out_point.index,
            tx_in.previous_out_point.tree,
        );
        if !existing_tx_out.insert(key) {
            return true;
        }
    }
    false
}

/// A transaction that passes every other sanity check, spending the
/// given outpoints in order.
fn spending(outpoints: &[OutPoint]) -> MsgTx {
    MsgTx {
        tx_in: outpoints
            .iter()
            .map(|&previous_out_point| TxIn {
                previous_out_point,
                ..TxIn::default()
            })
            .collect(),
        tx_out: vec![TxOut::default()],
        ..MsgTx::default()
    }
}

/// `count` outpoints, no two alike, that share hashes, indexes and
/// trees with one another wherever that leaves them distinct.
fn distinct_outpoints(count: usize) -> Vec<OutPoint> {
    (0..count)
        .map(|i| OutPoint {
            hash: Hash([(i / 4) as u8; 32]),
            index: (i / 2 % 2) as u32,
            tree: (i % 2) as i8,
        })
        .collect()
}

/// Hold the port's verdict and error to the set's for one transaction,
/// and return the verdict.
fn compare(tx: &MsgTx) -> bool {
    let want = has_duplicate_inputs_by_set(tx);
    match standalone::check_transaction_sanity(tx, MAX_TX_SIZE) {
        Ok(()) => assert!(!want, "a duplicate input went unreported: {tx:?}"),
        Err(err) => {
            assert!(want, "{err} for a transaction with no duplicate: {tx:?}");
            assert_eq!(err.kind, ErrorKind::DuplicateTxInputs);
            assert_eq!(err.description, "transaction contains duplicate inputs");
        }
    }
    want
}

/// Every input count from one to well past the pairwise limit, with the
/// two equal outpoints at every pair of positions, and with the second
/// of the pair differing from the first in its hash, its index or its
/// tree alone.
#[test]
fn every_pair_of_positions_is_judged_as_the_set_judges_it() {
    for count in 1..=40usize {
        let outpoints = distinct_outpoints(count);
        assert!(!compare(&spending(&outpoints)), "{count} distinct inputs");

        for second in 1..count {
            for first in 0..second {
                let mut equal = outpoints.clone();
                equal[second] = equal[first];
                assert!(compare(&spending(&equal)), "{count}: {first} and {second}");

                // One field apart from `first`, and from every other
                // input too: the fields are past the ranges
                // `distinct_outpoints` draws from.
                let mut other_hash = equal.clone();
                other_hash[second].hash.0[31] ^= 0x80;
                assert!(!compare(&spending(&other_hash)), "{count}: hash");
                let mut other_index = equal.clone();
                other_index[second].index += 2;
                assert!(!compare(&spending(&other_index)), "{count}: index");
                let mut other_tree = equal.clone();
                other_tree[second].tree += 2;
                assert!(!compare(&spending(&other_tree)), "{count}: tree");
            }
        }
    }
}

/// Two outpoints are the same output only when every bit of the hash,
/// the index and the tree agrees.  At input counts on both sides of the
/// pairwise limit, the last input spends the first input's outpoint
/// with one bit changed, for each of the 256 bits of the hash, the 32 of
/// the index and the 8 of the tree in turn: none of those is a
/// duplicate, and the unchanged outpoint is.  A search that compared or
/// filed part of a field would report some of them.
#[test]
fn outpoints_one_bit_apart_are_not_duplicates() {
    for count in [2usize, 16, 17, 33] {
        // The first outpoint has a hash of 32 different bytes, so no
        // change of one bit makes it any of the others, whose hashes
        // are one byte repeated.
        let mut outpoints: Vec<OutPoint> = (0..count)
            .map(|i| OutPoint {
                hash: Hash([i as u8; 32]),
                index: i as u32,
                tree: 0,
            })
            .collect();
        outpoints[0] = OutPoint {
            hash: Hash(core::array::from_fn(|byte| 0x40 + byte as u8)),
            index: 0x0102_0304,
            tree: 1,
        };
        assert!(!compare(&spending(&outpoints)), "{count} distinct inputs");
        let last = count - 1;
        outpoints[last] = outpoints[0];
        assert!(compare(&spending(&outpoints)), "{count}: the same outpoint");

        for bit in 0..256usize {
            let mut apart = outpoints.clone();
            apart[last].hash.0[bit / 8] ^= 1 << (bit % 8);
            assert!(!compare(&spending(&apart)), "{count}: hash bit {bit}");
        }
        for bit in 0..32u32 {
            let mut apart = outpoints.clone();
            apart[last].index ^= 1 << bit;
            assert!(!compare(&spending(&apart)), "{count}: index bit {bit}");
        }
        for bit in 0..8u32 {
            let mut apart = outpoints.clone();
            apart[last].tree = (apart[last].tree as u8 ^ (1 << bit)) as i8;
            assert!(!compare(&spending(&apart)), "{count}: tree bit {bit}");
        }
    }
}

/// Transactions drawn at random from a few hashes, indexes and trees,
/// so that many hold a duplicate and many do not, at input counts on
/// both sides of the pairwise limit.
#[test]
fn random_transactions_are_judged_as_the_set_judges_them() {
    let mut rng = SplitMix64::from_entropy("duplicate inputs");
    let (mut with, mut without) = (0usize, 0usize);
    for _ in 0..20_000 {
        let count = 1 + rng.below(40) as usize;
        // More distinct outpoints for the larger transactions, so both
        // verdicts stay common at every count.
        let hashes = 1 + rng.below(1 + count as u64 * 8);
        let outpoints: Vec<OutPoint> = (0..count)
            .map(|_| OutPoint {
                hash: Hash([rng.below(hashes) as u8; 32]),
                index: rng.below(3) as u32,
                tree: rng.below(2) as i8,
            })
            .collect();
        if compare(&spending(&outpoints)) {
            with += 1;
        } else {
            without += 1;
        }
    }
    assert!(
        with > 2_000 && without > 2_000,
        "{with} with, {without} without"
    );
}
