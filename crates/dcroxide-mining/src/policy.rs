// SPDX-License-Identifier: ISC

//! The mining priority calculation from dcrd's `policy.go`
//! (`calcInputValueAge` and `CalcPriority`).  dcrd's `Policy` struct
//! from the same file is [`MiningPolicy`](crate::MiningPolicy) in
//! `generator.rs`, with its `StandardVerifyFlags` closure on the
//! [`TemplateChain`](crate::TemplateChain) trait.

use dcroxide_wire::{MsgTx, OutPoint};

use crate::types::UNMINED_HEIGHT;

/// The total input age of a transaction: the number of confirmations
/// since each referenced output multiplied by its value, with mempool
/// inputs contributing zero (dcrd `calcInputValueAge`).  The lookup
/// returns the block height and amount for an outpoint when known,
/// standing in for dcrd's `PriorityInputser`.
pub fn calc_input_value_age(
    tx: &MsgTx,
    priority_input: impl Fn(&OutPoint) -> Option<(i64, i64)>,
    next_block_height: i64,
) -> f64 {
    let mut total_input_age = 0.0f64;
    for tx_in in &tx.tx_in {
        // Don't attempt to accumulate the total input age if the
        // referenced transaction output doesn't exist.
        if let Some((origin_height, input_value)) = priority_input(&tx_in.previous_out_point) {
            // Inputs with dependencies currently in the mempool have
            // their block height set to a special constant; their
            // input age is zero since the parent hasn't made it into
            // a block yet.
            let input_age = if origin_height == UNMINED_HEIGHT {
                0
            } else {
                next_block_height.wrapping_sub(origin_height)
            };

            // Sum the input value times age.  Go multiplies in int64,
            // which wraps: an old enough large output contributes a
            // negative age, and a plain `*` would panic instead in an
            // overflow-checked build.
            total_input_age += input_value.wrapping_mul(input_age) as f64;
        }
    }
    total_input_age
}

/// The transaction priority: the sum of each input value multiplied
/// by its age, divided by the adjusted transaction size (dcrd
/// `CalcPriority`).
#[allow(
    clippy::arithmetic_side_effects,
    reason = "overhead adds at most 168 per input of an in-memory transaction, and the \
              subtraction follows the overhead < serialized_tx_size check"
)]
pub fn calc_priority(
    tx: &MsgTx,
    priority_input: impl Fn(&OutPoint) -> Option<(i64, i64)>,
    next_block_height: i64,
) -> f64 {
    // In order to encourage spending multiple old unspent transaction
    // outputs thereby reducing the total set, don't count the
    // constant overhead for each input as well as enough bytes of the
    // signature script to cover a pay-to-script-hash redemption with
    // a compressed pubkey: 58 bytes of constant txin overhead plus up
    // to 110 bytes of signature script.
    let mut overhead = 0usize;
    for tx_in in &tx.tx_in {
        // Max inputs + size can't possibly overflow here.
        overhead += 58 + tx_in.signature_script.len().min(110);
    }

    let serialized_tx_size = tx.serialize_size();
    if overhead >= serialized_tx_size {
        return 0.0;
    }

    let input_value_age = calc_input_value_age(tx, priority_input, next_block_height);
    input_value_age / (serialized_tx_size - overhead) as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    use alloc::vec;
    use dcroxide_chainhash::Hash;
    use dcroxide_wire::{TX_TREE_REGULAR, TxIn, TxOut};

    /// A one-input transaction spending an output worth 1e13 atoms
    /// (100k DCR) confirmed at height 100, evaluated for a block at
    /// height 1,050,000.
    fn old_large_spend() -> (MsgTx, OutPoint) {
        let prev_out = OutPoint {
            hash: Hash([7u8; 32]),
            index: 0,
            tree: TX_TREE_REGULAR,
        };
        let mut tx = MsgTx::default();
        tx.tx_in.push(TxIn {
            previous_out_point: prev_out,
            sequence: 0xffff_ffff,
            value_in: 10_000_000_000_000,
            block_height: 100,
            block_index: 0,
            signature_script: vec![],
        });
        tx.tx_out.push(TxOut {
            value: 9_999_999_990_000,
            version: 0,
            pk_script: vec![0x51],
        });
        (tx, prev_out)
    }

    /// dcrd computes `float64(inputValue * inputAge)` in int64: 1e13
    /// atoms aged 1,049,900 blocks is 1.0499e19, past `i64::MAX`, and
    /// wraps to -7,947,744,073,709,551,616.  The port used a plain `*`,
    /// which panics in this (overflow-checked) test build.
    #[test]
    fn the_input_age_product_wraps_like_go() {
        let (tx, prev_out) = old_large_spend();
        let lookup = |op: &OutPoint| (*op == prev_out).then_some((100i64, 10_000_000_000_000i64));

        let age = calc_input_value_age(&tx, lookup, 1_050_000);
        assert_eq!(age, -7_947_744_073_709_551_616i64 as f64);

        // The wrapped, negative age carries through to the priority.
        let size = tx.serialize_size();
        let overhead = 58;
        let priority = calc_priority(&tx, lookup, 1_050_000);
        assert_eq!(priority, age / (size - overhead) as f64);
        assert!(priority < 0.0);
    }
}
