// SPDX-License-Identifier: ISC

//! The mining priority calculation from dcrd's `policy.go` (the
//! template policy struct itself arrives with the block template
//! generation).

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
                next_block_height - origin_height
            };

            // Sum the input value times age.
            total_input_age += (input_value * input_age) as f64;
        }
    }
    total_input_age
}

/// The transaction priority: the sum of each input value multiplied
/// by its age, divided by the adjusted transaction size (dcrd
/// `CalcPriority`).
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
