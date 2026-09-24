// SPDX-License-Identifier: ISC
//! Relative lock-time (sequence lock) calculation from dcrd's
//! `sequencelock.go`.
//!
//! dcrd resolves referenced outputs through a `UtxoViewpoint`; that
//! structure is engine-coupled, so the calculation here takes a lookup
//! closure returning the confirmation height of an unspent output
//! instead.  The chain walk for past median times and the treasury
//! agenda check run over the same height-indexed [`VoteChainView`] the
//! agenda code uses.

use alloc::format;

use dcroxide_chaincfg::Params;
use dcroxide_wire::{
    MsgTx, OutPoint, SEQUENCE_LOCK_TIME_DISABLED, SEQUENCE_LOCK_TIME_GRANULARITY,
    SEQUENCE_LOCK_TIME_IS_SECONDS, SEQUENCE_LOCK_TIME_MASK,
};

use crate::agendas::is_treasury_agenda_active;
use crate::ruleerror::{RuleError, RuleErrorKind, rule_error};
use crate::stakever::{VersionChainView, VersionNode, calc_past_median_time};
use crate::thresholdstate::VoteChainView;

/// The block height an unspent output reports while its transaction is
/// still in the mempool (dcrd's `mempoolHeight`).
pub const MEMPOOL_HEIGHT: i64 = 0x7fffffff;

/// The minimum timestamp and minimum block height after which a
/// transaction can be included into a block while satisfying the
/// relative lock times of all of its input sequence numbers (dcrd
/// `SequenceLock`).  Each field may be -1 if none of the input
/// sequence numbers require a specific relative lock time for the
/// respective type; since all valid heights and times are larger than
/// -1, that will not prevent inclusion.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SequenceLock {
    /// The minimum block height.
    pub min_height: i64,
    /// The minimum median time past as unix seconds.
    pub min_time: i64,
}

/// Adapter exposing a [`VoteChainView`] as the [`VersionChainView`]
/// the past-median-time calculation expects.
pub(crate) struct AsVersionView<'a, V: VoteChainView>(pub(crate) &'a V);

impl<V: VoteChainView> VersionChainView for AsVersionView<'_, V> {
    fn node(&self, height: i64) -> Option<VersionNode> {
        self.0.vote_node(height).map(|n| n.node)
    }

    // Forward the walk so a view that follows parent links keeps doing
    // so through the adapter; the version data is a projection of the
    // vote data, so both paths visit the same nodes.
    fn walk_back(&self, height: i64, visit: &mut dyn FnMut(&VersionNode) -> bool) {
        VersionChainView::walk_back(self.0, height, visit);
    }
}

/// Compute the relative lock times for the passed transaction from the
/// point of view of the block node at `node_height` along the view's
/// branch (dcrd `calcSequenceLock`/`CalcSequenceLock`).
///
/// `lookup_block_height` stands in for dcrd's
/// `UtxoViewpoint.LookupEntry`: it returns the confirmation height of
/// the referenced unspent output ([`MEMPOOL_HEIGHT`] while unmined),
/// or `None` when the output does not exist or has already been spent.
///
/// This calculates the sequence lock regardless of the state of the
/// agenda which conditionally activates it — `is_active` conveys that
/// state, and callers performing consensus checking must check the
/// agenda first, exactly as in dcrd.
pub fn calc_sequence_lock<V: VoteChainView>(
    view: &V,
    node_height: i64,
    tx: &MsgTx,
    lookup_block_height: impl Fn(&OutPoint) -> Option<i64>,
    is_active: bool,
    params: &Params,
) -> Result<SequenceLock, RuleError> {
    // dcrd derives the flag from the node's parent; a genesis tip
    // nil-derefs there and is unreachable in practice.
    let is_treasury_enabled = is_treasury_agenda_active(view, Some(node_height - 1), params)
        .map_err(|_| {
            rule_error(
                RuleErrorKind::UnknownDeploymentID,
                "treasury deployment not defined on this network",
            )
        })?;

    // A value of -1 for each lock type allows a transaction to be
    // included in a block at any given height or time.
    let mut sequence_lock = SequenceLock {
        min_height: -1,
        min_time: -1,
    };

    // Sequence locks do not apply if they are not yet active, the tx
    // version is less than 2, or the tx is a coinbase or stakebase, so
    // return now with a sequence lock that indicates the tx can
    // possibly be included in a block at any given height or time.
    let enforce = is_active && tx.version >= 2;
    if !enforce
        || dcroxide_standalone::is_coin_base_tx(tx, is_treasury_enabled)
        || dcroxide_stake::is_ssgen(tx)
    {
        return Ok(sequence_lock);
    }

    for (tx_in_index, tx_in) in tx.tx_in.iter().enumerate() {
        // Nothing to calculate for this input when relative time locks
        // are disabled for it.
        let sequence_num = tx_in.sequence;
        if sequence_num & SEQUENCE_LOCK_TIME_DISABLED != 0 {
            continue;
        }

        let Some(input_height) = lookup_block_height(&tx_in.previous_out_point) else {
            return Err(rule_error(
                RuleErrorKind::MissingTxOut,
                // dcrd formats the outpoint with `%v`, i.e. its
                // `hash:index` String form.
                format!(
                    "output {} referenced from transaction {}:{tx_in_index} either does \
                     not exist or has already been spent",
                    tx_in.previous_out_point,
                    tx.tx_hash()
                ),
            ));
        };

        // Calculate the sequence locks from the point of view of the
        // next block for inputs that are in the mempool.
        let input_height = if input_height == MEMPOOL_HEIGHT {
            node_height + 1
        } else {
            input_height
        };

        // Mask off the value portion of the sequence number to obtain
        // the time lock delta required before this input can be spent.
        // The relative lock can be time based or block based.
        let relative_lock = i64::from(sequence_num & SEQUENCE_LOCK_TIME_MASK);

        if sequence_num & SEQUENCE_LOCK_TIME_IS_SECONDS != 0 {
            // Time based relative locks are calculated relative to the
            // past median time of the block prior to the one in which
            // the referenced output was included.
            let prev_input_height = (input_height - 1).max(0);
            let median_time = calc_past_median_time(&AsVersionView(view), prev_input_height);

            // Shift left to convert the granular relative lock to
            // seconds, and subtract one to maintain the original lock
            // time semantics.
            let relative_secs = relative_lock << SEQUENCE_LOCK_TIME_GRANULARITY;
            let min_time = median_time + relative_secs - 1;
            if min_time > sequence_lock.min_time {
                sequence_lock.min_time = min_time;
            }
        } else {
            // Block based relative locks are the sum of the input
            // height and the required relative number of blocks, minus
            // one to maintain the original lock time semantics.
            let min_height = input_height + relative_lock - 1;
            if min_height > sequence_lock.min_height {
                sequence_lock.min_height = min_height;
            }
        }
    }

    Ok(sequence_lock)
}

/// Convert the passed relative lock time to a sequence number in
/// accordance with DCP0003 (dcrd `LockTimeToSequence`): bit 22 selects
/// seconds (granularity 512, truncated toward zero) over block height,
/// and the low 16 bits carry the value.  Errors when the value cannot
/// be represented, with dcrd's message text.
pub fn lock_time_to_sequence(
    is_seconds: bool,
    lock_time: u32,
) -> Result<u32, alloc::string::String> {
    // The corresponding sequence number is simply the desired input
    // age when expressing the relative lock time in blocks.
    if !is_seconds {
        if lock_time > SEQUENCE_LOCK_TIME_MASK {
            return Err(format!(
                "max relative block height a sequence number can represent is {SEQUENCE_LOCK_TIME_MASK}"
            ));
        }
        return Ok(lock_time);
    }

    let max_seconds = SEQUENCE_LOCK_TIME_MASK << SEQUENCE_LOCK_TIME_GRANULARITY;
    if lock_time > max_seconds {
        return Err(format!(
            "max relative seconds a sequence number can represent is {max_seconds}"
        ));
    }

    Ok(SEQUENCE_LOCK_TIME_IS_SECONDS | (lock_time >> SEQUENCE_LOCK_TIME_GRANULARITY))
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use alloc::vec::Vec;

    use dcroxide_chainhash::Hash;
    use dcroxide_wire::{TxIn, TxOut};

    use super::*;
    use crate::thresholdstate::VoteNode;

    struct VecChain(Vec<VoteNode>);

    impl VersionChainView for VecChain {
        fn node(&self, height: i64) -> Option<VersionNode> {
            self.vote_node(height).map(|n| n.node)
        }
    }

    impl VoteChainView for VecChain {
        fn vote_node(&self, height: i64) -> Option<VoteNode> {
            self.0.get(usize::try_from(height).ok()?).cloned()
        }
    }

    /// A missing referenced output is reported with dcrd's `%v`
    /// rendering of the outpoint, `hash:index`, not the derived Debug
    /// form.
    #[test]
    fn missing_output_message_renders_outpoint_like_dcrd() {
        let params = dcroxide_chaincfg::mainnet_params();
        let chain = VecChain(
            (0..3)
                .map(|height| VoteNode {
                    node: VersionNode {
                        height,
                        timestamp: 1_454_954_400 + height * 300,
                        ..VersionNode::default()
                    },
                    votes: Vec::new(),
                })
                .collect(),
        );

        let mut prev_hash = [0u8; 32];
        prev_hash[0] = 0xab;
        let mut tx = MsgTx {
            version: 2,
            ..MsgTx::default()
        };
        tx.tx_in.push(TxIn {
            previous_out_point: OutPoint {
                hash: Hash(prev_hash),
                index: 7,
                tree: 0,
            },
            sequence: 5,
            ..TxIn::default()
        });
        tx.tx_out.push(TxOut::default());

        let err = calc_sequence_lock(&chain, 2, &tx, |_| None, true, &params)
            .expect_err("the referenced output is missing");
        assert_eq!(err.kind, RuleErrorKind::MissingTxOut);
        let mut want = String::from("output ");
        want.push_str(&"0".repeat(62));
        want.push_str(&format!(
            "ab:7 referenced from transaction {}:0 either does not exist or has \
             already been spent",
            tx.tx_hash()
        ));
        assert_eq!(err.description, want);
    }
}
