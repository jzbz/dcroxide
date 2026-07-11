// SPDX-License-Identifier: ISC
//! The daemon's fee-estimator wiring (dcrd `newServer` building the
//! fee estimator and handing it to the mempool and the RPC server):
//! the one shared estimator instance is fed from the mempool as
//! transactions enter and leave, from the chain handler as blocks
//! connect, and read by the `estimatesmartfee` RPC handler.
//!
//! dcrd persists the estimator's bucket statistics to a leveldb file;
//! the ported estimator keeps the same in-memory statistics but the
//! on-disk store is deferred, so the daemon's estimator starts empty
//! each run (it re-primes itself over the first blocks after the
//! sync, exactly as a fresh dcrd database would).

use std::sync::{Arc, Mutex};

use dcroxide_chainhash::Hash;
use dcroxide_fees::Estimator;
use dcroxide_stake::TxType;

/// The extra fee bucket dcrd tracks for transactions from wallets
/// that predate a relay-fee change (dcrd `ExtraBucketFee = 1e5`).
const EXTRA_BUCKET_FEE: i64 = 100_000;

/// Build the shared fee estimator over the network's relay-fee floor
/// (dcrd's `EstimatorConfig` from `newServer`: buckets from the
/// minimum relay fee up to a hundred times it, plus the extra
/// wallet-compat bucket).
pub fn new_shared_estimator(min_relay_tx_fee: i64) -> Result<Arc<Mutex<Estimator>>, String> {
    let cfg = dcroxide_fees::EstimatorConfig {
        max_confirms: dcroxide_fees::DEFAULT_MAX_CONFIRMATIONS,
        min_bucket_fee: min_relay_tx_fee,
        max_bucket_fee: min_relay_tx_fee
            .saturating_mul(dcroxide_fees::DEFAULT_MAX_BUCKET_FEE_MULTIPLIER),
        extra_bucket_fee: EXTRA_BUCKET_FEE,
        fee_rate_step: dcroxide_fees::DEFAULT_FEE_RATE_STEP,
    };
    Ok(Arc::new(Mutex::new(Estimator::new(&cfg)?)))
}

/// Feed a connected block's transactions into the estimator (dcrd's
/// `feeEstimator.ProcessBlock` in the NTBlockConnected case, run
/// before the mempool removal so each transaction transitions from
/// mempool to mined).  Every regular and stake transaction hash is
/// passed — the coinbase and treasurybase were never in the mempool,
/// so the estimator ignores them, matching dcrd.
pub fn process_connected_block(estimator: &Arc<Mutex<Estimator>>, block: &dcroxide_wire::MsgBlock) {
    let regular: Vec<Hash> = block.transactions.iter().map(|tx| tx.tx_hash()).collect();
    let stake: Vec<Hash> = block.stransactions.iter().map(|tx| tx.tx_hash()).collect();
    estimator
        .lock()
        .expect("fee estimator mutex poisoned")
        .process_block(i64::from(block.header.height), &regular, &stake);
}

/// Enable the estimator at the accepted block's height once the chain
/// is believed current (dcrd's NTBlockAccepted `if !IsEnabled()
/// { Enable(block.Height()) }`).  Fed transactions before this point
/// are ignored so pre-sync mempool contents do not skew the
/// estimate.
pub fn enable_at_height(estimator: &Arc<Mutex<Estimator>>, height: i64) {
    let mut estimator = estimator.lock().expect("fee estimator mutex poisoned");
    if !estimator.is_enabled() {
        estimator.enable(height);
    }
}

/// The mempool's fee-estimation hook over the shared estimator (dcrd
/// wiring `AddMemPoolTransaction`/`RemoveMemPoolTransaction` into the
/// mempool config).
pub struct NodeFeeEstimatorSink {
    estimator: Arc<Mutex<Estimator>>,
}

impl NodeFeeEstimatorSink {
    /// A hook over the daemon's shared fee estimator.
    pub fn new(estimator: Arc<Mutex<Estimator>>) -> NodeFeeEstimatorSink {
        NodeFeeEstimatorSink { estimator }
    }
}

impl dcroxide_mempool::FeeEstimatorSink for NodeFeeEstimatorSink {
    fn add_mem_pool_transaction(&mut self, tx_hash: &Hash, fee: i64, size: i64, tx_type: TxType) {
        self.estimator
            .lock()
            .expect("fee estimator mutex poisoned")
            .add_mem_pool_transaction(tx_hash, fee, size, tx_type);
    }

    fn remove_mem_pool_transaction(&mut self, tx_hash: &Hash) {
        self.estimator
            .lock()
            .expect("fee estimator mutex poisoned")
            .remove_mem_pool_transaction(tx_hash);
    }
}

/// The RPC fee-estimator seam over the shared estimator (dcrd
/// assigning `s.feeEstimator` to the rpcserver config's
/// `FeeEstimator` interface).
pub struct NodeRpcFeeEstimator {
    estimator: Arc<Mutex<Estimator>>,
}

impl NodeRpcFeeEstimator {
    /// A seam over the daemon's shared fee estimator.
    pub fn new(estimator: Arc<Mutex<Estimator>>) -> NodeRpcFeeEstimator {
        NodeRpcFeeEstimator { estimator }
    }
}

impl dcroxide_rpc::server::RpcFeeEstimator for NodeRpcFeeEstimator {
    fn estimate_fee(&mut self, target_confirmations: i32) -> Result<i64, String> {
        self.estimator
            .lock()
            .expect("fee estimator mutex poisoned")
            .estimate_fee(target_confirmations)
            .map_err(|e| e.to_string())
    }
}

/// A convenience type alias so the daemon can hold one estimator and
/// hand clones to the mempool, the chain handler, and the RPC seam.
pub type SharedFeeEstimator = Arc<Mutex<Estimator>>;

#[cfg(test)]
mod tests {
    use super::*;
    use dcroxide_mempool::FeeEstimatorSink;
    use dcroxide_rpc::server::RpcFeeEstimator;

    /// The mempool sink, the block feed, and the RPC seam all drive
    /// the one shared estimator.
    #[test]
    fn the_seams_drive_the_shared_estimator() {
        let estimator = new_shared_estimator(10_000).expect("estimator");

        // An empty estimator has no data to estimate from.
        let mut rpc = NodeRpcFeeEstimator::new(Arc::clone(&estimator));
        assert!(
            rpc.estimate_fee(1)
                .unwrap_err()
                .contains("not enough transactions"),
            "an empty estimator has no data"
        );

        // While disabled (before the first current accepted block) the
        // mempool sink is inert: dcrd's `AddMemPoolTransaction`
        // early-returns until `Enable` sets a height, so pre-sync
        // mempool contents never enter the statistics.
        let mut sink = NodeFeeEstimatorSink::new(Arc::clone(&estimator));
        let hash = Hash([7u8; 32]);
        sink.add_mem_pool_transaction(&hash, 50_000, 1000, TxType::Regular);
        assert_eq!(
            mem_pool_tracked(&estimator),
            0.0,
            "a disabled estimator ignores feeds"
        );

        enable_at_height(&estimator, 100);
        assert!(estimator.lock().expect("est").is_enabled());

        // Enabled, the same feed is recorded in a mempool bucket.
        sink.add_mem_pool_transaction(&hash, 50_000, 1000, TxType::Regular);
        assert_eq!(
            mem_pool_tracked(&estimator),
            1.0,
            "the sink fed the estimator"
        );

        // Removing it clears the mempool tracking.
        sink.remove_mem_pool_transaction(&hash);
        assert_eq!(
            mem_pool_tracked(&estimator),
            0.0,
            "the remove hook cleared it"
        );
    }

    /// Total transaction count the estimator is tracking in its
    /// mempool buckets (each unconfirmed transaction lands in a
    /// bucket's per-confirmation-range counters, indexed by how long it
    /// has waited).
    fn mem_pool_tracked(estimator: &SharedFeeEstimator) -> f64 {
        estimator
            .lock()
            .expect("est")
            .mem_pool
            .iter()
            .flat_map(|b| b.confirmed.iter())
            .map(|c| c.tx_count)
            .sum()
    }

    /// The block feed advances the estimator and moves mempool
    /// transactions to the mined statistics.
    #[test]
    fn the_block_feed_advances_the_estimator() {
        use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx, OutPoint, TxIn, TxOut};

        let estimator = new_shared_estimator(10_000).expect("estimator");
        enable_at_height(&estimator, 100);

        // A real transaction at a real fee rate, tracked in the pool.
        let tx = MsgTx {
            tx_in: vec![TxIn {
                previous_out_point: OutPoint {
                    hash: Hash([3u8; 32]),
                    index: 0,
                    tree: dcroxide_wire::TX_TREE_REGULAR,
                },
                ..TxIn::default()
            }],
            tx_out: vec![TxOut {
                value: 1,
                ..TxOut::default()
            }],
            ..MsgTx::default()
        };
        let tx_hash = tx.tx_hash();
        NodeFeeEstimatorSink::new(Arc::clone(&estimator)).add_mem_pool_transaction(
            &tx_hash,
            50_000,
            1000,
            TxType::Regular,
        );

        // Connecting a block containing it at a later height feeds the
        // estimator, which shifts it from the mempool to the mined
        // statistics (dcrd's ProcessBlock; the coinbase is ignored).
        let header = BlockHeader {
            version: 1,
            prev_block: Hash::ZERO,
            merkle_root: Hash::ZERO,
            stake_root: Hash::ZERO,
            vote_bits: 0,
            final_state: [0u8; 6],
            voters: 0,
            fresh_stake: 0,
            revocations: 0,
            pool_size: 0,
            bits: 0,
            sbits: 0,
            height: 101,
            size: 0,
            timestamp: 0,
            nonce: 0,
            extra_data: [0u8; 32],
            stake_version: 0,
        };
        let coinbase = MsgTx::default();
        let block = MsgBlock {
            header,
            transactions: vec![coinbase, tx],
            stransactions: Vec::new(),
        };
        assert_eq!(
            mem_pool_tracked(&estimator),
            1.0,
            "tracked before the block"
        );
        process_connected_block(&estimator, &block);

        assert!(estimator.lock().expect("est").is_enabled());
        assert_eq!(
            mem_pool_tracked(&estimator),
            0.0,
            "the mined tx left the mempool stats"
        );
    }

    /// The daemon shares these seams across the mempool, sync, and RPC
    /// threads.
    #[test]
    fn fee_seams_are_send() {
        fn assert_send<T: Send>() {}
        assert_send::<NodeFeeEstimatorSink>();
        assert_send::<NodeRpcFeeEstimator>();
        assert_send::<SharedFeeEstimator>();
    }
}
