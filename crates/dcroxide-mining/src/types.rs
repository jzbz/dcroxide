// SPDX-License-Identifier: ISC

//! The transaction descriptor types shared between the transaction
//! source and the mining code (dcrd `mining.TxDesc` and friends).

use dcroxide_chainhash::Hash;
use dcroxide_stake::TxType;
use dcroxide_wire::MsgTx;

/// The height used for the "block" height field of contextual
/// transaction information when it has not yet been mined into a
/// block (dcrd `mining.UnminedHeight`).
pub const UNMINED_HEIGHT: i64 = 0x7fffffff;

/// A transaction in the source pool along with metadata (dcrd
/// `mining.TxDesc`, carrying the cached hash and tree the Go version
/// keeps on `dcrutil.Tx`).
#[derive(Clone, Debug)]
pub struct TxDesc {
    /// The transaction.
    pub tx: MsgTx,
    /// The transaction hash.
    pub tx_hash: Hash,
    /// The transaction tree derived from the type.
    pub tree: i8,
    /// The transaction type.
    pub tx_type: TxType,
    /// When the transaction was added to the pool, as unix seconds.
    pub added_unix: i64,
    /// The best block height when the transaction entered the pool.
    pub height: i64,
    /// The transaction fee in atoms.
    pub fee: i64,
    /// The total signature operations.
    pub total_sig_ops: i64,
    /// The serialized size in bytes.
    pub tx_size: i64,
}

/// Aggregated statistics for the unconfirmed ancestors of a
/// transaction (dcrd `TxAncestorStats`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct TxAncestorStats {
    /// The sum of all fees of unconfirmed ancestors.
    pub fees: i64,
    /// The total size of all unconfirmed ancestors.
    pub size_bytes: i64,
    /// The total signature operations of all ancestors.
    pub total_sig_ops: i64,
    /// The total number of ancestors.
    pub num_ancestors: i64,
    /// The number of descendants that have ancestor statistics
    /// tracked.
    pub num_descendants: i64,
}

/// Vote metadata for a block (dcrd `mining.VoteDesc`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VoteDesc {
    /// The vote transaction hash.
    pub vote_hash: Hash,
    /// The spent ticket hash.
    pub ticket_hash: Hash,
    /// Whether the vote approves the previous block's regular tree.
    pub approves_parent: bool,
}
