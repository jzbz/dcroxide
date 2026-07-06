// SPDX-License-Identifier: ISC

//! The mempool error identities from dcrd's `internal/mempool`
//! `error.go`: the error kinds and the rule error that wraps either a
//! mempool kind or an underlying chain rule error.

use alloc::format;
use alloc::string::String;

/// A kind of mempool error (dcrd `ErrorKind`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// A mempool transaction is invalid per consensus.
    Invalid,
    /// An orphan violates the prevailing orphan policy.
    OrphanPolicyViolation,
    /// A transaction attempts to spend coins already spent by other
    /// transactions in the pool.
    MempoolDoubleSpend,
    /// A non-mix transaction attempts to double spend current pair
    /// request UTXOs in the mixpool.
    MixpoolDoubleSpend,
    /// A ticket already voted.
    AlreadyVoted,
    /// A transaction already exists in the mempool.
    Duplicate,
    /// A transaction is a standalone coinbase transaction.
    Coinbase,
    /// A transaction is a standalone treasurybase transaction.
    Treasurybase,
    /// A transaction will be expired as of the next block.
    Expired,
    /// A non-standard transaction.
    NonStandard,
    /// A transaction has one or more dust outputs.
    DustOutput,
    /// A transaction does not pay the minimum fee required by the
    /// active policy.
    InsufficientFee,
    /// The number of vote double spends exceeds the maximum allowed.
    TooManyVotes,
    /// A revocation already exists in the mempool.
    DuplicateRevocation,
    /// A ticket votes on a block height lower than the minimum allowed
    /// by the mempool.
    OldVote,
    /// A transaction already exists on the main chain and is not fully
    /// spent.
    AlreadyExists,
    /// A transaction's sequence locks are not active.
    SeqLockUnmet,
    /// A transaction pays fees above the maximum allowed by the active
    /// policy.
    FeeTooHigh,
    /// A transaction is an orphan.
    Orphan,
    /// The number of treasury spend hashes exceeds the maximum
    /// allowed.
    TooManyTSpends,
    /// A referenced treasury spend was already mined on an ancestor
    /// block.
    TSpendMinedOnAncestor,
    /// A treasury spend expiry is invalid.
    TSpendInvalidExpiry,
}

impl ErrorKind {
    /// dcrd's name for the kind, exactly as its `ErrorKind` string
    /// value (note `AlreadyVoted` carries the historical
    /// "ErrorAlreadyVoted" spelling).
    pub fn kind_name(self) -> &'static str {
        match self {
            ErrorKind::Invalid => "ErrInvalid",
            ErrorKind::OrphanPolicyViolation => "ErrOrphanPolicyViolation",
            ErrorKind::MempoolDoubleSpend => "ErrMempoolDoubleSpend",
            ErrorKind::MixpoolDoubleSpend => "ErrMixpoolDoubleSpend",
            ErrorKind::AlreadyVoted => "ErrorAlreadyVoted",
            ErrorKind::Duplicate => "ErrDuplicate",
            ErrorKind::Coinbase => "ErrCoinbase",
            ErrorKind::Treasurybase => "ErrTreasurybase",
            ErrorKind::Expired => "ErrExpired",
            ErrorKind::NonStandard => "ErrNonStandard",
            ErrorKind::DustOutput => "ErrDustOutput",
            ErrorKind::InsufficientFee => "ErrInsufficientFee",
            ErrorKind::TooManyVotes => "ErrTooManyVotes",
            ErrorKind::DuplicateRevocation => "ErrDuplicateRevocation",
            ErrorKind::OldVote => "ErrOldVote",
            ErrorKind::AlreadyExists => "ErrAlreadyExists",
            ErrorKind::SeqLockUnmet => "ErrSeqLockUnmet",
            ErrorKind::FeeTooHigh => "ErrFeeTooHigh",
            ErrorKind::Orphan => "ErrOrphan",
            ErrorKind::TooManyTSpends => "ErrTooManyTSpends",
            ErrorKind::TSpendMinedOnAncestor => "ErrTSpendMinedOnAncestor",
            ErrorKind::TSpendInvalidExpiry => "ErrTSpendInvalidExpiry",
        }
    }
}

/// The underlying error a [`RuleError`] wraps: either a mempool error
/// kind or a chain rule error (dcrd's `RuleError.Err`, which holds
/// either an `ErrorKind` or a `blockchain.RuleError`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuleErrorSource {
    /// A mempool policy error kind.
    Mempool(ErrorKind),
    /// An underlying chain rule error.
    Chain(dcroxide_blockchain::RuleError),
}

/// A mempool rule violation (dcrd `RuleError`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleError {
    /// The underlying error.
    pub err: RuleErrorSource,
    /// The human-readable description.
    pub description: String,
}

impl RuleError {
    /// dcrd's name for the underlying error kind: the mempool kind
    /// name or the wrapped chain rule error kind name.
    pub fn kind_name(&self) -> &'static str {
        match &self.err {
            RuleErrorSource::Mempool(kind) => kind.kind_name(),
            RuleErrorSource::Chain(err) => err.kind.kind_name(),
        }
    }
}

/// Wrap a chain rule error (dcrd `chainRuleError`).
pub fn chain_rule_error(chain_err: dcroxide_blockchain::RuleError) -> RuleError {
    RuleError {
        description: chain_err.description.clone(),
        err: RuleErrorSource::Chain(chain_err),
    }
}

/// Create a rule error from a mempool kind (dcrd `txRuleError`).
pub(crate) fn tx_rule_error(kind: ErrorKind, desc: impl Into<String>) -> RuleError {
    RuleError {
        err: RuleErrorSource::Mempool(kind),
        description: desc.into(),
    }
}

/// A new rule error with the given description, retaining the error
/// kind from the original error when it carries one (dcrd
/// `wrapTxRuleError`).
pub(crate) fn wrap_tx_rule_error(kind: ErrorKind, desc: String, err: &RuleError) -> RuleError {
    // Override the passed error kind with the one from the error if it
    // is a mempool kind.
    let kind = match &err.err {
        RuleErrorSource::Mempool(inner) => *inner,
        RuleErrorSource::Chain(_) => kind,
    };

    // Fill a default error description if empty.
    let desc = if desc.is_empty() {
        format!("rejected: {}", err.description)
    } else {
        desc
    };

    tx_rule_error(kind, desc)
}

/// An error from a pool operation: either a rule violation or a
/// non-rule failure from the chain backend (dcrd returns these as
/// plain errors alongside its `RuleError`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PoolError {
    /// A rule violation.
    Rule(RuleError),
    /// A non-rule failure.
    Other(String),
}

impl PoolError {
    /// dcrd's name for the error: the rule error kind name, or
    /// "plain" for non-rule failures.
    pub fn kind_name(&self) -> &'static str {
        match self {
            PoolError::Rule(err) => err.kind_name(),
            PoolError::Other(_) => "plain",
        }
    }
}

impl From<RuleError> for PoolError {
    fn from(err: RuleError) -> PoolError {
        PoolError::Rule(err)
    }
}
