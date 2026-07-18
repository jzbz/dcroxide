// SPDX-License-Identifier: ISC
//! Consensus rule error kinds (dcrd internal/blockchain `error.go`).
//!
//! This file's variant list is machine-generated from dcrd's ErrorKind
//! constants at the pinned tag; regenerate rather than hand-edit.

use alloc::string::{String, ToString};
use core::fmt;

/// The kind of a consensus rule violation; each variant's
/// [`kind_name`] matches the corresponding dcrd `ErrorKind` string
/// exactly.
///
/// [`kind_name`]: RuleErrorKind::kind_name
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[allow(missing_docs)] // The dcrd names are the documentation.
pub enum RuleErrorKind {
    DuplicateBlock,
    MissingParent,
    NoBlockData,
    BlockTooBig,
    WrongBlockSize,
    BlockVersionTooOld,
    BadStakeVersion,
    InvalidTime,
    TimeTooOld,
    TimeTooNew,
    UnexpectedDifficulty,
    HighHash,
    BadMerkleRoot,
    BadCommitmentRoot,
    ForkTooOld,
    BadMaxDiffCheckpoint,
    NoTransactions,
    NoTxInputs,
    NoTxOutputs,
    TxTooBig,
    BadTxOutValue,
    DuplicateTxInputs,
    TxVersionTooHigh,
    BadTxInput,
    ScriptVersionTooHigh,
    MissingTxOut,
    UnfinalizedTx,
    DuplicateTx,
    OverwriteTx,
    ImmatureSpend,
    SpendTooHigh,
    BadFees,
    TooManySigOps,
    FirstTxNotCoinbase,
    CoinbaseHeight,
    MultipleCoinbases,
    StakeTxInRegularTree,
    RegTxInStakeTree,
    BadCoinbaseScriptLen,
    BadCoinbaseValue,
    BadCoinbaseOutpoint,
    BadCoinbaseFraudProof,
    BadCoinbaseAmountIn,
    BadStakebaseAmountIn,
    BadStakebaseScriptLen,
    BadStakebaseScrVal,
    ScriptMalformed,
    ScriptValidation,
    NotEnoughStake,
    StakeBelowMinimum,
    NonstandardStakeTx,
    NotEnoughVotes,
    TooManyVotes,
    FreshStakeMismatch,
    TooManySStxs,
    InvalidEarlyStakeTx,
    TicketUnavailable,
    VotesOnWrongBlock,
    VotesMismatch,
    IncongruentVotebit,
    InvalidSSRtx,
    RevocationsMismatch,
    TooManyRevocations,
    TicketCommitment,
    InvalidVoteInput,
    BadNumPayees,
    BadPayeeScriptVersion,
    BadPayeeScriptType,
    MismatchedPayeeHash,
    BadPayeeValue,
    SSGenSubsidy,
    ImmatureTicketSpend,
    TicketInputScript,
    InvalidRevokeInput,
    TxSStxOutSpend,
    RegTxCreateStakeOut,
    InvalidFinalState,
    PoolSize,
    ForceReorgSameBlock,
    ForceReorgWrongChain,
    ForceReorgMissingChild,
    BadStakebaseValue,
    StakeFees,
    NoStakeTx,
    BadBlockHeight,
    BlockOneTx,
    BlockOneInputs,
    BlockOneOutputs,
    NoTreasury,
    ExpiredTx,
    ExpiryTxSpentEarly,
    FraudAmountIn,
    FraudBlockHeight,
    FraudBlockIndex,
    ZeroValueOutputSpend,
    InvalidEarlyVoteBits,
    InvalidEarlyFinalState,
    KnownInvalidBlock,
    InvalidAncestorBlock,
    InvalidTemplateParent,
    UnknownPiKey,
    InvalidPiSignature,
    InvalidTVoteWindow,
    NotTVI,
    InvalidTreasurySpendExpiry,
    InvalidTSpendWindow,
    NotEnoughTSpendVotes,
    TooManyTreasurySpendVotes,
    InvalidTSpendValueIn,
    TSpendExists,
    InvalidExpenditure,
    FirstTxNotTreasurybase,
    BadTreasurybaseOutpoint,
    BadTreasurybaseFraudProof,
    BadTreasurybaseScriptLen,
    TreasurybaseTxNotOpReturn,
    TreasurybaseHeight,
    InvalidTreasurybaseTxOutputs,
    InvalidTreasurybaseVersion,
    InvalidTreasurybaseScript,
    TreasurybaseOutValue,
    MultipleTreasurybases,
    BadTreasurybaseAmountIn,
    BadTSpendOutpoint,
    BadTSpendFraudProof,
    BadTSpendScriptLen,
    InvalidTAddChange,
    TooManyTAdds,
    TicketExhaustion,
    DBTooOldToUpgrade,
    UnknownBlock,
    NoFilter,
    NoTreasuryBalance,
    InvalidateGenesisBlock,
    SerializeHeader,
    NotAnAncestor,
    RequestTooLarge,
    UtxoBackend,
    UtxoBackendCorruption,
    UtxoBackendNotOpen,
    UtxoBackendTxClosed,
    InvalidRevocationTxVersion,
    NoExpiredTicketRevocation,
    NoMissedTicketRevocation,
    UnknownDeploymentID,
    UnknownDeploymentVersion,
    DuplicateDeployment,
    UnknownDeploymentChoice,
    DeploymentBadMask,
    DeploymentTooManyChoices,
    DeploymentMissingChoiceID,
    DeploymentBadChoiceBits,
    DeploymentNonExclusiveFlags,
    DeploymentDuplicateChoice,
    DeploymentMissingAbstain,
    DeploymentTooManyAbstain,
    DeploymentMissingNo,
    DeploymentTooManyNo,
    DeploymentChoiceAbstain,
    ForcedMainNetChoice,
}

impl RuleErrorKind {
    /// dcrd's name for this error kind.
    pub fn kind_name(self) -> &'static str {
        match self {
            RuleErrorKind::DuplicateBlock => "ErrDuplicateBlock",
            RuleErrorKind::MissingParent => "ErrMissingParent",
            RuleErrorKind::NoBlockData => "ErrNoBlockData",
            RuleErrorKind::BlockTooBig => "ErrBlockTooBig",
            RuleErrorKind::WrongBlockSize => "ErrWrongBlockSize",
            RuleErrorKind::BlockVersionTooOld => "ErrBlockVersionTooOld",
            RuleErrorKind::BadStakeVersion => "ErrBadStakeVersion",
            RuleErrorKind::InvalidTime => "ErrInvalidTime",
            RuleErrorKind::TimeTooOld => "ErrTimeTooOld",
            RuleErrorKind::TimeTooNew => "ErrTimeTooNew",
            RuleErrorKind::UnexpectedDifficulty => "ErrUnexpectedDifficulty",
            RuleErrorKind::HighHash => "ErrHighHash",
            RuleErrorKind::BadMerkleRoot => "ErrBadMerkleRoot",
            RuleErrorKind::BadCommitmentRoot => "ErrBadCommitmentRoot",
            RuleErrorKind::ForkTooOld => "ErrForkTooOld",
            RuleErrorKind::BadMaxDiffCheckpoint => "ErrBadMaxDiffCheckpoint",
            RuleErrorKind::NoTransactions => "ErrNoTransactions",
            RuleErrorKind::NoTxInputs => "ErrNoTxInputs",
            RuleErrorKind::NoTxOutputs => "ErrNoTxOutputs",
            RuleErrorKind::TxTooBig => "ErrTxTooBig",
            RuleErrorKind::BadTxOutValue => "ErrBadTxOutValue",
            RuleErrorKind::DuplicateTxInputs => "ErrDuplicateTxInputs",
            RuleErrorKind::TxVersionTooHigh => "ErrTxVersionTooHigh",
            RuleErrorKind::BadTxInput => "ErrBadTxInput",
            RuleErrorKind::ScriptVersionTooHigh => "ErrScriptVersionTooHigh",
            RuleErrorKind::MissingTxOut => "ErrMissingTxOut",
            RuleErrorKind::UnfinalizedTx => "ErrUnfinalizedTx",
            RuleErrorKind::DuplicateTx => "ErrDuplicateTx",
            RuleErrorKind::OverwriteTx => "ErrOverwriteTx",
            RuleErrorKind::ImmatureSpend => "ErrImmatureSpend",
            RuleErrorKind::SpendTooHigh => "ErrSpendTooHigh",
            RuleErrorKind::BadFees => "ErrBadFees",
            RuleErrorKind::TooManySigOps => "ErrTooManySigOps",
            RuleErrorKind::FirstTxNotCoinbase => "ErrFirstTxNotCoinbase",
            RuleErrorKind::CoinbaseHeight => "ErrCoinbaseHeight",
            RuleErrorKind::MultipleCoinbases => "ErrMultipleCoinbases",
            RuleErrorKind::StakeTxInRegularTree => "ErrStakeTxInRegularTree",
            RuleErrorKind::RegTxInStakeTree => "ErrRegTxInStakeTree",
            RuleErrorKind::BadCoinbaseScriptLen => "ErrBadCoinbaseScriptLen",
            RuleErrorKind::BadCoinbaseValue => "ErrBadCoinbaseValue",
            RuleErrorKind::BadCoinbaseOutpoint => "ErrBadCoinbaseOutpoint",
            RuleErrorKind::BadCoinbaseFraudProof => "ErrBadCoinbaseFraudProof",
            RuleErrorKind::BadCoinbaseAmountIn => "ErrBadCoinbaseAmountIn",
            RuleErrorKind::BadStakebaseAmountIn => "ErrBadStakebaseAmountIn",
            RuleErrorKind::BadStakebaseScriptLen => "ErrBadStakebaseScriptLen",
            RuleErrorKind::BadStakebaseScrVal => "ErrBadStakebaseScrVal",
            RuleErrorKind::ScriptMalformed => "ErrScriptMalformed",
            RuleErrorKind::ScriptValidation => "ErrScriptValidation",
            RuleErrorKind::NotEnoughStake => "ErrNotEnoughStake",
            RuleErrorKind::StakeBelowMinimum => "ErrStakeBelowMinimum",
            RuleErrorKind::NonstandardStakeTx => "ErrNonstandardStakeTx",
            RuleErrorKind::NotEnoughVotes => "ErrNotEnoughVotes",
            RuleErrorKind::TooManyVotes => "ErrTooManyVotes",
            RuleErrorKind::FreshStakeMismatch => "ErrFreshStakeMismatch",
            RuleErrorKind::TooManySStxs => "ErrTooManySStxs",
            RuleErrorKind::InvalidEarlyStakeTx => "ErrInvalidEarlyStakeTx",
            RuleErrorKind::TicketUnavailable => "ErrTicketUnavailable",
            RuleErrorKind::VotesOnWrongBlock => "ErrVotesOnWrongBlock",
            RuleErrorKind::VotesMismatch => "ErrVotesMismatch",
            RuleErrorKind::IncongruentVotebit => "ErrIncongruentVotebit",
            RuleErrorKind::InvalidSSRtx => "ErrInvalidSSRtx",
            RuleErrorKind::RevocationsMismatch => "ErrRevocationsMismatch",
            RuleErrorKind::TooManyRevocations => "ErrTooManyRevocations",
            RuleErrorKind::TicketCommitment => "ErrTicketCommitment",
            RuleErrorKind::InvalidVoteInput => "ErrInvalidVoteInput",
            RuleErrorKind::BadNumPayees => "ErrBadNumPayees",
            RuleErrorKind::BadPayeeScriptVersion => "ErrBadPayeeScriptVersion",
            RuleErrorKind::BadPayeeScriptType => "ErrBadPayeeScriptType",
            RuleErrorKind::MismatchedPayeeHash => "ErrMismatchedPayeeHash",
            RuleErrorKind::BadPayeeValue => "ErrBadPayeeValue",
            RuleErrorKind::SSGenSubsidy => "ErrSSGenSubsidy",
            RuleErrorKind::ImmatureTicketSpend => "ErrImmatureTicketSpend",
            RuleErrorKind::TicketInputScript => "ErrTicketInputScript",
            RuleErrorKind::InvalidRevokeInput => "ErrInvalidRevokeInput",
            RuleErrorKind::TxSStxOutSpend => "ErrTxSStxOutSpend",
            RuleErrorKind::RegTxCreateStakeOut => "ErrRegTxCreateStakeOut",
            RuleErrorKind::InvalidFinalState => "ErrInvalidFinalState",
            RuleErrorKind::PoolSize => "ErrPoolSize",
            RuleErrorKind::ForceReorgSameBlock => "ErrForceReorgSameBlock",
            RuleErrorKind::ForceReorgWrongChain => "ErrForceReorgWrongChain",
            RuleErrorKind::ForceReorgMissingChild => "ErrForceReorgMissingChild",
            RuleErrorKind::BadStakebaseValue => "ErrBadStakebaseValue",
            RuleErrorKind::StakeFees => "ErrStakeFees",
            RuleErrorKind::NoStakeTx => "ErrNoStakeTx",
            RuleErrorKind::BadBlockHeight => "ErrBadBlockHeight",
            RuleErrorKind::BlockOneTx => "ErrBlockOneTx",
            RuleErrorKind::BlockOneInputs => "ErrBlockOneInputs",
            RuleErrorKind::BlockOneOutputs => "ErrBlockOneOutputs",
            RuleErrorKind::NoTreasury => "ErrNoTreasury",
            RuleErrorKind::ExpiredTx => "ErrExpiredTx",
            RuleErrorKind::ExpiryTxSpentEarly => "ErrExpiryTxSpentEarly",
            RuleErrorKind::FraudAmountIn => "ErrFraudAmountIn",
            RuleErrorKind::FraudBlockHeight => "ErrFraudBlockHeight",
            RuleErrorKind::FraudBlockIndex => "ErrFraudBlockIndex",
            RuleErrorKind::ZeroValueOutputSpend => "ErrZeroValueOutputSpend",
            RuleErrorKind::InvalidEarlyVoteBits => "ErrInvalidEarlyVoteBits",
            RuleErrorKind::InvalidEarlyFinalState => "ErrInvalidEarlyFinalState",
            RuleErrorKind::KnownInvalidBlock => "ErrKnownInvalidBlock",
            RuleErrorKind::InvalidAncestorBlock => "ErrInvalidAncestorBlock",
            RuleErrorKind::InvalidTemplateParent => "ErrInvalidTemplateParent",
            RuleErrorKind::UnknownPiKey => "ErrUnknownPiKey",
            RuleErrorKind::InvalidPiSignature => "ErrInvalidPiSignature",
            RuleErrorKind::InvalidTVoteWindow => "ErrInvalidTVoteWindow",
            RuleErrorKind::NotTVI => "ErrNotTVI",
            RuleErrorKind::InvalidTSpendWindow => "ErrInvalidTSpendWindow",
            RuleErrorKind::InvalidTreasurySpendExpiry => "ErrInvalidTreasurySpendExpiry",
            RuleErrorKind::NotEnoughTSpendVotes => "ErrNotEnoughTSpendVotes",
            RuleErrorKind::TooManyTreasurySpendVotes => "ErrTooManyTreasurySpendVotes",
            RuleErrorKind::InvalidTSpendValueIn => "ErrInvalidTSpendValueIn",
            RuleErrorKind::TSpendExists => "ErrTSpendExists",
            RuleErrorKind::InvalidExpenditure => "ErrInvalidExpenditure",
            RuleErrorKind::FirstTxNotTreasurybase => "ErrFirstTxNotTreasurybase",
            RuleErrorKind::BadTreasurybaseOutpoint => "ErrBadTreasurybaseOutpoint",
            RuleErrorKind::BadTreasurybaseFraudProof => "ErrBadTreasurybaseFraudProof",
            RuleErrorKind::BadTreasurybaseScriptLen => "ErrBadTreasurybaseScriptLen",
            RuleErrorKind::TreasurybaseTxNotOpReturn => "ErrTreasurybaseTxNotOpReturn",
            RuleErrorKind::TreasurybaseHeight => "ErrTreasurybaseHeight",
            RuleErrorKind::InvalidTreasurybaseTxOutputs => "ErrInvalidTreasurybaseTxOutputs",
            RuleErrorKind::InvalidTreasurybaseVersion => "ErrInvalidTreasurybaseVersion",
            RuleErrorKind::InvalidTreasurybaseScript => "ErrInvalidTreasurybaseScript",
            RuleErrorKind::TreasurybaseOutValue => "ErrTreasurybaseOutValue",
            RuleErrorKind::MultipleTreasurybases => "ErrMultipleTreasurybases",
            RuleErrorKind::BadTreasurybaseAmountIn => "ErrBadTreasurybaseAmountIn",
            RuleErrorKind::BadTSpendOutpoint => "ErrBadTSpendOutpoint",
            RuleErrorKind::BadTSpendFraudProof => "ErrBadTSpendFraudProof",
            RuleErrorKind::BadTSpendScriptLen => "ErrBadTSpendScriptLen",
            RuleErrorKind::InvalidTAddChange => "ErrInvalidTAddChange",
            RuleErrorKind::TooManyTAdds => "ErrTooManyTAdds",
            RuleErrorKind::TicketExhaustion => "ErrTicketExhaustion",
            RuleErrorKind::DBTooOldToUpgrade => "ErrDBTooOldToUpgrade",
            RuleErrorKind::UnknownBlock => "ErrUnknownBlock",
            RuleErrorKind::NoFilter => "ErrNoFilter",
            RuleErrorKind::NoTreasuryBalance => "ErrNoTreasuryBalance",
            RuleErrorKind::InvalidateGenesisBlock => "ErrInvalidateGenesisBlock",
            RuleErrorKind::SerializeHeader => "ErrSerializeHeader",
            RuleErrorKind::NotAnAncestor => "ErrNotAnAncestor",
            RuleErrorKind::RequestTooLarge => "ErrRequestTooLarge",
            RuleErrorKind::UtxoBackend => "ErrUtxoBackend",
            RuleErrorKind::UtxoBackendCorruption => "ErrUtxoBackendCorruption",
            RuleErrorKind::UtxoBackendNotOpen => "ErrUtxoBackendNotOpen",
            RuleErrorKind::UtxoBackendTxClosed => "ErrUtxoBackendTxClosed",
            RuleErrorKind::InvalidRevocationTxVersion => "ErrInvalidRevocationTxVersion",
            RuleErrorKind::NoExpiredTicketRevocation => "ErrNoExpiredTicketRevocation",
            RuleErrorKind::NoMissedTicketRevocation => "ErrNoMissedTicketRevocation",
            RuleErrorKind::UnknownDeploymentID => "ErrUnknownDeploymentID",
            RuleErrorKind::UnknownDeploymentVersion => "ErrUnknownDeploymentVersion",
            RuleErrorKind::DuplicateDeployment => "ErrDuplicateDeployment",
            RuleErrorKind::UnknownDeploymentChoice => "ErrUnknownDeploymentChoice",
            RuleErrorKind::DeploymentBadMask => "ErrDeploymentBadMask",
            RuleErrorKind::DeploymentTooManyChoices => "ErrDeploymentTooManyChoices",
            RuleErrorKind::DeploymentMissingChoiceID => "ErrDeploymentMissingChoiceID",
            RuleErrorKind::DeploymentBadChoiceBits => "ErrDeploymentBadChoiceBits",
            RuleErrorKind::DeploymentNonExclusiveFlags => "ErrDeploymentNonExclusiveFlags",
            RuleErrorKind::DeploymentDuplicateChoice => "ErrDeploymentDuplicateChoice",
            RuleErrorKind::DeploymentMissingAbstain => "ErrDeploymentMissingAbstain",
            RuleErrorKind::DeploymentTooManyAbstain => "ErrDeploymentTooManyAbstain",
            RuleErrorKind::DeploymentMissingNo => "ErrDeploymentMissingNo",
            RuleErrorKind::DeploymentTooManyNo => "ErrDeploymentTooManyNo",
            RuleErrorKind::DeploymentChoiceAbstain => "ErrDeploymentChoiceAbstain",
            RuleErrorKind::ForcedMainNetChoice => "ErrForcedMainNetChoice",
        }
    }
}

impl fmt::Display for RuleErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kind_name())
    }
}

/// A consensus rule violation (dcrd `RuleError`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleError {
    /// The kind of rule that was violated.
    pub kind: RuleErrorKind,
    /// The human-readable description, mirroring dcrd's message.
    pub description: String,
}

impl fmt::Display for RuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.description)
    }
}

/// Build a [`RuleError`] (dcrd `ruleError`).
pub(crate) fn rule_error(kind: RuleErrorKind, description: impl Into<String>) -> RuleError {
    RuleError {
        kind,
        description: description.into(),
    }
}

/// Render a slice of block-processing errors exactly as dcrd's
/// `blockchain.MultiError.Error` renders the combined `finalErr` that
/// `ProcessBlock` returns (dcrd internal/blockchain `error.go`).
///
/// A lone error renders unadorned (its bare description), matching the
/// common single-error rejection.  Two or more render as a
/// `multiple errors (N):` block that lists the first five errors, each
/// on its own ` - <description>` line, followed by a ` - ... M more
/// error(s)` line when more than five are present.
///
/// dcrd's `ProcessBlock` flattens the reorganization `MultiError` into
/// the acceptance error rather than nesting it — its final-error switch
/// uses `errors.As` to combine them into a single flat `MultiError`
/// rather than wrapping one inside the other.  The flat error slice the
/// ported [`process_block`](crate::process::Chain::process_block)
/// returns (the acceptance error followed by the reorganization errors)
/// therefore renders byte-for-byte identically to dcrd's `finalErr`.
pub fn render_multi_error(errs: &[RuleError]) -> String {
    // dcrd `MultiError.Error` returns a lone error's text unadorned.
    if errs.len() == 1 {
        return errs[0].description.clone();
    }

    const MAX_ERRS: usize = 5;
    let mut out = String::new();
    out.push_str("multiple errors (");
    out.push_str(&errs.len().to_string());
    out.push_str("):\n");
    for err in errs.iter().take(MAX_ERRS) {
        out.push_str(" - ");
        out.push_str(&err.description);
        out.push('\n');
    }
    if errs.len() > MAX_ERRS {
        out.push_str(" - ... ");
        out.push_str(&(errs.len() - MAX_ERRS).to_string());
        out.push_str(" more error(s)\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn err(description: &str) -> RuleError {
        rule_error(RuleErrorKind::UnexpectedDifficulty, description)
    }

    // Ground-truth strings below are captured from dcrd
    // release-v2.1.5's `blockchain.MultiError.Error`.

    #[test]
    fn single_error_is_unadorned() {
        assert_eq!(
            render_multi_error(&[err("already have block abc")]),
            "already have block abc"
        );
    }

    #[test]
    fn two_errors_render_as_multi() {
        // The acceptance error followed by a single reorganization
        // error, the smallest multi-error rejection.
        assert_eq!(
            render_multi_error(&[err("accept failed: bad"), err("reorg failed: worse")]),
            "multiple errors (2):\n - accept failed: bad\n - reorg failed: worse\n"
        );
    }

    #[test]
    fn three_errors_list_every_line() {
        assert_eq!(
            render_multi_error(&[err("accept-err"), err("reorg-err-1"), err("reorg-err-2")]),
            "multiple errors (3):\n - accept-err\n - reorg-err-1\n - reorg-err-2\n"
        );
    }

    #[test]
    fn five_errors_have_no_tail() {
        assert_eq!(
            render_multi_error(&[err("e1"), err("e2"), err("e3"), err("e4"), err("e5")]),
            "multiple errors (5):\n - e1\n - e2\n - e3\n - e4\n - e5\n"
        );
    }

    #[test]
    fn more_than_five_errors_are_capped_with_tail() {
        let errs = vec![
            err("e1"),
            err("e2"),
            err("e3"),
            err("e4"),
            err("e5"),
            err("e6"),
            err("e7"),
        ];
        assert_eq!(
            render_multi_error(&errs),
            "multiple errors (7):\n - e1\n - e2\n - e3\n - e4\n - e5\n - ... 2 more error(s)\n"
        );
    }
}
