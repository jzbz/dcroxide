// SPDX-License-Identifier: ISC
// GENERATED from dcrd blockchain/stake error.go ErrorKind constants at
// release-v2.1.5 (stake/v5 v5.0.2); names are the differential parity
// surface. Regenerate rather than editing by hand.
//! Stake rule errors (dcrd stake `ErrorKind`/`RuleError`).

use alloc::string::String;
use core::fmt;

/// The kind of a stake rule error, mirroring dcrd's constants 1:1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)] // Kinds mirror dcrd's documented ErrorKind constants 1:1.
pub enum ErrorKind {
    SStxTooManyInputs,
    SStxTooManyOutputs,
    SStxNoOutputs,
    SStxInvalidInputs,
    SStxInvalidOutputs,
    SStxInOutProportions,
    SStxBadCommitAmount,
    SStxBadChangeAmts,
    SStxVerifyCalcAmts,
    SSGenWrongNumInputs,
    SSGenTooManyOutputs,
    SSGenNoOutputs,
    SSGenWrongIndex,
    SSGenWrongTxTree,
    SSGenNoStakebase,
    SSGenNoReference,
    SSGenBadReference,
    SSGenNoVotePush,
    SSGenBadVotePush,
    SSGenInvalidDiscriminatorLength,
    SSGenInvalidNullScript,
    SSGenInvalidTVLength,
    SSGenInvalidTreasuryVote,
    SSGenDuplicateTreasuryVote,
    SSGenInvalidTxVersion,
    SSGenUnknownDiscriminator,
    SSGenBadGenOuts,
    SSRtxWrongNumInputs,
    SSRtxTooManyOutputs,
    SSRtxNoOutputs,
    SSRtxWrongTxTree,
    SSRtxBadOuts,
    SSRtxInvalidFee,
    SSRtxInputHasSigScript,
    SSRtxInvalidTxVersion,
    VerSStxAmts,
    VerifyInput,
    VerifyOutType,
    VerifyTooMuchFees,
    VerifySpendTooMuch,
    VerifyOutputAmt,
    VerifyOutPkhs,
    DatabaseCorrupt,
    MissingDatabaseTx,
    MemoryCorruption,
    FindTicketIdxs,
    MissingTicket,
    DuplicateTicket,
    UnknownTicketSpent,
    TAddInvalidTxVersion,
    TAddInvalidCount,
    TAddInvalidVersion,
    TAddInvalidScriptLength,
    TAddInvalidLength,
    TAddInvalidOpcode,
    TAddInvalidChange,
    TSpendInvalidTxVersion,
    TSpendInvalidLength,
    TSpendInvalidVersion,
    TSpendInvalidScriptLength,
    TSpendInvalidPubkey,
    TSpendInvalidScript,
    TSpendInvalidTGen,
    TSpendInvalidTransaction,
    TSpendInvalidSpendScript,
    TreasuryBaseInvalidTxVersion,
    TreasuryBaseInvalidCount,
    TreasuryBaseInvalidLength,
    TreasuryBaseInvalidVersion,
    TreasuryBaseInvalidOpcode0,
    TreasuryBaseInvalidOpcode1,
    TreasuryBaseInvalid,
}

impl ErrorKind {
    /// The dcrd `ErrorKind` constant name (e.g. `"ErrSStxTooManyInputs"`).
    pub fn kind_name(self) -> &'static str {
        match self {
            ErrorKind::SStxTooManyInputs => "ErrSStxTooManyInputs",
            ErrorKind::SStxTooManyOutputs => "ErrSStxTooManyOutputs",
            ErrorKind::SStxNoOutputs => "ErrSStxNoOutputs",
            ErrorKind::SStxInvalidInputs => "ErrSStxInvalidInputs",
            ErrorKind::SStxInvalidOutputs => "ErrSStxInvalidOutputs",
            ErrorKind::SStxInOutProportions => "ErrSStxInOutProportions",
            ErrorKind::SStxBadCommitAmount => "ErrSStxBadCommitAmount",
            ErrorKind::SStxBadChangeAmts => "ErrSStxBadChangeAmts",
            ErrorKind::SStxVerifyCalcAmts => "ErrSStxVerifyCalcAmts",
            ErrorKind::SSGenWrongNumInputs => "ErrSSGenWrongNumInputs",
            ErrorKind::SSGenTooManyOutputs => "ErrSSGenTooManyOutputs",
            ErrorKind::SSGenNoOutputs => "ErrSSGenNoOutputs",
            ErrorKind::SSGenWrongIndex => "ErrSSGenWrongIndex",
            ErrorKind::SSGenWrongTxTree => "ErrSSGenWrongTxTree",
            ErrorKind::SSGenNoStakebase => "ErrSSGenNoStakebase",
            ErrorKind::SSGenNoReference => "ErrSSGenNoReference",
            ErrorKind::SSGenBadReference => "ErrSSGenBadReference",
            ErrorKind::SSGenNoVotePush => "ErrSSGenNoVotePush",
            ErrorKind::SSGenBadVotePush => "ErrSSGenBadVotePush",
            ErrorKind::SSGenInvalidDiscriminatorLength => "ErrSSGenInvalidDiscriminatorLength",
            ErrorKind::SSGenInvalidNullScript => "ErrSSGenInvalidNullScript",
            ErrorKind::SSGenInvalidTVLength => "ErrSSGenInvalidTVLength",
            ErrorKind::SSGenInvalidTreasuryVote => "ErrSSGenInvalidTreasuryVote",
            ErrorKind::SSGenDuplicateTreasuryVote => "ErrSSGenDuplicateTreasuryVote",
            ErrorKind::SSGenInvalidTxVersion => "ErrSSGenInvalidTxVersion",
            ErrorKind::SSGenUnknownDiscriminator => "ErrSSGenUnknownDiscriminator",
            ErrorKind::SSGenBadGenOuts => "ErrSSGenBadGenOuts",
            ErrorKind::SSRtxWrongNumInputs => "ErrSSRtxWrongNumInputs",
            ErrorKind::SSRtxTooManyOutputs => "ErrSSRtxTooManyOutputs",
            ErrorKind::SSRtxNoOutputs => "ErrSSRtxNoOutputs",
            ErrorKind::SSRtxWrongTxTree => "ErrSSRtxWrongTxTree",
            ErrorKind::SSRtxBadOuts => "ErrSSRtxBadOuts",
            ErrorKind::SSRtxInvalidFee => "ErrSSRtxInvalidFee",
            ErrorKind::SSRtxInputHasSigScript => "ErrSSRtxInputHasSigScript",
            ErrorKind::SSRtxInvalidTxVersion => "ErrSSRtxInvalidTxVersion",
            ErrorKind::VerSStxAmts => "ErrVerSStxAmts",
            ErrorKind::VerifyInput => "ErrVerifyInput",
            ErrorKind::VerifyOutType => "ErrVerifyOutType",
            ErrorKind::VerifyTooMuchFees => "ErrVerifyTooMuchFees",
            ErrorKind::VerifySpendTooMuch => "ErrVerifySpendTooMuch",
            ErrorKind::VerifyOutputAmt => "ErrVerifyOutputAmt",
            ErrorKind::VerifyOutPkhs => "ErrVerifyOutPkhs",
            ErrorKind::DatabaseCorrupt => "ErrDatabaseCorrupt",
            ErrorKind::MissingDatabaseTx => "ErrMissingDatabaseTx",
            ErrorKind::MemoryCorruption => "ErrMemoryCorruption",
            ErrorKind::FindTicketIdxs => "ErrFindTicketIdxs",
            ErrorKind::MissingTicket => "ErrMissingTicket",
            ErrorKind::DuplicateTicket => "ErrDuplicateTicket",
            ErrorKind::UnknownTicketSpent => "ErrUnknownTicketSpent",
            ErrorKind::TAddInvalidTxVersion => "ErrTAddInvalidTxVersion",
            ErrorKind::TAddInvalidCount => "ErrTAddInvalidCount",
            ErrorKind::TAddInvalidVersion => "ErrTAddInvalidVersion",
            ErrorKind::TAddInvalidScriptLength => "ErrTAddInvalidScriptLength",
            ErrorKind::TAddInvalidLength => "ErrTAddInvalidLength",
            ErrorKind::TAddInvalidOpcode => "ErrTAddInvalidOpcode",
            ErrorKind::TAddInvalidChange => "ErrTAddInvalidChange",
            ErrorKind::TSpendInvalidTxVersion => "ErrTSpendInvalidTxVersion",
            ErrorKind::TSpendInvalidLength => "ErrTSpendInvalidLength",
            ErrorKind::TSpendInvalidVersion => "ErrTSpendInvalidVersion",
            ErrorKind::TSpendInvalidScriptLength => "ErrTSpendInvalidScriptLength",
            ErrorKind::TSpendInvalidPubkey => "ErrTSpendInvalidPubkey",
            ErrorKind::TSpendInvalidScript => "ErrTSpendInvalidScript",
            ErrorKind::TSpendInvalidTGen => "ErrTSpendInvalidTGen",
            ErrorKind::TSpendInvalidTransaction => "ErrTSpendInvalidTransaction",
            ErrorKind::TSpendInvalidSpendScript => "ErrTSpendInvalidSpendScript",
            ErrorKind::TreasuryBaseInvalidTxVersion => "ErrTreasuryBaseInvalidTxVersion",
            ErrorKind::TreasuryBaseInvalidCount => "ErrTreasuryBaseInvalidCount",
            ErrorKind::TreasuryBaseInvalidLength => "ErrTreasuryBaseInvalidLength",
            ErrorKind::TreasuryBaseInvalidVersion => "ErrTreasuryBaseInvalidVersion",
            ErrorKind::TreasuryBaseInvalidOpcode0 => "ErrTreasuryBaseInvalidOpcode0",
            ErrorKind::TreasuryBaseInvalidOpcode1 => "ErrTreasuryBaseInvalidOpcode1",
            ErrorKind::TreasuryBaseInvalid => "ErrTreasuryBaseInvalid",
        }
    }
}

/// A stake rule error (dcrd `RuleError`): the kind plus an informational
/// description; only the kind carries identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleError {
    /// The kind of error.
    pub kind: ErrorKind,
    /// Human-readable description.
    pub description: String,
}

impl fmt::Display for RuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.description)
    }
}

impl core::error::Error for RuleError {}

/// Construct a [`RuleError`] (dcrd `stakeRuleError`).
pub(crate) fn stake_rule_error(kind: ErrorKind, description: impl Into<String>) -> RuleError {
    RuleError {
        kind,
        description: description.into(),
    }
}
