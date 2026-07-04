// SPDX-License-Identifier: ISC
//! Script errors, mirroring dcrd txscript's `ErrorKind`/`Error` identities.

use alloc::string::String;
use core::fmt;

/// The kind of a script error (dcrd `ErrorKind`).
///
/// The variants and their [`ErrorKind::kind_name`] strings match dcrd's
/// constants one-for-one; the names are the differential parity surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)] // Kinds mirror dcrd's documented ErrorKind constants 1:1.
pub enum ErrorKind {
    // Failures related to improper API usage.
    InvalidIndex,
    InvalidSigHashSingleIndex,
    UnsupportedScriptVersion,

    // Failures related to final execution state.
    EarlyReturn,
    EmptyStack,
    EvalFalse,
    ScriptUnfinished,
    InvalidProgramCounter,

    // Failures related to exceeding maximum allowed limits.
    ScriptTooBig,
    ElementTooBig,
    TooManyOperations,
    StackOverflow,
    InvalidPubKeyCount,
    InvalidSignatureCount,
    NumOutOfRange,

    // Failures related to verification operations.
    Verify,
    EqualVerify,
    NumEqualVerify,
    CheckSigVerify,
    CheckMultiSigVerify,
    CheckSigAltVerify,

    // Failures related to improper use of opcodes.
    P2SHStakeOpCodes,
    DisabledOpcode,
    ReservedOpcode,
    MalformedPush,
    InvalidStackOperation,
    UnbalancedConditional,
    NegativeSubstrIdx,
    OverflowSubstrIdx,
    NegativeRotation,
    OverflowRotation,
    DivideByZero,
    NegativeShift,
    OverflowShift,
    P2SHTreasuryOpCodes,

    // Failures related to malleability.
    MinimalData,
    InvalidSigHashType,
    SigTooShort,
    SigTooLong,
    SigInvalidSeqID,
    SigInvalidDataLen,
    SigMissingSTypeID,
    SigMissingSLen,
    SigInvalidSLen,
    SigInvalidRIntID,
    SigZeroRLen,
    SigNegativeR,
    SigTooMuchRPadding,
    SigInvalidSIntID,
    SigZeroSLen,
    SigNegativeS,
    SigTooMuchSPadding,
    SigHighS,
    NotPushOnly,
    PubKeyType,
    CleanStack,

    // Failures related to soft forks.
    DiscourageUpgradableNOPs,
    NegativeLockTime,
    UnsatisfiedLockTime,
}

impl ErrorKind {
    /// The dcrd `ErrorKind` constant name (e.g. `"ErrEvalFalse"`), used to
    /// assert error-identity parity in differential tests.
    pub fn kind_name(self) -> &'static str {
        use ErrorKind::*;
        match self {
            InvalidIndex => "ErrInvalidIndex",
            InvalidSigHashSingleIndex => "ErrInvalidSigHashSingleIndex",
            UnsupportedScriptVersion => "ErrUnsupportedScriptVersion",
            EarlyReturn => "ErrEarlyReturn",
            EmptyStack => "ErrEmptyStack",
            EvalFalse => "ErrEvalFalse",
            ScriptUnfinished => "ErrScriptUnfinished",
            InvalidProgramCounter => "ErrInvalidProgramCounter",
            ScriptTooBig => "ErrScriptTooBig",
            ElementTooBig => "ErrElementTooBig",
            TooManyOperations => "ErrTooManyOperations",
            StackOverflow => "ErrStackOverflow",
            InvalidPubKeyCount => "ErrInvalidPubKeyCount",
            InvalidSignatureCount => "ErrInvalidSignatureCount",
            NumOutOfRange => "ErrNumOutOfRange",
            Verify => "ErrVerify",
            EqualVerify => "ErrEqualVerify",
            NumEqualVerify => "ErrNumEqualVerify",
            CheckSigVerify => "ErrCheckSigVerify",
            CheckMultiSigVerify => "ErrCheckMultiSigVerify",
            CheckSigAltVerify => "ErrCheckSigAltVerify",
            P2SHStakeOpCodes => "ErrP2SHStakeOpCodes",
            DisabledOpcode => "ErrDisabledOpcode",
            ReservedOpcode => "ErrReservedOpcode",
            MalformedPush => "ErrMalformedPush",
            InvalidStackOperation => "ErrInvalidStackOperation",
            UnbalancedConditional => "ErrUnbalancedConditional",
            NegativeSubstrIdx => "ErrNegativeSubstrIdx",
            OverflowSubstrIdx => "ErrOverflowSubstrIdx",
            NegativeRotation => "ErrNegativeRotation",
            OverflowRotation => "ErrOverflowRotation",
            DivideByZero => "ErrDivideByZero",
            NegativeShift => "ErrNegativeShift",
            OverflowShift => "ErrOverflowShift",
            P2SHTreasuryOpCodes => "ErrP2SHTreasuryOpCodes",
            MinimalData => "ErrMinimalData",
            InvalidSigHashType => "ErrInvalidSigHashType",
            SigTooShort => "ErrSigTooShort",
            SigTooLong => "ErrSigTooLong",
            SigInvalidSeqID => "ErrSigInvalidSeqID",
            SigInvalidDataLen => "ErrSigInvalidDataLen",
            SigMissingSTypeID => "ErrSigMissingSTypeID",
            SigMissingSLen => "ErrSigMissingSLen",
            SigInvalidSLen => "ErrSigInvalidSLen",
            SigInvalidRIntID => "ErrSigInvalidRIntID",
            SigZeroRLen => "ErrSigZeroRLen",
            SigNegativeR => "ErrSigNegativeR",
            SigTooMuchRPadding => "ErrSigTooMuchRPadding",
            SigInvalidSIntID => "ErrSigInvalidSIntID",
            SigZeroSLen => "ErrSigZeroSLen",
            SigNegativeS => "ErrSigNegativeS",
            SigTooMuchSPadding => "ErrSigTooMuchSPadding",
            SigHighS => "ErrSigHighS",
            NotPushOnly => "ErrNotPushOnly",
            PubKeyType => "ErrPubKeyType",
            CleanStack => "ErrCleanStack",
            DiscourageUpgradableNOPs => "ErrDiscourageUpgradableNOPs",
            NegativeLockTime => "ErrNegativeLockTime",
            UnsatisfiedLockTime => "ErrUnsatisfiedLockTime",
        }
    }

    /// Whether this kind is one of the non-canonical-DER-signature kinds
    /// (dcrd `IsDERSigError`).
    pub fn is_der_sig_error(self) -> bool {
        use ErrorKind::*;
        matches!(
            self,
            SigTooShort
                | SigTooLong
                | SigInvalidSeqID
                | SigInvalidDataLen
                | SigMissingSTypeID
                | SigMissingSLen
                | SigInvalidSLen
                | SigInvalidRIntID
                | SigZeroRLen
                | SigNegativeR
                | SigTooMuchRPadding
                | SigInvalidSIntID
                | SigZeroSLen
                | SigNegativeS
                | SigTooMuchSPadding
                | SigHighS
        )
    }
}

/// A script-related error (dcrd `Error`): the kind plus a human-readable
/// description. Only the kind carries identity; descriptions are
/// informational.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptError {
    /// The kind of error.
    pub kind: ErrorKind,
    /// Human-readable description.
    pub description: String,
}

impl fmt::Display for ScriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.description)
    }
}

impl core::error::Error for ScriptError {}

/// Construct a [`ScriptError`] (dcrd `scriptError`).
pub(crate) fn script_error(kind: ErrorKind, description: impl Into<String>) -> ScriptError {
    ScriptError {
        kind,
        description: description.into(),
    }
}
