// SPDX-License-Identifier: ISC
//! Rule errors for the standalone consensus functions (dcrd
//! blockchain/standalone `error.go`).

use alloc::string::String;
use core::fmt;

/// The kind of a standalone rule error; each variant's [`kind_name`]
/// matches the corresponding dcrd `ErrorKind` string exactly.
///
/// [`kind_name`]: ErrorKind::kind_name
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// Specified bits do not align with the expected value, either
    /// because it doesn't match the calculated value based on difficulty
    /// rules or it is out of the valid range.
    UnexpectedDifficulty,
    /// The block does not hash to a value which is lower than the
    /// required target difficulty.
    HighHash,
    /// An invalid expiry was provided when calculating the treasury
    /// spend voting window.
    InvalidTSpendExpiry,
    /// A transaction does not have any inputs.
    NoTxInputs,
    /// A transaction does not have any outputs.
    NoTxOutputs,
    /// A transaction exceeds the maximum allowed size when serialized.
    TxTooBig,
    /// An output value for a transaction is invalid in some way, such as
    /// being out of range.
    BadTxOutValue,
    /// A transaction references the same input more than once.
    DuplicateTxInputs,
}

impl ErrorKind {
    /// dcrd's name for this error kind.
    pub fn kind_name(self) -> &'static str {
        match self {
            ErrorKind::UnexpectedDifficulty => "ErrUnexpectedDifficulty",
            ErrorKind::HighHash => "ErrHighHash",
            ErrorKind::InvalidTSpendExpiry => "ErrInvalidTSpendExpiry",
            ErrorKind::NoTxInputs => "ErrNoTxInputs",
            ErrorKind::NoTxOutputs => "ErrNoTxOutputs",
            ErrorKind::TxTooBig => "ErrTxTooBig",
            ErrorKind::BadTxOutValue => "ErrBadTxOutValue",
            ErrorKind::DuplicateTxInputs => "ErrDuplicateTxInputs",
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kind_name())
    }
}

/// A rule violation (dcrd `RuleError`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleError {
    /// The kind of rule that was violated.
    pub kind: ErrorKind,
    /// The human-readable description, mirroring dcrd's message.
    pub description: String,
}

impl fmt::Display for RuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.description)
    }
}

/// Build a [`RuleError`] (dcrd `ruleError`).
pub(crate) fn rule_error(kind: ErrorKind, description: impl Into<String>) -> RuleError {
    RuleError {
        kind,
        description: description.into(),
    }
}
