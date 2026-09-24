// SPDX-License-Identifier: ISC
//! Errors for the chain-engine components; currently just the
//! deserialization error the UTXO serialization layer surfaces (dcrd
//! internal/blockchain `errDeserialize`).

use alloc::string::String;
use core::fmt;

/// An error in the blockchain components.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// A serialized structure could not be decoded (dcrd
    /// `errDeserialize`); indicates database corruption when it
    /// surfaces from stored data.
    Deserialize(String),
}

impl fmt::Display for Error {
    /// The bare description, as dcrd's `errDeserialize.Error` returns
    /// it (`chainio.go:138-141`), so nested decode errors read the way
    /// dcrd's do.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Deserialize(s) => f.write_str(s),
        }
    }
}

/// Build a deserialization error (dcrd `errDeserialize`).
pub(crate) fn deserialize_error(description: impl Into<String>) -> Error {
    Error::Deserialize(description.into())
}
