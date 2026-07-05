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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Deserialize(s) => write!(f, "deserialize error: {s}"),
        }
    }
}

/// Build a deserialization error (dcrd `errDeserialize`).
pub(crate) fn deserialize_error(description: impl Into<String>) -> Error {
    Error::Deserialize(description.into())
}
