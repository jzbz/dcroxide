// SPDX-License-Identifier: ISC
//! Database errors (dcrd database `error.go`).

use core::fmt;

/// The kind of a database error; each variant's [`kind_name`] matches
/// the corresponding dcrd `ErrorKind` string exactly.
///
/// [`kind_name`]: ErrorKind::kind_name
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// A database driver with the specified type is already registered.
    DbTypeRegistered,
    /// There is no driver registered with the specified database type.
    DbUnknownType,
    /// A database does not exist when it was expected to.
    DbDoesNotExist,
    /// A database already exists when it was expected not to.
    DbExists,
    /// The database is not open when it was expected to be.
    DbNotOpen,
    /// The database is already open when it was expected not to be.
    DbAlreadyOpen,
    /// The specified database is invalid.
    Invalid,
    /// A checksum failure or a corrupted database in some other way.
    Corruption,
    /// An operation was attempted against a closed transaction.
    TxClosed,
    /// An operation that requires a writable transaction was attempted
    /// against a read-only transaction.
    TxNotWritable,
    /// An attempt to access a bucket that has not been created yet.
    BucketNotFound,
    /// An attempt to create a bucket that already exists.
    BucketExists,
    /// An attempt to create a bucket with a blank name.
    BucketNameRequired,
    /// An attempt to insert a zero-length key.
    KeyRequired,
    /// An attempt to insert a key larger than the max allowed size.
    KeyTooLarge,
    /// An attempt to insert a value larger than the max allowed size.
    ValueTooLarge,
    /// A value is invalid for a specific requested operation, such as
    /// trying to delete a bucket through a cursor pointed at it.
    IncompatibleValue,
    /// No value was found for the provided key.
    ValueNotFound,
    /// A block with the provided hash does not exist in the database.
    BlockNotFound,
    /// A block with the provided hash already exists in the database.
    BlockExists,
    /// A region exceeds the bounds of the specified block or the region
    /// is otherwise invalid.
    BlockRegionInvalid,
    /// A driver-specific error.
    DriverSpecific,
}

impl ErrorKind {
    /// dcrd's name for this error kind.
    pub fn kind_name(self) -> &'static str {
        match self {
            ErrorKind::DbTypeRegistered => "ErrDbTypeRegistered",
            ErrorKind::DbUnknownType => "ErrDbUnknownType",
            ErrorKind::DbDoesNotExist => "ErrDbDoesNotExist",
            ErrorKind::DbExists => "ErrDbExists",
            ErrorKind::DbNotOpen => "ErrDbNotOpen",
            ErrorKind::DbAlreadyOpen => "ErrDbAlreadyOpen",
            ErrorKind::Invalid => "ErrInvalid",
            ErrorKind::Corruption => "ErrCorruption",
            ErrorKind::TxClosed => "ErrTxClosed",
            ErrorKind::TxNotWritable => "ErrTxNotWritable",
            ErrorKind::BucketNotFound => "ErrBucketNotFound",
            ErrorKind::BucketExists => "ErrBucketExists",
            ErrorKind::BucketNameRequired => "ErrBucketNameRequired",
            ErrorKind::KeyRequired => "ErrKeyRequired",
            ErrorKind::KeyTooLarge => "ErrKeyTooLarge",
            ErrorKind::ValueTooLarge => "ErrValueTooLarge",
            ErrorKind::IncompatibleValue => "ErrIncompatibleValue",
            ErrorKind::ValueNotFound => "ErrValueNotFound",
            ErrorKind::BlockNotFound => "ErrBlockNotFound",
            ErrorKind::BlockExists => "ErrBlockExists",
            ErrorKind::BlockRegionInvalid => "ErrBlockRegionInvalid",
            ErrorKind::DriverSpecific => "ErrDriverSpecific",
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kind_name())
    }
}

/// A database error (dcrd `Error`): a kind plus a human-readable
/// description mirroring dcrd's message text where practical.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    /// The kind of error that occurred.
    pub kind: ErrorKind,
    /// The human-readable description.
    pub description: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.description)
    }
}

impl std::error::Error for Error {}

/// Build an [`Error`] (dcrd `makeDbErr`).
pub(crate) fn db_error(kind: ErrorKind, description: impl Into<String>) -> Error {
    Error {
        kind,
        description: description.into(),
    }
}
