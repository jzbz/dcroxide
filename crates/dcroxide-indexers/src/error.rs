// SPDX-License-Identifier: ISC
//! Indexer errors (dcrd indexers `error.go`).

use core::fmt;

/// The kind of an indexer error; each variant's [`kind_name`] matches
/// the corresponding dcrd `ErrorKind` string exactly.
///
/// [`kind_name`]: ErrorKind::kind_name
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// An unsupported address type.
    UnsupportedAddressType,
    /// An error indexing a connected block.
    ConnectBlock,
    /// An error indexing a disconnected block.
    DisconnectBlock,
    /// A spend dependency removal error.
    RemoveSpendDependency,
    /// An invalid indexer notification type.
    InvalidNotificationType,
    /// An operation was cancelled due to a user-requested interrupt.
    InterruptRequested,
    /// An error fetching an index subscription.
    FetchSubscription,
    /// An error fetching an index tip.
    FetchTip,
    /// A missing index notification.
    MissingNotification,
    /// The provided block is not on the main chain.
    BlockNotOnMainChain,
}

impl ErrorKind {
    /// dcrd's name for this error kind.
    pub fn kind_name(self) -> &'static str {
        match self {
            ErrorKind::UnsupportedAddressType => "ErrUnsupportedAddressType",
            ErrorKind::ConnectBlock => "ErrConnectBlock",
            ErrorKind::DisconnectBlock => "ErrDisconnectBlock",
            ErrorKind::RemoveSpendDependency => "ErrRemoveSpendDependency",
            ErrorKind::InvalidNotificationType => "ErrInvalidNotificationType",
            ErrorKind::InterruptRequested => "ErrInterruptRequested",
            ErrorKind::FetchSubscription => "ErrFetchSubscription",
            ErrorKind::FetchTip => "ErrFetchTip",
            ErrorKind::MissingNotification => "ErrMissingNotification",
            ErrorKind::BlockNotOnMainChain => "ErrBlockNotOnMainChain",
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kind_name())
    }
}

/// An indexer error (dcrd `IndexerError`): a kind plus a
/// human-readable description.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexerError {
    /// The kind of error that occurred.
    pub kind: ErrorKind,
    /// The human-readable description.
    pub description: String,
}

impl fmt::Display for IndexerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.description)
    }
}

impl std::error::Error for IndexerError {}

/// Construct an [`IndexerError`] (dcrd `indexerError`).
pub(crate) fn indexer_error(kind: ErrorKind, desc: impl Into<String>) -> IdxError {
    IdxError::Indexer(IndexerError {
        kind,
        description: desc.into(),
    })
}

/// Any error surfaced by the indexers: dcrd's functions return plain
/// `error` values that are either a `database.Error`, an
/// `IndexerError`, or an ad hoc `fmt.Errorf` string; this enum keeps
/// the three shapes distinguishable so error kinds compare exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdxError {
    /// A wrapped database error.
    Db(dcroxide_database::Error),
    /// A wrapped indexer error.
    Indexer(IndexerError),
    /// An ad hoc error message (dcrd `fmt.Errorf`).
    Other(String),
}

impl IdxError {
    /// dcrd's error kind name for the wrapped error, when it has one.
    pub fn kind_name(&self) -> Option<&'static str> {
        match self {
            IdxError::Db(err) => Some(err.kind.kind_name()),
            IdxError::Indexer(err) => Some(err.kind.kind_name()),
            IdxError::Other(_) => None,
        }
    }
}

impl fmt::Display for IdxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdxError::Db(err) => err.fmt(f),
            IdxError::Indexer(err) => err.fmt(f),
            IdxError::Other(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for IdxError {}

impl From<dcroxide_database::Error> for IdxError {
    fn from(err: dcroxide_database::Error) -> IdxError {
        IdxError::Db(err)
    }
}

impl From<IndexerError> for IdxError {
    fn from(err: IndexerError) -> IdxError {
        IdxError::Indexer(err)
    }
}
