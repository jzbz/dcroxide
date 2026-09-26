// SPDX-License-Identifier: ISC
//! The database corruption a persistence failure carries, read back
//! from the rule error `persist_rule_error` makes of it.
//!
//! The chain hands a storage failure over as a `RuleError`, which keeps
//! the database error's kind only in its rendered text.  The daemon's
//! sync adapter reads it back with `is_persisted_db_corruption` to emit
//! dcrd's corruption-only `Critical failure` line (netsync
//! `manager.go:1265-1269`, `:1646-1648`), so a change to the rendering
//! that the reader does not follow would silently drop that line.

use dcroxide_blockchain::chaindb::ChainDbError;
use dcroxide_blockchain::process::{is_persisted_db_corruption, persist_rule_error};
use dcroxide_blockchain::{RuleError, RuleErrorKind};
use dcroxide_database::{Error, ErrorKind};

fn persisted(kind: ErrorKind) -> RuleError {
    persist_rule_error(ChainDbError::Db(Error {
        kind,
        description: "checksum mismatch".to_string(),
    }))
}

/// Only a database `ErrCorruption` counts: not another database
/// failure, not the chain's own consistency failures, and not a rule
/// error that merely shares the kind `persist_rule_error` uses.
#[test]
fn only_a_persisted_database_corruption_is_recognised() {
    assert!(is_persisted_db_corruption(&persisted(
        ErrorKind::Corruption
    )));

    assert!(!is_persisted_db_corruption(&persisted(ErrorKind::Fatal)));
    assert!(!is_persisted_db_corruption(&persisted(
        ErrorKind::DriverSpecific
    )));
    assert!(!is_persisted_db_corruption(&persist_rule_error(
        ChainDbError::Corrupt("missing utxo set bucket".to_string())
    )));
    assert!(!is_persisted_db_corruption(&RuleError {
        kind: RuleErrorKind::UnknownBlock,
        description: "unknown block".to_string(),
    }));
}

/// Every other persistence failure renders as its own text, as dcrd's
/// plain error does under `%v` (`database/error.go:150-152`), rather
/// than as a debug dump of the port's error types (review finding
/// RG03#2).  Only the corruption keeps the form its reader needs.
#[test]
fn other_persistence_failures_render_as_their_own_text() {
    for kind in [ErrorKind::Fatal, ErrorKind::DriverSpecific] {
        let err = persisted(kind);
        assert_eq!(err.kind, RuleErrorKind::UnknownBlock);
        assert_eq!(err.description, "checksum mismatch");
    }
    assert_eq!(
        persist_rule_error(ChainDbError::Corrupt("missing utxo set bucket".to_string()))
            .description,
        "missing utxo set bucket"
    );
    assert_eq!(
        persisted(ErrorKind::Corruption).description,
        "chain database failure: Db(Error { kind: Corruption, description: \"checksum mismatch\" })"
    );
}
