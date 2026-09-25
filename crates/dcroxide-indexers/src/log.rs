// SPDX-License-Identifier: ISC
//! The package logger (dcrd indexers `log.go`).
//!
//! dcrd's package-level `log` is `slog.Disabled` until the daemon
//! points it at its `INDX` subsystem logger with `UseLogger`
//! (`log.go:90`; addblock does the same, `cmd/addblock/addblock.go:78`).
//! The port takes the sink as an argument instead of holding a package
//! global: [`IndexSubscriber::new`](crate::IndexSubscriber::new) keeps
//! the one its indexes log through, and each public drop function takes
//! one.  The sink is the database crate's, so a caller binds both with
//! the same renderer.  `None` is dcrd's disabled default: nothing is
//! logged.

pub use dcroxide_database::{LogLevel, LogSink};

/// Hand a line to the sink, if there is one.
pub(crate) fn log_line(sink: Option<&LogSink>, level: LogLevel, msg: &str) {
    if let Some(sink) = sink {
        sink(level, msg);
    }
}
