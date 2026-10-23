// SPDX-License-Identifier: ISC
//! The package logger (dcrd internal/mempool `log.go`).
//!
//! dcrd's package-level `log` is `slog.Disabled` until the daemon points
//! it at its `TXMP` subsystem logger (`log.go:91`,
//! `mempool.UseLogger(txmpLog)`).  The crate is `no_std`, so the port
//! carries the logger on the pool instead
//! ([`TxPool::set_logger`](crate::TxPool::set_logger)); a pool without
//! one logs nothing, dcrd's disabled default.  The logger is the mining
//! crate's, so the daemon binds both with one renderer, and so is its
//! contract: a line's level is checked before the line is formatted.

pub use dcroxide_mining::log::{LogLevel, LogLevelGate, LogSink, Logger};
pub(crate) use dcroxide_mining::log::{debugf, pick_noun, tracef};

/// A logger that keeps the lines at or above a level, for the pool's
/// unit tests.
#[cfg(test)]
pub(crate) struct Capture {
    /// The logger to install on a pool.
    pub(crate) logger: Logger,
    lines: std::sync::Arc<std::sync::Mutex<alloc::vec::Vec<(LogLevel, alloc::string::String)>>>,
}

#[cfg(test)]
impl Capture {
    /// A capture keeping the lines at `level` and above.
    pub(crate) fn at(level: LogLevel) -> Capture {
        use std::sync::{Arc, Mutex};
        let lines = Arc::new(Mutex::new(alloc::vec::Vec::new()));
        let sink = Arc::clone(&lines);
        let logger = Logger::new(
            Arc::new(move |at| at >= level),
            Arc::new(move |at, msg: &str| {
                sink.lock()
                    .expect("lines")
                    .push((at, alloc::string::String::from(msg)));
            }),
        );
        Capture { logger, lines }
    }

    /// The lines kept since the last take, emptying the capture.
    pub(crate) fn take(&self) -> alloc::vec::Vec<(LogLevel, alloc::string::String)> {
        core::mem::take(&mut *self.lines.lock().expect("lines"))
    }
}
