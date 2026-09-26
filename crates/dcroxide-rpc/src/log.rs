// SPDX-License-Identifier: ISC
//! The RPC server's package logger (dcrd `internal/rpcserver/log.go`).
//!
//! dcrd's package holds a `log` variable that starts as `slog.Disabled`
//! and that the daemon points at its `RPCS` subsystem logger with
//! `rpcserver.UseLogger(rpcsLog)` (the daemon's `log.go:96`).  This is
//! the same shape: a process-wide sink, silent until [`use_logger`]
//! installs one, so the handlers and the request surface log where
//! dcrd's do without every call site carrying a handle.  The daemon
//! renders the lines and gates them by the subsystem's configured level;
//! nothing here filters.

use std::sync::{Arc, PoisonError, RwLock};

/// The level of a line handed to the [`LogSink`] (the `slog` levels
/// dcrd's RPC server logs at).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogLevel {
    /// `slog.LevelTrace`.
    Trace,
    /// `slog.LevelDebug`.
    Debug,
    /// `slog.LevelInfo`.
    Info,
    /// `slog.LevelWarn`.
    Warn,
    /// `slog.LevelError`.
    Error,
}

/// Where the RPC server's log lines go: the daemon's `RPCS` subsystem
/// logger in the node, a capture in tests.
pub type LogSink = Arc<dyn Fn(LogLevel, &str) + Send + Sync>;

/// The installed sink; `None` is dcrd's `slog.Disabled`.
static LOGGER: RwLock<Option<LogSink>> = RwLock::new(None);

/// Install the package logger (dcrd `rpcserver.UseLogger`).  A later
/// call replaces the earlier sink, as reassigning dcrd's `log` does.
pub fn use_logger(sink: LogSink) {
    *LOGGER.write().unwrap_or_else(PoisonError::into_inner) = Some(sink);
}

/// Hand one line to the installed sink, if any.
///
/// The sink is cloned out of the lock before it runs, so a sink that
/// logs, or that takes a while, holds up nothing else.
pub(crate) fn log(level: LogLevel, msg: &str) {
    let sink = LOGGER
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    if let Some(sink) = sink {
        sink(level, msg);
    }
}

/// A debug-level line (`log.Debugf`).
pub(crate) fn debug(msg: &str) {
    log(LogLevel::Debug, msg);
}

/// An info-level line (`log.Infof`).
pub(crate) fn info(msg: &str) {
    log(LogLevel::Info, msg);
}

/// A warning-level line (`log.Warnf`).
pub(crate) fn warn(msg: &str) {
    log(LogLevel::Warn, msg);
}

/// An error-level line (`log.Error`, `log.Errorf`).
pub(crate) fn error(msg: &str) {
    log(LogLevel::Error, msg);
}
