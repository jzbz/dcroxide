// SPDX-License-Identifier: ISC
//! The daemon's log line rendering: decred/slog@v1.2.0's exact
//! header format — `YYYY-MM-DD hh:mm:ss.sss [LVL] TAG: message` in
//! local time — over a stdout backend, gated by the per-subsystem
//! levels the configuration's `--debuglevel` grammar parsed
//! ([`crate::logsubsys::LogLevels`]).  Each line carries the
//! subsystem tag its dcrd counterpart logs under (`DCRD` for package
//! main, `RPCS` for the RPC server, `SRVR` for the server, and so
//! on).  The rotating file backend (`jrick/logrotate`) remains
//! unwired; stdout is the only sink.

use std::sync::OnceLock;

use crate::logsubsys::{LogLevel, LogLevels};

/// The installed per-subsystem levels; every subsystem defaults to
/// `Info` until [`set_levels`] runs (slog's default level).
static LEVELS: OnceLock<LogLevels> = OnceLock::new();

/// Install the per-subsystem levels parsed from `--debuglevel`
/// (dcrd's `parseAndSetDebugLevels` feeding the subsystem loggers).
/// Only the first call takes effect.
pub fn set_levels(levels: LogLevels) {
    let _ = LEVELS.set(levels);
}

/// The configured level for a subsystem; unknown tags — such as the
/// tool binaries' `MAIN` — and an uninstalled configuration read as
/// slog's default `Info`.
fn subsystem_level(subsys: &str) -> LogLevel {
    LEVELS
        .get()
        .and_then(|levels| levels.0.get(subsys).copied())
        .unwrap_or(LogLevel::Info)
}

/// Whether a message at the level passes the subsystem's configured
/// level (the slog `Logger` level check; a subsystem set to `Off`
/// suppresses everything).
fn enabled(level: LogLevel, configured: LogLevel) -> bool {
    level >= configured
}

/// Render one line in slog's default header format
/// (`formatHeader`): the timestamp, the bracketed three-letter
/// level, the subsystem tag, a colon, and the message.
fn render(timestamp: &str, level: LogLevel, subsys: &str, msg: &str) -> String {
    format!("{timestamp} [{}] {subsys}: {msg}", level.three_letter())
}

/// The local-time timestamp slog writes: zero-padded
/// `YYYY-MM-DD hh:mm:ss` with milliseconds (slog formats
/// `time.Now()`, which is local time).
fn timestamp() -> String {
    chrono::Local::now()
        .format("%Y-%m-%d %H:%M:%S%.3f")
        .to_string()
}

/// Emit a log line for the subsystem at the level when its
/// configured level allows it.
pub fn log(subsys: &str, level: LogLevel, msg: &str) {
    if !enabled(level, subsystem_level(subsys)) {
        return;
    }
    println!("{}", render(&timestamp(), level, subsys, msg));
}

/// A trace-level line.
pub fn trace(subsys: &str, msg: &str) {
    log(subsys, LogLevel::Trace, msg);
}

/// A debug-level line.
pub fn debug(subsys: &str, msg: &str) {
    log(subsys, LogLevel::Debug, msg);
}

/// An info-level line.
pub fn info(subsys: &str, msg: &str) {
    log(subsys, LogLevel::Info, msg);
}

/// A warning-level line.
pub fn warn(subsys: &str, msg: &str) {
    log(subsys, LogLevel::Warn, msg);
}

/// An error-level line.
pub fn error(subsys: &str, msg: &str) {
    log(subsys, LogLevel::Error, msg);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_slog_header_format() {
        assert_eq!(
            render(
                "2017-06-01 14:32:05.123",
                LogLevel::Info,
                "DCRD",
                "Version 2.1.5"
            ),
            "2017-06-01 14:32:05.123 [INF] DCRD: Version 2.1.5"
        );
        assert_eq!(
            render("2017-06-01 14:32:05.001", LogLevel::Error, "INDX", "boom"),
            "2017-06-01 14:32:05.001 [ERR] INDX: boom"
        );
    }

    #[test]
    fn timestamp_matches_slog_widths() {
        // YYYY-MM-DD hh:mm:ss.sss — 23 characters with fixed
        // zero-padded fields, exactly slog's itoa widths.
        let ts = timestamp();
        assert_eq!(ts.len(), 23, "{ts}");
        let bytes = ts.as_bytes();
        for (i, b) in bytes.iter().enumerate() {
            match i {
                4 | 7 => assert_eq!(*b, b'-', "{ts}"),
                10 => assert_eq!(*b, b' ', "{ts}"),
                13 | 16 => assert_eq!(*b, b':', "{ts}"),
                19 => assert_eq!(*b, b'.', "{ts}"),
                _ => assert!(b.is_ascii_digit(), "{ts}"),
            }
        }
    }

    #[test]
    fn levels_gate_like_slog() {
        // A message passes at or above the configured level; Off
        // suppresses everything.
        assert!(enabled(LogLevel::Info, LogLevel::Info));
        assert!(enabled(LogLevel::Error, LogLevel::Info));
        assert!(!enabled(LogLevel::Debug, LogLevel::Info));
        assert!(enabled(LogLevel::Trace, LogLevel::Trace));
        assert!(!enabled(LogLevel::Critical, LogLevel::Off));
    }

    #[test]
    fn three_letter_tags_match_slog() {
        assert_eq!(LogLevel::Trace.three_letter(), "TRC");
        assert_eq!(LogLevel::Debug.three_letter(), "DBG");
        assert_eq!(LogLevel::Info.three_letter(), "INF");
        assert_eq!(LogLevel::Warn.three_letter(), "WRN");
        assert_eq!(LogLevel::Error.three_letter(), "ERR");
        assert_eq!(LogLevel::Critical.three_letter(), "CRT");
    }
}
