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

/// The process's local UTC offset, resolved once.
///
/// Go's `time.Local` is a single process-wide `*Location` initialised
/// lazily and then reused, so every line dcrd writes is in the same zone.
/// `chrono::Local` is not equivalent: it caches the zone PER THREAD, and
/// a thread whose first lookup cannot open `/etc/localtime` — a daemon
/// holding many peer sockets and RPC handler threads can transiently run
/// out of descriptors — silently caches UTC for the rest of its life.
/// The result is one log file carrying two different zones with no
/// indication, which is exactly what happened on a twenty-hour mainnet
/// run: every line in local time until the shutdown lines, emitted from a
/// thread whose first timestamp call landed during descriptor pressure,
/// appeared four hours in the future.  That is worse than either zone
/// alone, because it silently invents gaps — it had me chasing a
/// four-hour stall that never occurred.
///
/// Resolving once, process-wide, reproduces Go's single-zone property and
/// cannot be poisoned by a later failed lookup.
static LOCAL_OFFSET: OnceLock<chrono::FixedOffset> = OnceLock::new();

/// The offset every line is rendered in, resolved on first use.
///
/// Deliberate divergence: Go's `time.Local` holds the zone's transition
/// rules, so dcrd follows a daylight-saving change while running; this
/// holds the offset that was in effect when logging started, so a process
/// running across a DST boundary keeps the earlier offset until it is
/// restarted.  One zone for the life of the process is the property worth
/// having — a reader can trust that two lines an hour apart really are an
/// hour apart — and the alternative on offer was two zones in one file.
fn local_offset() -> chrono::FixedOffset {
    *LOCAL_OFFSET.get_or_init(|| *chrono::Local::now().offset())
}

/// The local-time timestamp slog writes: zero-padded
/// `YYYY-MM-DD hh:mm:ss` with milliseconds (slog formats
/// `time.Now()`, which is local time).
fn timestamp() -> String {
    chrono::Utc::now()
        .with_timezone(&local_offset())
        .format("%Y-%m-%d %H:%M:%S%.3f")
        .to_string()
}

/// The offset log timestamps are rendered in, as `+hh:mm`, for the
/// startup banner: a log whose zone is fixed for the process should say
/// which zone, so a reader never has to guess.
pub fn local_offset_label() -> String {
    local_offset().to_string()
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

    /// The process must render every line in one zone, and there must be
    /// exactly one source of that zone.
    ///
    /// `chrono::Local` caches the timezone PER THREAD, so a thread whose
    /// first lookup cannot open `/etc/localtime` — a daemon holding many
    /// peer sockets and RPC handler threads can transiently exhaust its
    /// descriptors — silently caches UTC for the rest of its life. On a
    /// twenty-hour mainnet run that put the shutdown lines four hours in
    /// the future while every earlier line was local, and it had me chasing
    /// a stall that never happened.
    ///
    /// Be clear about what this test is: it pins that all threads agree and
    /// that the offset comes from the single process-wide `LOCAL_OFFSET`.
    /// It does NOT reproduce the failure. Reproducing it needs the
    /// timezone read to fail, which needs a descriptor limit low enough to
    /// exhaust — under this machine's 524288 the starvation loop is far too
    /// expensive to run in a unit test. It was reproduced out of tree with
    /// `ulimit -n 64`: a thread's first `Local::now()` under exhaustion
    /// returns UTC and stays UTC, while its parent keeps local time.
    ///
    /// What actually prevents a recurrence is structural: there is one
    /// offset for the process, resolved once, so two threads cannot
    /// disagree regardless of what any later lookup does.
    #[test]
    fn one_zone_for_the_whole_process() {
        let from_main = local_offset();
        let stamp_main = timestamp();

        let seen: Vec<chrono::FixedOffset> = (0..8)
            .map(|_| std::thread::spawn(local_offset))
            .map(|h| h.join().expect("thread"))
            .collect();
        for off in &seen {
            assert_eq!(
                *off, from_main,
                "a thread resolved a different offset ({off}) than the main \
                 thread ({from_main}); the process must have exactly one"
            );
        }

        // And the rendered zone field agrees, which is what a reader sees.
        let stamps: Vec<String> = (0..8)
            .map(|_| std::thread::spawn(timestamp))
            .map(|h| h.join().expect("thread"))
            .collect();
        for s in &stamps {
            assert_eq!(
                &s[..13],
                &stamp_main[..13],
                "threads rendered different hours: {s} against {stamp_main}"
            );
        }

        // The offset really is memoised, not re-derived per call.
        assert!(
            LOCAL_OFFSET.get().is_some(),
            "the offset must be resolved once into LOCAL_OFFSET, so no later \
             failed lookup can change it"
        );
        assert!(
            local_offset_label().starts_with('+') || local_offset_label().starts_with('-'),
            "the banner label must carry a signed offset, got {}",
            local_offset_label()
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
