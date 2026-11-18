// SPDX-License-Identifier: ISC
//! The daemon's log line rendering: decred/slog@v1.2.0's exact
//! header format — `YYYY-MM-DD hh:mm:ss.sss [LVL] TAG: message` in
//! local time — over standard output and the log file, gated by the
//! per-subsystem levels the configuration's `--debuglevel` grammar
//! parsed ([`crate::logsubsys::LogLevels`]).  Each line carries the
//! subsystem tag its dcrd counterpart logs under (`DCRD` for package
//! main, `RPCS` for the RPC server, `SRVR` for the server, and so
//! on).  Once the daemon has opened its log file
//! ([`init_log_rotator`]), every line goes to the file as well, through
//! the port of `jrick/logrotate` in `logrotate.rs`, as dcrd's
//! `logWriter` writes each line to standard output and then to its
//! rotator (`log.go:32-42`).

use std::io::Write;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use crate::gostd::{filepath_split, go_mkdir_all_owner_only};
use crate::logrotate::Rotator;
use crate::logsubsys::{LogLevel, LogLevels, SUBSYSTEM_IDS};

/// Every level in declaration order, so a level's discriminant indexes
/// it back out of the slots in [`LEVELS`].
const LEVEL_BY_DISCRIMINANT: [LogLevel; 7] = [
    LogLevel::Trace,
    LogLevel::Debug,
    LogLevel::Info,
    LogLevel::Warn,
    LogLevel::Error,
    LogLevel::Critical,
    LogLevel::Off,
];

/// The installed per-subsystem levels, one slot per [`SUBSYSTEM_IDS`]
/// entry in its order, each holding a [`LogLevel`] discriminant; every
/// subsystem reads slog's default `Info` until [`set_levels`] runs.
/// They change while the node runs -- the `debuglevel` RPC sets them --
/// and every log call reads one, so each is an atomic, as each slog
/// logger's level is (`Logger.SetLevel` stores it atomically).
static LEVELS: [AtomicU8; SUBSYSTEM_IDS.len()] =
    [const { AtomicU8::new(LogLevel::Info as u8) }; SUBSYSTEM_IDS.len()];

/// Serializes the writers of [`LEVELS`], so a `debuglevel` call's read,
/// update and store of the slots cannot interleave with another's.
static LEVELS_WRITER: Mutex<()> = Mutex::new(());

/// The level a slot holds.
fn decode_level(slot: &AtomicU8) -> LogLevel {
    LEVEL_BY_DISCRIMINANT
        .get(usize::from(slot.load(Ordering::Relaxed)))
        .copied()
        .unwrap_or(LogLevel::Info)
}

/// Store every subsystem level the map carries into its slot.
fn store_levels(levels: &LogLevels) {
    for (id, slot) in SUBSYSTEM_IDS.iter().zip(&LEVELS) {
        if let Some(level) = levels.0.get(id) {
            slot.store(*level as u8, Ordering::Relaxed);
        }
    }
}

/// Install the per-subsystem levels parsed from `--debuglevel`
/// (dcrd's `parseAndSetDebugLevels` feeding the subsystem loggers).
pub fn set_levels(levels: LogLevels) {
    let _writer = LEVELS_WRITER.lock().unwrap_or_else(PoisonError::into_inner);
    store_levels(&levels);
}

/// The levels every subsystem runs at now.
fn current_levels() -> LogLevels {
    LogLevels(
        SUBSYSTEM_IDS
            .iter()
            .zip(&LEVELS)
            .map(|(id, slot)| (*id, decode_level(slot)))
            .collect(),
    )
}

/// Parse a debug level specification and apply it to the running node
/// (dcrd's `rpcLogManager.ParseAndSetDebugLevels`, which is
/// `parseAndSetDebugLevels`, behind the `debuglevel` RPC).  As in dcrd,
/// the subsystem/level pairs ahead of an invalid one stay applied when
/// the specification fails: dcrd sets each pair's logger as it walks
/// them and returns at the first bad one.
pub fn parse_and_set_debug_levels(debug_level: &str) -> Result<(), String> {
    let _writer = LEVELS_WRITER.lock().unwrap_or_else(PoisonError::into_inner);
    let mut levels = current_levels();
    let result = crate::logsubsys::parse_and_set_debug_levels(&mut levels, debug_level);
    store_levels(&levels);
    result
}

/// The slot holding a subsystem's level; `None` for a tag the daemon
/// keeps no level for, such as the tool binaries' `MAIN`.
fn level_slot(subsys: &str) -> Option<&'static AtomicU8> {
    SUBSYSTEM_IDS
        .iter()
        .zip(&LEVELS)
        .find(|(id, _)| **id == subsys)
        .map(|(_, slot)| slot)
}

/// The configured level for a subsystem; unknown tags — such as the
/// tool binaries' `MAIN` — and an uninstalled configuration read as
/// slog's default `Info`.
pub(crate) fn subsystem_level(subsys: &str) -> LogLevel {
    level_slot(subsys).map_or(LogLevel::Info, decode_level)
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

/// The process's local time zone, read once.
///
/// slog stamps each line with `time.Now()`, which is in Go's `time.Local`:
/// one process-wide zone, read from the environment on first use and
/// kept, whose offset each line works out at its own time
/// ([`crate::zoneinfo`] ports how Go reads it).  So a daemon running
/// across a daylight saving change follows it, as dcrd does, and every
/// line comes from the one zone.
///
/// Reading the zone once matters as much as reading it as Go does.  The
/// chrono `Local` this replaced kept the zone per thread, and a thread
/// whose first lookup could not open `/etc/localtime`, as a daemon short
/// of descriptors can fail to, kept UTC for good: one twenty-hour mainnet
/// log had its shutdown lines four hours ahead of every line before them,
/// which reads as a stall that never happened.  A zone read once for the
/// process cannot change under it, whatever a later read would do.
static LOCAL_ZONE: OnceLock<crate::zoneinfo::LocalZone> = OnceLock::new();

/// The zone every line is rendered in, read on first use.
fn local_zone() -> &'static crate::zoneinfo::LocalZone {
    LOCAL_ZONE.get_or_init(|| crate::zoneinfo::local(crate::timefmt::now().0))
}

/// The timestamp slog writes for an instant in a zone: zero-padded
/// `YYYY-MM-DD hh:mm:ss` with milliseconds, at the zone's offset for
/// that instant.
fn timestamp_in(zone: &crate::zoneinfo::Location, secs: i64, nanos: u32) -> String {
    crate::timefmt::slog_timestamp(secs, nanos, zone.offset(secs))
}

/// The local-time timestamp slog writes for now (slog formats
/// `time.Now()`, which is local time).
fn timestamp() -> String {
    let (secs, nanos) = crate::timefmt::now();
    timestamp_in(&local_zone().location, secs, nanos)
}

/// The startup banner's line on the zone log timestamps are in, so a
/// reader never has to guess it: the local zone and its offset now, or
/// UTC, with the reason when the local zone could not be read, where Go
/// falls back to UTC without a word.
pub fn timestamp_zone_line() -> String {
    zone_line(local_zone(), crate::timefmt::now().0)
}

/// [`timestamp_zone_line`] for a given zone and Unix second.
fn zone_line(zone: &crate::zoneinfo::LocalZone, now: i64) -> String {
    let label = crate::timefmt::offset_label(zone.location.offset(now));
    match (&zone.unread, zone.name.as_str()) {
        (Some(why), _) => {
            format!("Log timestamps are UTC{label}: the local time zone could not be read ({why})")
        }
        (None, "UTC") => format!("Log timestamps are UTC{label}"),
        (None, "Local") => format!("Log timestamps are local time, now UTC{label}"),
        (None, name) => format!("Log timestamps are local time in {name}, now UTC{label}"),
    }
}

/// The exit status a shell reports for a process `SIGPIPE` killed
/// (128 plus the signal number, 13 on every unix).
#[cfg(unix)]
const SIGPIPE_EXIT_STATUS: i32 = 128 + 13;

/// Write to standard output the way dcrd's `logWriter` does (`log.go`),
/// discarding the result of `os.Stdout.Write`: a terminal that hung up
/// (`EIO`) or a full disk behind a redirect (`ENOSPC`) never stops the
/// node, where `println!` panics and `panic = "abort"` then takes the
/// process down, mid-shutdown when the hangup was what started it.
///
/// The one failure Go does not let pass is a broken pipe: its runtime
/// answers `EPIPE` on descriptor 1 or 2 by killing the process with
/// `SIGPIPE` (`os.epipecheck`, `runtime.sigpipe`), which dcrd does not
/// catch.  Rust ignores `SIGPIPE`, and with `unsafe` forbidden there is
/// no restoring its default action to raise it, so the process exits at
/// once with the status a shell reports for that death instead.  Go
/// makes no such check on Windows, where every error is discarded.
pub fn write_stdout(bytes: &[u8]) {
    let result = std::io::stdout().lock().write_all(bytes);
    #[cfg(unix)]
    if let Err(e) = &result
        && e.kind() == std::io::ErrorKind::BrokenPipe
    {
        std::process::exit(SIGPIPE_EXIT_STATUS);
    }
    let _ = result;
}

/// The log file, once the daemon has opened it (dcrd's `logRotator`,
/// `log.go:58-60`).  The daemon alone opens one: addblock logs to
/// standard output only, as dcrd's `cmd/addblock` does.
///
/// Its lock is held across a line's write to standard output and its
/// write to the file, as slog's backend holds its mutex across
/// `logWriter`'s two writes (decred/slog v1.2.0 `log.go:305-307`), so
/// the file has the lines in the order standard output has them.
static LOG_ROTATOR: Mutex<Option<Rotator>> = Mutex::new(None);

/// How many rolls of the log file are kept (dcrd's `rotator.New(logFile,
/// logSize, false, 3)`, `log.go:137`).
const LOG_ROLLS: isize = 3;

/// Open the log file at `log_file`, creating its directory, so that
/// every later line is written to it after standard output, rotated
/// once `log_size_kib` thousand bytes have been written to it (dcrd's
/// `initLogRotator`, `log.go:124-144`).  The directory, everything up
/// to the file name's last separator, is made as `os.MkdirAll(logDir,
/// 0700)` makes it: owner-only where it is created, an existing one
/// left as it is.  The error is the line dcrd writes to standard error
/// before it exits with status 1.
pub fn init_log_rotator(log_file: &str, log_size_kib: i64) -> Result<(), String> {
    let (log_dir, _) = filepath_split(log_file);
    go_mkdir_all_owner_only(log_dir).map_err(|e| format!("failed to create log directory: {e}"))?;
    let rotator = Rotator::new(log_file, log_size_kib, LOG_ROLLS)
        .map_err(|e| format!("failed to create file rotator: {e}"))?;
    *LOG_ROTATOR.lock().unwrap_or_else(PoisonError::into_inner) = Some(rotator);
    Ok(())
}

/// Close the log file, waiting for the rolls being compressed (dcrd's
/// deferred `logRotator.Close()`, `dcrd.go:54-58`).  A line logged
/// after it goes to standard output only, as dcrd's write of one to the
/// closed file fails and is discarded.
pub fn close_log_rotator() {
    let rotator = LOG_ROTATOR
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    if let Some(mut rotator) = rotator {
        rotator.close();
    }
}

/// Emit a log line for the subsystem at the level when its
/// configured level allows it: to standard output, then to the log
/// file if one is open.  The rotator's result is discarded, as dcrd's
/// `logWriter` discards it.
pub fn log(subsys: &str, level: LogLevel, msg: &str) {
    if !enabled(level, subsystem_level(subsys)) {
        return;
    }
    write_line(subsys, level, msg);
}

/// Write a line whose level has passed the subsystem's, as [`log`]
/// writes it.
fn write_line(subsys: &str, level: LogLevel, msg: &str) {
    let mut line = render(&timestamp(), level, subsys, msg);
    line.push('\n');
    let mut rotator = LOG_ROTATOR.lock().unwrap_or_else(PoisonError::into_inner);
    write_stdout(line.as_bytes());
    if let Some(rotator) = rotator.as_mut() {
        let _ = rotator.write(line.as_bytes());
    }
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

/// A package log sink (the `dcroxide_database::LogSink` shape the
/// database and the indexers take) rendered under the subsystem tag
/// and gated by its configured level, as a dcrd subsystem logger
/// handed to a package's `UseLogger` is.
pub fn subsystem_log_sink(subsys: &'static str) -> dcroxide_database::LogSink {
    std::sync::Arc::new(move |level: dcroxide_database::LogLevel, msg: &str| {
        use dcroxide_database::LogLevel as DbLevel;
        let level = match level {
            DbLevel::Trace => LogLevel::Trace,
            DbLevel::Debug => LogLevel::Debug,
            DbLevel::Info => LogLevel::Info,
            DbLevel::Warn => LogLevel::Warn,
            DbLevel::Error => LogLevel::Error,
        };
        log(subsys, level, msg);
    })
}

/// The block database's package log sink, rendered under `BCDB`: the
/// unclean-shutdown repair, the corruption warning and the ROLLBACK
/// lines.  The daemon installs it as dcrd's `log.go:88` does
/// (`database.UseLogger(bcdbLog)`) and addblock as dcrd's
/// `cmd/addblock/addblock.go:76` does, so both print what their dcrd
/// counterparts print.
pub fn bcdb_log_sink() -> dcroxide_database::LogSink {
    subsystem_log_sink("BCDB")
}

/// The indexers' package log sink, rendered under `INDX`: the index
/// catch-up and recovery with their progress lines, and the index
/// drops.  The daemon passes it where dcrd's `log.go:90` installs
/// `indexers.UseLogger(indxLog)`, and addblock where dcrd's
/// `cmd/addblock/addblock.go:78` does.
pub fn indx_log_sink() -> dcroxide_database::LogSink {
    subsystem_log_sink("INDX")
}

/// A package logger for the mining and mempool crates
/// (`dcroxide_mining::log::Logger`) rendered under the subsystem tag, as
/// a dcrd subsystem logger handed to a package's `UseLogger` is.  Its
/// gate reads the subsystem's level slot, found once here, so a line
/// whose level is off costs an atomic load and is never formatted, the
/// check slog's print methods make before they format.
fn package_logger(subsys: &'static str) -> dcroxide_mining::log::Logger {
    use dcroxide_mining::log::LogLevel as PkgLevel;
    fn level(level: PkgLevel) -> LogLevel {
        match level {
            PkgLevel::Trace => LogLevel::Trace,
            PkgLevel::Debug => LogLevel::Debug,
            PkgLevel::Info => LogLevel::Info,
            PkgLevel::Warn => LogLevel::Warn,
            PkgLevel::Error => LogLevel::Error,
        }
    }
    let slot = level_slot(subsys);
    dcroxide_mining::log::Logger::new(
        Arc::new(move |at: PkgLevel| enabled(level(at), slot.map_or(LogLevel::Info, decode_level))),
        Arc::new(move |at: PkgLevel, msg: &str| write_line(subsys, level(at), msg)),
    )
}

/// The mempool's package logger, rendered under `TXMP`.  The daemon's
/// pool logs through it ([`crate::txmempool::new_shared_tx_pool`]), as
/// dcrd's `log.go:91` installs `mempool.UseLogger(txmpLog)`.
pub fn txmp_logger() -> dcroxide_mining::log::Logger {
    static LOGGER: OnceLock<dcroxide_mining::log::Logger> = OnceLock::new();
    LOGGER.get_or_init(|| package_logger("TXMP")).clone()
}

/// The mining packages' logger, rendered under `MINR`: the template
/// generation and the background generator log through it
/// ([`crate::mining::NodeTemplateChain`]), and so does the CPU miner's
/// solve core, as dcrd's `log.go:92` and `:94` install it for both
/// (`mining.UseLogger(minrLog)`, `cpuminer.UseLogger(minrLog)`).
pub fn minr_logger() -> dcroxide_mining::log::Logger {
    static LOGGER: OnceLock<dcroxide_mining::log::Logger> = OnceLock::new();
    LOGGER.get_or_init(|| package_logger("MINR")).clone()
}

/// The RPC server's package log sink, rendered under `RPCS`: the
/// authentication failures, internal errors, dropped replies and handler
/// lines `dcroxide-rpc` logs.  The daemon installs it as dcrd's
/// `log.go:96` does (`rpcserver.UseLogger(rpcsLog)`).
pub fn rpcs_log_sink() -> dcroxide_rpc::log::LogSink {
    std::sync::Arc::new(|level: dcroxide_rpc::log::LogLevel, msg: &str| {
        use dcroxide_rpc::log::LogLevel as RpcLevel;
        let level = match level {
            RpcLevel::Trace => LogLevel::Trace,
            RpcLevel::Debug => LogLevel::Debug,
            RpcLevel::Info => LogLevel::Info,
            RpcLevel::Warn => LogLevel::Warn,
            RpcLevel::Error => LogLevel::Error,
        };
        log("RPCS", level, msg);
    })
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

    /// The process renders every line in one zone, read once into
    /// `LOCAL_ZONE`, so no thread has a zone of its own: the property the
    /// per-thread chrono zone lacked (see `LOCAL_ZONE`).  This pins that
    /// every thread gets the one zone; it does not reproduce a failed
    /// read, which needs the descriptors exhausted.
    #[test]
    fn one_zone_for_the_whole_process() {
        let from_main = std::ptr::from_ref(local_zone()).addr();
        let seen: Vec<usize> = (0..8)
            .map(|_| std::thread::spawn(|| std::ptr::from_ref(local_zone()).addr()))
            .map(|h| h.join().expect("thread"))
            .collect();
        for zone in &seen {
            assert_eq!(*zone, from_main, "a thread read a zone of its own");
        }
        assert!(
            LOCAL_ZONE.get().is_some(),
            "the zone must be read once into LOCAL_ZONE, so no later read can \
             change it"
        );
    }

    /// A zone of New York's rules, whose daylight saving comes from the
    /// footer alone.
    fn new_york() -> crate::zoneinfo::Location {
        crate::zoneinfo::footer_zone(-18_000, "EST5EDT,M3.2.0,M11.1.0")
    }

    /// Each line is stamped at its own instant's offset in the zone it
    /// is given, so a dropped or frozen offset shows on a UTC host too.
    #[test]
    fn lines_take_their_own_instants_offset() {
        let kathmandu = crate::zoneinfo::footer_zone(20_700, "<+0545>-5:45");
        assert_eq!(
            timestamp_in(&kathmandu, 1_496_327_525, 123_456_789),
            "2017-06-01 20:17:05.123"
        );
        // 2026-03-08 07:00 UTC, when New York's clocks go to 03:00, and
        // 2026-11-01 06:00 UTC, when they go back to 01:00.
        let ny = new_york();
        for (secs, want) in [
            (1_772_953_199, "2026-03-08 01:59:59.999"),
            (1_772_953_200, "2026-03-08 03:00:00.999"),
            (1_793_512_799, "2026-11-01 01:59:59.999"),
            (1_793_512_800, "2026-11-01 01:00:00.999"),
            (1_794_916_800, "2026-11-17 07:00:00.999"),
        ] {
            assert_eq!(timestamp_in(&ny, secs, 999_999_999), want, "{secs}");
        }
    }

    /// The banner names the zone and its offset now, or says why the
    /// local zone could not be read.
    #[test]
    fn the_banner_names_the_zone() {
        use crate::zoneinfo::{LocalZone, Location};
        let zone = |name: &str, location, unread: Option<&str>| LocalZone {
            name: name.to_owned(),
            location,
            unread: unread.map(str::to_owned),
        };
        let july = 1_782_907_200;
        for (zone, want) in [
            (
                zone("Local", new_york(), None),
                "Log timestamps are local time, now UTC-04:00",
            ),
            (
                zone("America/New_York", new_york(), None),
                "Log timestamps are local time in America/New_York, now UTC-04:00",
            ),
            (
                zone("UTC", Location::utc(), None),
                "Log timestamps are UTC+00:00",
            ),
            (
                zone("UTC", Location::utc(), Some("unknown time zone EST5")),
                "Log timestamps are UTC+00:00: the local time zone could not be read \
                 (unknown time zone EST5)",
            ),
        ] {
            assert_eq!(zone_line(&zone, july), want);
        }
        assert!(timestamp_zone_line().starts_with("Log timestamps are "));
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

    /// A line's timestamp is the current time at the process zone's
    /// offset, to the minute (a second attempt covers a minute ending between
    /// the two readings).
    #[test]
    fn timestamp_is_now_in_the_local_offset() {
        let agrees = || {
            let (secs, _) = crate::timefmt::now();
            let want = crate::timefmt::slog_timestamp(secs, 0, local_zone().location.offset(secs));
            let got = timestamp();
            (got[..16] == want[..16]).then_some(()).ok_or((got, want))
        };
        if let Err((got, want)) = agrees().or_else(|_| agrees()) {
            panic!("timestamp {got} is not now in the local offset, {want}");
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

    /// Each level's discriminant indexes it back out of the table the
    /// atomic slots are decoded through.
    #[test]
    fn level_slots_round_trip() {
        for (discriminant, level) in LEVEL_BY_DISCRIMINANT.iter().enumerate() {
            assert_eq!(*level as usize, discriminant);
            let slot = AtomicU8::new(*level as u8);
            assert_eq!(decode_level(&slot), *level);
        }
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
