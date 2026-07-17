// SPDX-License-Identifier: ISC
//! The daemon's logging subsystem registry and the `--debuglevel`
//! grammar (dcrd `log.go` / `config.go`): the nineteen subsystem
//! identifiers, slog's level names, and
//! `parseAndSetDebugLevels` with dcrd's exact error texts.

use std::collections::BTreeMap;
use std::fmt;

/// The supported subsystem identifiers, pre-sorted as dcrd's
/// `supportedSubsystems` sorts them for display.
pub const SUBSYSTEM_IDS: [&str; 19] = [
    "ADXR", "AMGR", "BCDB", "CHAN", "CMGR", "DCRD", "DISC", "FEES", "INDX", "MINR", "MIXP", "PEER",
    "RPCS", "SCRP", "SRVR", "STKE", "SYNC", "TRSY", "TXMP",
];

/// A logging level (decred/slog `Level`).  The ordering follows the
/// declaration: a message is emitted when its level is at or above
/// the subsystem's configured level, and `Off` — above every real
/// level — suppresses everything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    /// Trace.
    Trace,
    /// Debug.
    Debug,
    /// Info.
    Info,
    /// Warn.
    Warn,
    /// Error.
    Error,
    /// Critical.
    Critical,
    /// Off.
    Off,
}

impl LogLevel {
    /// Parse a level name like slog's `LevelFromString` (with the
    /// short aliases and case folding).
    pub fn from_str_slog(s: &str) -> Option<LogLevel> {
        match s.to_lowercase().as_str() {
            "trace" | "trc" => Some(LogLevel::Trace),
            "debug" | "dbg" => Some(LogLevel::Debug),
            "info" | "inf" => Some(LogLevel::Info),
            "warn" | "wrn" => Some(LogLevel::Warn),
            "error" | "err" => Some(LogLevel::Error),
            "critical" | "crt" => Some(LogLevel::Critical),
            "off" => Some(LogLevel::Off),
            _ => None,
        }
    }

    /// The three-letter tag slog renders inside the brackets of a log
    /// line's header (slog `Level.String`).
    pub fn three_letter(self) -> &'static str {
        match self {
            LogLevel::Trace => "TRC",
            LogLevel::Debug => "DBG",
            LogLevel::Info => "INF",
            LogLevel::Warn => "WRN",
            LogLevel::Error => "ERR",
            LogLevel::Critical => "CRT",
            LogLevel::Off => "OFF",
        }
    }
}

impl fmt::Display for LogLevel {
    /// The three-letter tag slog's `Level.String` produces.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            LogLevel::Trace => "TRC",
            LogLevel::Debug => "DBG",
            LogLevel::Info => "INF",
            LogLevel::Warn => "WRN",
            LogLevel::Error => "ERR",
            LogLevel::Critical => "CRT",
            LogLevel::Off => "OFF",
        })
    }
}

/// The per-subsystem log levels (the observable state of dcrd's
/// `subsystemLoggers`).
#[derive(Debug, Clone)]
pub struct LogLevels(pub BTreeMap<&'static str, LogLevel>);

impl LogLevels {
    /// All subsystems at the default info level.
    pub fn new() -> LogLevels {
        LogLevels(
            SUBSYSTEM_IDS
                .iter()
                .map(|id| (*id, LogLevel::Info))
                .collect(),
        )
    }

    /// Set every subsystem to the level (dcrd `setLogLevels`).
    fn set_all(&mut self, level: LogLevel) {
        for v in self.0.values_mut() {
            *v = level;
        }
    }
}

impl Default for LogLevels {
    fn default() -> Self {
        LogLevels::new()
    }
}

/// Whether the level name is valid (dcrd `validLogLevel`).
fn valid_log_level(log_level: &str) -> bool {
    LogLevel::from_str_slog(log_level).is_some()
}

/// The sorted subsystem list formatted as Go's `%v` renders a string
/// slice.
pub fn supported_subsystems() -> String {
    format!("[{}]", SUBSYSTEM_IDS.join(" "))
}

/// Parse the debug level specification and set the levels (dcrd
/// `parseAndSetDebugLevels`).
pub fn parse_and_set_debug_levels(levels: &mut LogLevels, debug_level: &str) -> Result<(), String> {
    // When the specified string doesn't have any delimiters, treat
    // it as the log level for all subsystems.
    if !debug_level.contains(',') && !debug_level.contains('=') {
        // Validate debug log level.
        if !valid_log_level(debug_level) {
            return Err(format!(
                "the specified debug level [{debug_level}] is invalid"
            ));
        }

        // Change the logging level for all subsystems.
        levels.set_all(LogLevel::from_str_slog(debug_level).expect("validated"));
        return Ok(());
    }

    // Split the specified string into subsystem/level pairs while
    // detecting issues and update the log levels accordingly.
    for log_level_pair in debug_level.split(',') {
        if !log_level_pair.contains('=') {
            return Err(format!(
                "the specified debug level contains an invalid subsystem/level pair [{log_level_pair}]"
            ));
        }

        // Extract the specified subsystem and log level; extra
        // '='-separated fields are ignored exactly as dcrd's
        // two-element indexing does.
        let fields: Vec<&str> = log_level_pair.split('=').collect();
        let (subsys_id, log_level) = (fields[0], fields[1]);

        // Validate subsystem.
        let Some(key) = SUBSYSTEM_IDS.iter().find(|id| **id == subsys_id) else {
            return Err(format!(
                "the specified subsystem [{subsys_id}] is invalid -- supported subsystems {}",
                supported_subsystems()
            ));
        };

        // Validate log level.
        if !valid_log_level(log_level) {
            return Err(format!(
                "the specified debug level [{log_level}] is invalid"
            ));
        }

        levels
            .0
            .insert(key, LogLevel::from_str_slog(log_level).expect("validated"));
    }

    Ok(())
}
