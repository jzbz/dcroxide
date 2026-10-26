// SPDX-License-Identifier: ISC
//! The package logger (dcrd internal/mining `log.go`, and the same in its
//! `cpuminer` subpackage).
//!
//! dcrd's package-level `log` is `slog.Disabled` until the daemon points
//! it at its `MINR` subsystem logger, the same one for both packages
//! (`mining.UseLogger(minrLog)` and `cpuminer.UseLogger(minrLog)`,
//! `log.go:92`, `:94`).  The crate is `no_std`, so the port carries the
//! logger rather than holding a package global: the template generation
//! and the background generator's vote handler log through the one
//! [`TemplateChain::logger`](crate::TemplateChain::logger) answers, and
//! the CPU miner's solve core through the one its caller passes.  `None`
//! is dcrd's disabled default: nothing is logged.  The mempool crate's
//! logger is this type too, so the daemon binds both with one renderer.
//!
//! A line's level is checked before the line is formatted, as slog's
//! `Tracef` and `Debugf` compare the logger's level before formatting
//! (decred/slog v1.2.0 `log.go:375-402`), so a line whose level is off
//! costs the check and no formatting.  The arguments are evaluated at the
//! call either way, as Go evaluates them; where computing one costs
//! something dcrd's call does not pay, the call site asks [`enabled`]
//! first.

use alloc::string::String;
use alloc::sync::Arc;
use core::fmt;

/// The level of a line, least severe first (the `slog` levels dcrd's
/// mining and mempool packages log at).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
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

/// Whether a line at the level would be written now: the comparison
/// with the logger's level each slog print method makes first.  It is
/// asked on every log call, so it must be cheap and must not block.
pub type LogLevelGate = Arc<dyn Fn(LogLevel) -> bool + Send + Sync>;

/// Where a line the gate passed goes, formatted: the daemon's subsystem
/// logger in the node, a capture in tests.  It is called on whichever
/// thread logs, sometimes with the mempool or chain lock held, so it
/// must not block on either.
pub type LogSink = Arc<dyn Fn(LogLevel, &str) + Send + Sync>;

/// A package logger: the gate a line must pass and the sink it then goes
/// to (the `slog.Logger` dcrd hands the package's `UseLogger`).
#[derive(Clone)]
pub struct Logger {
    gate: LogLevelGate,
    sink: LogSink,
}

impl Logger {
    /// A logger over the gate and the sink.
    pub fn new(gate: LogLevelGate, sink: LogSink) -> Logger {
        Logger { gate, sink }
    }

    /// Whether a line at the level would be written now.
    pub fn enabled(&self, level: LogLevel) -> bool {
        (self.gate)(level)
    }

    /// Format the line and hand it to the sink when its level is
    /// enabled (slog's `Tracef`, `Debugf`, `Warnf` and the rest).
    pub fn log(&self, level: LogLevel, args: fmt::Arguments<'_>) {
        if self.enabled(level) {
            (self.sink)(level, &alloc::fmt::format(args));
        }
    }
}

impl fmt::Debug for Logger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Logger")
    }
}

/// Whether the logger, if there is one, would write a line at the level
/// now; `false` without one, as `slog.Disabled` writes nothing.
pub fn enabled(logger: Option<&Logger>, level: LogLevel) -> bool {
    logger.is_some_and(|logger| logger.enabled(level))
}

/// A line at the level through the logger, if there is one.
pub fn logf(logger: Option<&Logger>, level: LogLevel, args: fmt::Arguments<'_>) {
    if let Some(logger) = logger {
        logger.log(level, args);
    }
}

/// A trace-level line (`log.Tracef`).
pub fn tracef(logger: Option<&Logger>, args: fmt::Arguments<'_>) {
    logf(logger, LogLevel::Trace, args);
}

/// A debug-level line (`log.Debugf`, and `log.Debug` of one operand).
pub fn debugf(logger: Option<&Logger>, args: fmt::Arguments<'_>) {
    logf(logger, LogLevel::Debug, args);
}

/// A warning-level line (`log.Warnf`).
pub fn warnf(logger: Option<&Logger>, args: fmt::Arguments<'_>) {
    logf(logger, LogLevel::Warn, args);
}

/// An error-level line (`log.Errorf`).
pub fn errorf(logger: Option<&Logger>, args: fmt::Arguments<'_>) {
    logf(logger, LogLevel::Error, args);
}

/// The singular or plural form of a noun depending on the count (dcrd's
/// `pickNoun` in both packages' `log.go`).
pub fn pick_noun<'a>(n: u64, singular: &'a str, plural: &'a str) -> &'a str {
    if n == 1 { singular } else { plural }
}

/// A `float64` as Go's `%v` verb prints it: the shortest decimal that
/// reads back as the same value, in `%f` form unless the decimal
/// exponent is below -4 or at least 6, where it is `%e` form with a
/// signed exponent of at least two digits (`fmt` hands `%v` to
/// `strconv.AppendFloat(f, 'g', -1, 64)`, whose shortest form decides
/// with a precision of 6, `strconv/ftoa.go`).
///
/// Rust's `{:e}` writes the same shortest digits, so they are taken from
/// it and laid out as Go lays them out.  NaN and the infinities print as
/// Go prints them.
pub fn go_float_v(v: f64) -> String {
    if v.is_nan() {
        return String::from("NaN");
    }
    if v.is_infinite() {
        return String::from(if v > 0.0 { "+Inf" } else { "-Inf" });
    }
    let sci = alloc::format!("{v:e}");
    let (mantissa, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let (neg, mantissa) = match mantissa.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, mantissa),
    };
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    if !(-4..6).contains(&exp) {
        // %e: the first digit, the rest after a point, and the exponent.
        let (first, rest) = digits.split_at(1);
        out.push_str(first);
        if !rest.is_empty() {
            out.push('.');
            out.push_str(rest);
        }
        out.push('e');
        out.push(if exp < 0 { '-' } else { '+' });
        let magnitude = exp.unsigned_abs();
        if magnitude < 10 {
            out.push('0');
        }
        out.push_str(&alloc::format!("{magnitude}"));
        return out;
    }
    // %f: as many digits as the shortest form has, the point placed by
    // the exponent.
    let point = exp.saturating_add(1);
    if point <= 0 {
        out.push_str("0.");
        for _ in 0..point.unsigned_abs() {
            out.push('0');
        }
        out.push_str(&digits);
        return out;
    }
    let point = point.unsigned_abs() as usize;
    if digits.len() <= point {
        out.push_str(&digits);
        for _ in digits.len()..point {
            out.push('0');
        }
    } else {
        let (int, frac) = digits.split_at(point);
        out.push_str(int);
        out.push('.');
        out.push_str(frac);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    /// Go's `fmt.Sprintf("%v", f)` for each value, as go1.27 prints it and
    /// go1.26.2, the reference Go, prints it alike:
    /// ticket prices of every size the template line carries, the
    /// exponent forms on both sides, and the values Go spells by name.
    #[test]
    fn floats_print_as_go_prints_them_with_v() {
        let cases: [(f64, &str); 19] = [
            (0.0002, "0.0002"),
            (85.40653569, "85.40653569"),
            (7588.66011909, "7588.66011909"),
            (2.0, "2"),
            (0.0, "0"),
            (-0.0, "-0"),
            (100000.0, "100000"),
            (999999.0, "999999"),
            (1_000_000.0, "1e+06"),
            (1_234_567.0, "1.234567e+06"),
            (2.1e15, "2.1e+15"),
            (1e100, "1e+100"),
            (0.0001, "0.0001"),
            (0.00002, "2e-05"),
            (0.000012345, "1.2345e-05"),
            (-7.5, "-7.5"),
            (f64::NAN, "NaN"),
            (f64::INFINITY, "+Inf"),
            (f64::NEG_INFINITY, "-Inf"),
        ];
        for (v, want) in cases {
            assert_eq!(go_float_v(v), want, "{v:?}");
        }
    }

    #[test]
    fn nouns_follow_dcrds_pick_noun() {
        assert_eq!(pick_noun(1, "orphan", "orphans"), "orphan");
        assert_eq!(pick_noun(0, "orphan", "orphans"), "orphans");
        assert_eq!(pick_noun(2, "orphan", "orphans"), "orphans");
    }

    /// A line below the gate's level is neither formatted nor handed to
    /// the sink; one at or above it is, with its level.
    #[test]
    fn the_gate_is_asked_before_the_line_is_formatted() {
        struct Panics;
        impl fmt::Display for Panics {
            fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
                panic!("a line whose level is off was formatted");
            }
        }

        let lines = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&lines);
        let logger = Logger::new(
            Arc::new(|level| level >= LogLevel::Debug),
            Arc::new(move |level, msg: &str| {
                sink.lock().expect("lines").push((level, String::from(msg)));
            }),
        );
        tracef(Some(&logger), format_args!("{}", Panics));
        debugf(Some(&logger), format_args!("shown {}", 1));
        warnf(Some(&logger), format_args!("shown {}", 2));
        tracef(None, format_args!("{}", Panics));
        assert!(!enabled(None, LogLevel::Error));
        assert!(enabled(Some(&logger), LogLevel::Debug));
        assert!(!enabled(Some(&logger), LogLevel::Trace));
        assert_eq!(
            *lines.lock().expect("lines"),
            [
                (LogLevel::Debug, String::from("shown 1")),
                (LogLevel::Warn, String::from("shown 2")),
            ]
        );
    }
}
