// SPDX-License-Identifier: ISC
//! Go's `time.Duration.String` and a monotonic stopwatch, for the chain
//! log lines that report an elapsed time (dcrd formats a `time.Since`
//! with `%v`, as in `chainio.go:1716`'s "Block index loaded in %v"),
//! the monotonic clock the chain's periodic jobs are timed on, and
//! Go's `time.Time` rendering of a whole-second unix time, which the
//! chain's rule errors and the daemon's block import progress line
//! share.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// Format an elapsed time in nanoseconds like Go's
/// `time.Duration.String`: `0s`, `1ns`, `1.1µs`, `2.2ms`, `3.3s`,
/// `4m5.001s`, `5h6m0s`.
///
/// The same port as the daemon's `dcroxide_node::gostd::go_duration_string`,
/// which this crate sits below.  Only the non-negative half is needed:
/// `time.Since` over a monotonic clock never goes backwards.
pub(crate) fn go_duration_string(nanos: u64) -> String {
    const SECOND: u64 = 1_000_000_000;
    if nanos == 0 {
        return String::from("0s");
    }
    if nanos < SECOND {
        // Below a second Go switches to the smaller units, like 1.2ms.
        let (unit, prec) = if nanos < 1_000 {
            ("ns", 0)
        } else if nanos < 1_000_000 {
            ("µs", 3)
        } else {
            ("ms", 6)
        };
        let (frac, whole) = fmt_frac(nanos, prec);
        return format!("{whole}{frac}{unit}");
    }
    let (frac, secs) = fmt_frac(nanos, 9);
    let (mins, secs) = (secs / 60, secs % 60);
    let (hours, mins) = (mins / 60, mins % 60);
    // Go stops at hours because days can be different lengths.
    if hours > 0 {
        format!("{hours}h{mins}m{secs}{frac}s")
    } else if mins > 0 {
        format!("{mins}m{secs}{frac}s")
    } else {
        format!("{secs}{frac}s")
    }
}

/// Format the fraction of `v / 10**prec` omitting trailing zeros (Go
/// `fmtFrac`); returns the fraction text (with a leading dot when
/// non-empty) and the remaining whole part.
fn fmt_frac(mut v: u64, prec: usize) -> (String, u64) {
    let mut digits: Vec<u8> = Vec::new();
    let mut print = false;
    for _ in 0..prec {
        let digit = v % 10;
        print = print || digit != 0;
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "digit = v % 10 < 10, so b'0' + digit <= b'9'"
        )]
        if print {
            digits.push(b'0' + digit as u8);
        }
        v /= 10;
    }
    let mut frac = String::new();
    if print {
        frac.push('.');
        for d in digits.iter().rev() {
            frac.push(char::from(*d));
        }
    }
    (frac, v)
}

/// Render a unix timestamp the way Go's `%v` prints a whole-second
/// `time.Time` (`2006-01-02 15:04:05 +0000 UTC`).
///
/// dcrd's times come from `time.Unix` and so print in the host's local
/// zone; the port pins UTC so the text does not depend on the host
/// zone database.  The one rendering serves the chain's rule errors
/// (header timestamps and median times) and the daemon's block import
/// progress line, so the two cannot drift apart.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "exact for every i64: |days| <= i64::MAX / 86_400 < 1.1e14, so z and era * 400 (< 3e11) fit, and doe < 146_097, yoe < 400, doy < 366, mp < 12"
)]
pub fn go_time_utc_string(unix: i64) -> String {
    // Civil-from-unix over the proleptic Gregorian calendar, per Howard
    // Hinnant's algorithm (the same math Go's time package performs).
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (hh, mm, ss) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}:{ss:02} +0000 UTC")
}

/// A monotonic stopwatch standing in for dcrd's `time.Now()` and
/// `time.Since` pairs.
///
/// Only a build with `std` has a clock to read.  Without one the elapsed
/// time is unknown, [`Stopwatch::elapsed_nanos`] is `None`, and the
/// caller leaves out the line that would report it.  The daemon and
/// addblock build this crate with `std` (`dcroxide-node`'s dependency
/// on it enables the feature).
pub(crate) struct Stopwatch {
    #[cfg(any(test, feature = "std"))]
    started: std::time::Instant,
}

impl Stopwatch {
    /// Start timing now.
    pub(crate) fn start() -> Stopwatch {
        Stopwatch {
            #[cfg(any(test, feature = "std"))]
            started: std::time::Instant::now(),
        }
    }

    /// The nanoseconds since [`Stopwatch::start`], when there is a clock.
    #[cfg(any(test, feature = "std"))]
    pub(crate) fn elapsed_nanos(&self) -> Option<u64> {
        Some(u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX))
    }

    /// The nanoseconds since [`Stopwatch::start`], when there is a clock.
    #[cfg(not(any(test, feature = "std")))]
    pub(crate) fn elapsed_nanos(&self) -> Option<u64> {
        None
    }
}

/// Nanoseconds on the process's monotonic clock, standing in for the
/// `time.Now()` readings dcrd subtracts to time the chain's periodic
/// jobs.  Go's `Time.Sub` and `time.Since` use the monotonic reading
/// `time.Now` carries, so a step of the wall clock neither stalls nor
/// hastens them.  The origin is the first call: only differences
/// between its values mean anything.
///
/// Only a build with `std` has a clock to read, as for [`Stopwatch`];
/// without one this is `None`.
#[cfg(any(test, feature = "std"))]
pub(crate) fn monotonic_nanos() -> Option<i64> {
    static ORIGIN: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let origin = *ORIGIN.get_or_init(std::time::Instant::now);
    Some(i64::try_from(origin.elapsed().as_nanos()).unwrap_or(i64::MAX))
}

/// Nanoseconds on the process's monotonic clock, when there is one.
#[cfg(not(any(test, feature = "std")))]
pub(crate) fn monotonic_nanos() -> Option<i64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The values mirror Go's own `time.Duration.String` outputs (the
    /// daemon's copy pins the same table).
    #[test]
    fn durations_render_like_go() {
        for (nanos, s) in [
            (0u64, "0s"),
            (1, "1ns"),
            (999, "999ns"),
            (1_100, "1.1µs"),
            (2_200_000, "2.2ms"),
            (123_456_789, "123.456789ms"),
            (500_000_000, "500ms"),
            (1_000_000_000, "1s"),
            (3_300_000_000, "3.3s"),
            (30_000_000_000, "30s"),
            (120_000_000_000, "2m0s"),
            (245_000_000_000, "4m5s"),
            (245_001_000_000, "4m5.001s"),
            (18_000_000_000_000 + 360_000_000_000, "5h6m0s"),
            (86_400_000_000_000, "24h0m0s"),
        ] {
            assert_eq!(go_duration_string(nanos), s, "{nanos}");
        }
    }

    /// Whole-second times render as Go's default `time.Time` format
    /// in UTC.
    #[test]
    fn times_render_like_go_in_utc() {
        assert_eq!(go_time_utc_string(0), "1970-01-01 00:00:00 +0000 UTC");
        assert_eq!(
            go_time_utc_string(1_790_172_001),
            "2026-09-23 14:00:01 +0000 UTC"
        );
        // dcrd's mainnet genesis timestamp.
        assert_eq!(
            go_time_utc_string(1_454_954_400),
            "2016-02-08 18:00:00 +0000 UTC"
        );
        assert_eq!(
            go_time_utc_string(1_231_006_505),
            "2009-01-03 18:15:05 +0000 UTC"
        );
        assert_eq!(
            go_time_utc_string(i64::from(u32::MAX)),
            "2106-02-07 06:28:15 +0000 UTC"
        );
    }

    #[test]
    fn a_std_stopwatch_reads_a_clock() {
        assert!(Stopwatch::start().elapsed_nanos().is_some());
    }

    #[test]
    fn the_std_monotonic_clock_never_goes_back() {
        let first = monotonic_nanos().expect("a clock");
        assert!(first >= 0);
        assert!(monotonic_nanos().expect("a clock") >= first);
    }
}
