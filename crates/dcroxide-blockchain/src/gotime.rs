// SPDX-License-Identifier: ISC
//! Go's `time.Duration.String` and a monotonic stopwatch, for the chain
//! log lines that report an elapsed time (dcrd formats a `time.Since`
//! with `%v`, as in `chainio.go:1716`'s "Block index loaded in %v").

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

    #[test]
    fn a_std_stopwatch_reads_a_clock() {
        assert!(Stopwatch::start().elapsed_nanos().is_some());
    }
}
