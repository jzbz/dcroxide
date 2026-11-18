// SPDX-License-Identifier: ISC
//! The calendar text the node writes for a moment in time: the
//! timestamp heading each log line, laid out as decred/slog@v1.2.0
//! lays it out, the `Date` header of the RPC server's responses, in
//! the one layout Go's `net/http` writes, and the offset the startup
//! banner names.  The calendar fields come from
//! [`dcroxide_certgen::civil_from_unix`], the proleptic Gregorian
//! conversion the certificate generator dates certificates with.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dcroxide_certgen::civil_from_unix;

/// The current time as whole seconds since the Unix epoch, rounded
/// down, and the nanoseconds past them, as Go's `time.Now()` holds it.
pub(crate) fn now() -> (i64, u32) {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(after) => (
            i64::try_from(after.as_secs()).unwrap_or(i64::MAX),
            after.subsec_nanos(),
        ),
        Err(before) => before_epoch(before.duration()),
    }
}

/// A clock reading `before` ahead of the epoch, as [`now`] gives it:
/// negative whole seconds rounded down, and the nanoseconds still
/// counted forward from them.
fn before_epoch(before: Duration) -> (i64, u32) {
    let secs = i64::try_from(before.as_secs()).map_or(i64::MIN, |s| 0i64.saturating_sub(s));
    match before.subsec_nanos() {
        0 => (secs, 0),
        nanos => (
            secs.saturating_sub(1),
            1_000_000_000u32.saturating_sub(nanos),
        ),
    }
}

/// Append a year as Go's `appendInt(b, year, 4)` writes the `2006` of a
/// layout (go1.27.3 `time/format.go:418-465`, `:712-713`): at least
/// four digits, zero-padded, a minus sign ahead of the padding.  slog's
/// `itoa(buf, year, 4)` writes the same for every year from 0 on.
fn push_year(out: &mut String, year: i64) {
    if year < 0 {
        out.push('-');
    }
    out.push_str(&format!("{:04}", year.unsigned_abs()));
}

/// The log line timestamp for an instant `offset` seconds east of UTC:
/// `YYYY-MM-DD hh:mm:ss.sss`, the milliseconds truncated, as slog's
/// `formatHeader` writes `time.Now()` (decred/slog@v1.2.0
/// `log.go:217-237`, with `itoa` at `:197-211`).
pub(crate) fn slog_timestamp(secs: i64, nanos: u32, offset: i32) -> String {
    let (year, month, day, hour, min, sec) =
        civil_from_unix(secs.saturating_add(i64::from(offset)));
    let millis = nanos / 1_000_000;
    let mut out = String::with_capacity(23);
    push_year(&mut out, year);
    out.push_str(&format!(
        "-{month:02}-{day:02} {hour:02}:{min:02}:{sec:02}.{millis:03}"
    ));
    out
}

/// Weekday names indexed by days since 1970-01-01, a Thursday, modulo
/// seven.
const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];

/// Month names indexed from January.
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// The `Date` header value for a time in Unix seconds, in `net/http`'s
/// `TimeFormat`, `Mon, 02 Jan 2006 15:04:05 GMT` (go1.27.3
/// `net/http/server.go:1027`), which its server writes with
/// `time.Now().UTC().AppendFormat(…, TimeFormat)` (`:1504`).
pub(crate) fn http_date(secs: i64) -> String {
    let (year, month, day, hour, min, sec) = civil_from_unix(secs);
    let weekday = usize::try_from(secs.div_euclid(86_400).rem_euclid(7))
        .ok()
        .and_then(|i| WEEKDAYS.get(i))
        .copied()
        .unwrap_or("???");
    let month = usize::try_from(month)
        .ok()
        .and_then(|m| m.checked_sub(1))
        .and_then(|i| MONTHS.get(i))
        .copied()
        .unwrap_or("???");
    let mut out = format!("{weekday}, {day:02} {month} ");
    push_year(&mut out, year);
    out.push_str(&format!(" {hour:02}:{min:02}:{sec:02} GMT"));
    out
}

/// An offset east of UTC as `+hh:mm`, or `+hh:mm:ss` when it has
/// seconds, the label the startup banner has always printed after
/// `UTC`.
pub(crate) fn offset_label(offset: i32) -> String {
    let sign = if offset < 0 { '-' } else { '+' };
    let abs = offset.unsigned_abs();
    let (hours, minutes, seconds) = (abs / 3600, abs / 60 % 60, abs % 60);
    if seconds == 0 {
        format!("{sign}{hours:02}:{minutes:02}")
    } else {
        format!("{sign}{hours:02}:{minutes:02}:{seconds:02}")
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    /// Instants whose calendar text is known: the epoch and the second
    /// before it, RFC 9110's example date, leap days in and out of
    /// century years, and the last second of year 9999.
    #[rustfmt::skip]
    const KNOWN: [(i64, &str, &str); 11] = [
        (0, "1970-01-01 00:00:00", "Thu, 01 Jan 1970 00:00:00 GMT"),
        (-1, "1969-12-31 23:59:59", "Wed, 31 Dec 1969 23:59:59 GMT"),
        (784_111_777, "1994-11-06 08:49:37", "Sun, 06 Nov 1994 08:49:37 GMT"),
        (1_496_327_525, "2017-06-01 14:32:05", "Thu, 01 Jun 2017 14:32:05 GMT"),
        (951_782_400, "2000-02-29 00:00:00", "Tue, 29 Feb 2000 00:00:00 GMT"),
        (1_709_208_000, "2024-02-29 12:00:00", "Thu, 29 Feb 2024 12:00:00 GMT"),
        (4_102_444_800, "2100-01-01 00:00:00", "Fri, 01 Jan 2100 00:00:00 GMT"),
        (4_107_542_399, "2100-02-28 23:59:59", "Sun, 28 Feb 2100 23:59:59 GMT"),
        (4_107_542_400, "2100-03-01 00:00:00", "Mon, 01 Mar 2100 00:00:00 GMT"),
        (-62_135_596_800, "0001-01-01 00:00:00", "Mon, 01 Jan 0001 00:00:00 GMT"),
        (253_402_300_799, "9999-12-31 23:59:59", "Fri, 31 Dec 9999 23:59:59 GMT"),
    ];

    #[test]
    fn known_instants_format_as_go_does() {
        for (secs, local, http) in KNOWN {
            assert_eq!(slog_timestamp(secs, 0, 0), format!("{local}.000"), "{secs}");
            assert_eq!(http_date(secs), http, "{secs}");
        }
    }

    /// slog divides the nanoseconds down to milliseconds, so .999999999
    /// is still .999, never a rounded-up next second.
    #[test]
    fn milliseconds_are_truncated() {
        assert_eq!(
            slog_timestamp(1_496_327_525, 123_999_999, 0),
            "2017-06-01 14:32:05.123"
        );
        assert_eq!(
            slog_timestamp(-1, 999_999_999, 0),
            "1969-12-31 23:59:59.999"
        );
        assert_eq!(slog_timestamp(0, 999_999, 0), "1970-01-01 00:00:00.000");
        assert_eq!(slog_timestamp(0, 1_000_000, 0), "1970-01-01 00:00:00.001");
    }

    /// The offset moves the wall clock and, across midnight, the date;
    /// the HTTP date is UTC whatever the zone.
    #[test]
    fn offsets_move_the_wall_clock() {
        assert_eq!(slog_timestamp(0, 0, -18_000), "1969-12-31 19:00:00.000");
        assert_eq!(slog_timestamp(0, 0, 20_700), "1970-01-01 05:45:00.000");
        assert_eq!(slog_timestamp(951_782_399, 0, 1), "2000-02-29 00:00:00.000");
        assert_eq!(
            slog_timestamp(951_868_799, 0, 50_400),
            "2000-03-01 13:59:59.000"
        );
        assert_eq!(slog_timestamp(0, 0, -34), "1969-12-31 23:59:26.000");
    }

    #[test]
    fn years_are_four_digits_at_least() {
        // 10000-01-01 and 0000-01-01 (1 BC), and the year before that,
        // which Go writes with its minus sign ahead of the padding.
        assert_eq!(http_date(253_402_300_800), "Sat, 01 Jan 10000 00:00:00 GMT");
        assert_eq!(
            slog_timestamp(253_402_300_800, 0, 0),
            "10000-01-01 00:00:00.000"
        );
        assert_eq!(http_date(-62_167_219_200), "Sat, 01 Jan 0000 00:00:00 GMT");
        assert_eq!(http_date(-62_198_755_200), "Fri, 01 Jan -0001 00:00:00 GMT");
    }

    #[test]
    fn offset_labels_keep_the_banner_form() {
        for (offset, label) in [
            (0, "+00:00"),
            (-18_000, "-05:00"),
            (19_800, "+05:30"),
            (20_700, "+05:45"),
            (50_400, "+14:00"),
            (-43_200, "-12:00"),
            (3_661, "+01:01:01"),
            (-34, "-00:00:34"),
            (i32::MIN, "-596523:14:08"),
        ] {
            assert_eq!(offset_label(offset), label, "{offset}");
        }
    }

    #[test]
    fn now_counts_nanoseconds_within_a_second() {
        let (secs, nanos) = now();
        assert!(nanos < 1_000_000_000, "{nanos}");
        // Before year 10000; a host whose clock is unset may be anywhere
        // earlier.
        assert!(secs < 253_402_300_800, "{secs}");
    }

    /// A clock before 1970 rounds the seconds down and counts the
    /// nanoseconds forward, as Go's `time.Time` holds such an instant,
    /// and an absurd reading saturates rather than wrapping.
    #[test]
    fn clocks_before_the_epoch_round_down() {
        for (before, want) in [
            (Duration::from_millis(1500), (-2, 500_000_000)),
            (Duration::from_secs(1), (-1, 0)),
            (Duration::from_nanos(1), (-1, 999_999_999)),
            (Duration::from_secs(86_400 * 365), (-31_536_000, 0)),
            (Duration::from_secs(i64::MAX.unsigned_abs()), (-i64::MAX, 0)),
            (Duration::MAX, (i64::MIN, 1)),
        ] {
            assert_eq!(before_epoch(before), want, "{before:?}");
        }
    }

    /// A deterministic run of instants and offsets over years 1 to 9999:
    /// xorshift64, so a failure names a case that reproduces.
    fn sweep() -> Vec<(i64, u32, i32)> {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let first = -62_135_596_800 + 86_400; // 0001-01-02
        let span = 253_402_300_799 - 86_400 - first; // to 9999-12-30
        let mut cases: Vec<(i64, u32, i32)> = KNOWN
            .iter()
            .filter(|(secs, _, _)| (first..=first + span).contains(secs))
            .map(|(secs, _, _)| (*secs, 0, 0))
            .collect();
        for _ in 0..4096 {
            let secs = first + i64::try_from(next() % span.unsigned_abs()).expect("span fits");
            let nanos = u32::try_from(next() % 1_000_000_000).expect("below 1e9");
            // Whole quarter hours mostly, as zones have; odd seconds too.
            let draw = next();
            let offset = if draw % 4 == 0 {
                i32::try_from(draw / 4 % 172_799).expect("fits") - 86_399
            } else {
                (i32::try_from(draw / 4 % 113).expect("fits") - 56) * 900
            };
            cases.push((secs, nanos, offset));
        }
        cases
    }

    /// Go's own calendar against this one, through the oracle's
    /// `time_format`: the slog timestamp as Go's `.000` layout gives it
    /// in a fixed zone of the offset, and the `Date` header as
    /// `net/http` writes it.
    #[test]
    fn calendar_text_matches_go() {
        let Some(mut oracle) = dcroxide_testutil::oracle_or_skip() else {
            return;
        };
        let cases = sweep();
        let mut request = Vec::with_capacity(cases.len() * 16);
        for (secs, nanos, offset) in &cases {
            request.extend_from_slice(&secs.to_be_bytes());
            request.extend_from_slice(&nanos.to_be_bytes());
            request.extend_from_slice(&offset.to_be_bytes());
        }
        let response = oracle.call_ok("time_format", &request);
        let lines: Vec<&str> = response.split('\n').collect();
        assert_eq!(lines.len(), cases.len());
        for ((secs, nanos, offset), line) in cases.iter().zip(lines) {
            let ours = format!(
                "{}\t{}",
                slog_timestamp(*secs, *nanos, *offset),
                http_date(*secs)
            );
            assert_eq!(ours, line, "secs {secs}, nanos {nanos}, offset {offset}");
        }
    }
}
