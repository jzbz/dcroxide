// SPDX-License-Identifier: ISC
//! The local time zone's rules as Windows reports them, for the zone
//! dcrd's log lines are stamped in: Go's Windows `initLocal` asks
//! `GetTimeZoneInformation` for them and builds `time.Local` from the
//! biases and the two transition dates it returns, ignoring `TZ`
//! (go1.27.3 `time/zoneinfo_windows.go:230-237`).  Only the call is
//! here; `dcroxide-node` builds the zone from what it returns, as Go's
//! `initLocalFromTZI` does (`:137-202`).

use std::io;

/// A transition date as `GetTimeZoneInformation` gives it, Go's
/// `syscall.Systemtime` less the fields its zone code never reads: the
/// month (0 when the zone has no daylight saving), the weekday (Sunday
/// is 0), the week of the month (5 for the last), and the local time of
/// day.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ZoneDate {
    /// `wMonth`, 1 to 12, or 0 for none.
    pub month: u16,
    /// `wDayOfWeek`, Sunday 0 to Saturday 6.
    pub day_of_week: u16,
    /// `wDay`, the week within the month, 1 to 5, 5 being the last.
    pub day: u16,
    /// `wHour`.
    pub hour: u16,
    /// `wMinute`.
    pub minute: u16,
    /// `wSecond`.
    pub second: u16,
}

/// The fields of `TIME_ZONE_INFORMATION` Go's zone code reads: the
/// biases, in minutes west of UTC, and the dates daylight saving starts
/// (`daylight_date`) and ends (`standard_date`).  The zone names, which
/// Go reads only for abbreviations, are left out.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TimeZoneInformation {
    /// `Bias`: UTC is local time plus this many minutes.
    pub bias: i32,
    /// `StandardDate`: when standard time begins.
    pub standard_date: ZoneDate,
    /// `StandardBias`, added to `bias` in standard time.
    pub standard_bias: i32,
    /// `DaylightDate`: when daylight saving begins.
    pub daylight_date: ZoneDate,
    /// `DaylightBias`, added to `bias` in daylight saving.
    pub daylight_bias: i32,
}

/// The current time zone settings, from `GetTimeZoneInformation` (Go's
/// `syscall.GetTimeZoneInformation`, which fails only on
/// `TIME_ZONE_ID_INVALID`).  Off Windows this always fails with
/// `Unsupported`.
pub fn time_zone_information() -> io::Result<TimeZoneInformation> {
    imp::time_zone_information()
}

#[cfg(windows)]
mod imp {
    use std::io;

    use windows_sys::Win32::Foundation::SYSTEMTIME;
    use windows_sys::Win32::System::Time::{
        GetTimeZoneInformation, TIME_ZONE_ID_INVALID, TIME_ZONE_INFORMATION,
    };

    use super::{TimeZoneInformation, ZoneDate};

    fn date(d: &SYSTEMTIME) -> ZoneDate {
        ZoneDate {
            month: d.wMonth,
            day_of_week: d.wDayOfWeek,
            day: d.wDay,
            hour: d.wHour,
            minute: d.wMinute,
            second: d.wSecond,
        }
    }

    pub(super) fn time_zone_information() -> io::Result<TimeZoneInformation> {
        let mut tzi = TIME_ZONE_INFORMATION::default();
        // SAFETY: the one pointer passed is `&mut tzi`, a live, aligned
        // local of the type the call writes, which outlives the call;
        // `GetTimeZoneInformation` only writes through it and keeps no
        // copy.
        #[allow(unsafe_code)]
        let id = unsafe { GetTimeZoneInformation(&mut tzi) };
        if id == TIME_ZONE_ID_INVALID {
            return Err(io::Error::last_os_error());
        }
        Ok(TimeZoneInformation {
            bias: tzi.Bias,
            standard_date: date(&tzi.StandardDate),
            standard_bias: tzi.StandardBias,
            daylight_date: date(&tzi.DaylightDate),
            daylight_bias: tzi.DaylightBias,
        })
    }
}

#[cfg(not(windows))]
mod imp {
    use std::io;

    use super::TimeZoneInformation;

    /// Unix zones are read by the daemon itself.
    pub(super) fn time_zone_information() -> io::Result<TimeZoneInformation> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the time zone is asked of Windows only on Windows",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Off Windows the call is a stub.
    #[cfg(not(windows))]
    #[test]
    fn the_zone_is_asked_of_windows_only_on_windows() {
        let err = time_zone_information().expect_err("stub");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    /// Windows answers with a bias inside a day of UTC either way and,
    /// when the zone has daylight saving, dates that name a month.  The
    /// day fields are not checked: Windows may give a date in its
    /// absolute form, a day of the month in a given year, which Go's zone
    /// code, and so this port, reads as a week and weekday regardless.
    #[cfg(windows)]
    #[test]
    fn windows_reports_a_zone() {
        let tzi = time_zone_information().expect("GetTimeZoneInformation");
        assert!((-24 * 60..=24 * 60).contains(&tzi.bias), "{tzi:?}");
        if tzi.standard_date.month != 0 {
            for d in [tzi.standard_date, tzi.daylight_date] {
                assert!((1..=12).contains(&d.month), "{tzi:?}");
            }
        }
    }
}
