// SPDX-License-Identifier: ISC
//! The local time zone, read as Go reads `time.Local`, and the offset
//! from UTC it gives at an instant, as Go's `Location.lookup` gives it.
//!
//! dcrd stamps every log line with `time.Now()` in `time.Local`
//! (decred/slog@v1.2.0 `log.go:217-237`).  Go reads that zone once per
//! process, on first use, and works out each line's offset at that
//! line's time, so a daemon running across a daylight saving change
//! follows it.  Everything here is a port of Go 1.27.3's own code,
//! cited by go1.27.3 file and line:
//!
//! - which zone: `initLocal` (`time/zoneinfo_unix.go:28-69`) over the
//!   directories of `platformZoneSources` (`:21-26`), through
//!   `loadLocation` and `readFile` (`time/zoneinfo_read.go:531-599`),
//!   with its 10 MiB cap (`:34-37`); and on Windows `initLocal` and
//!   `initLocalFromTZI` (`time/zoneinfo_windows.go:230-237`,
//!   `:137-202`), from `GetTimeZoneInformation`, which
//!   `dcroxide-winsvc` calls;
//! - reading a TZif file: `LoadLocationFromTZData`
//!   (`time/zoneinfo_read.go:118-354`), versions 1 to 3, a missing or
//!   malformed footer passed over as Go passes it over;
//! - the offset at an instant: `lookup`, `lookupFirstZone` and
//!   `firstZoneUsed` (`time/zoneinfo.go:149-268`), and past a file's
//!   last transition the POSIX rule in its footer, `tzset` through
//!   `tzruleTime` (`:276-604`), with the calendar arithmetic they call
//!   from `time/time.go`.
//!
//! Left out: the zone abbreviations, which nothing here prints, and the
//! two places Go's `loadLocation` looks after the system's directories
//! (`time/zoneinfo_read.go:543-564`): the tzdata a program embeds by
//! importing `time/tzdata`, which dcrd does not, and the
//! `lib/time/zoneinfo.zip` of the Go tree a binary was built from,
//! which a dcrd built with `-trimpath` finds only when `GOROOT` is set
//! in its environment.  The port reads neither.  Go's arithmetic wraps
//! where it overflows, so the port's does too.

#[cfg(unix)]
use std::ffi::{OsStr, OsString};
use std::fmt;

/// The start and end of time for zone transitions (Go's `alpha` and
/// `omega`, `time/zoneinfo.go:65-68`).
const ALPHA: i64 = i64::MIN;
const OMEGA: i64 = i64::MAX;

const SECONDS_PER_MINUTE: i64 = 60;
const SECONDS_PER_HOUR: i64 = 60 * SECONDS_PER_MINUTE;
const SECONDS_PER_DAY: i64 = 24 * SECONDS_PER_HOUR;
/// The same, for Go's unsigned absolute seconds.
const ABS_SECONDS_PER_DAY: u64 = 86_400;

/// Go's absolute calendar (`time/time.go:535-567`): years counted from
/// March 1 of year -292277022400, and the seconds between that instant
/// and the Unix epoch, `unixToAbsolute` and `absoluteToUnix`.
const ABSOLUTE_YEARS: u64 = 292_277_022_400;
const MARCH_THRU_DECEMBER: u32 = 306;
const UNIX_TO_ABSOLUTE: i64 = 9_223_372_028_741_760_000;
#[cfg(any(windows, test))]
const ABSOLUTE_TO_UNIX: i64 = -UNIX_TO_ABSOLUTE;

/// The largest file Go's `readFile` reads (`maxFileSize`,
/// `time/zoneinfo_read.go:34-37`), and the most read to find a file
/// over it.
#[cfg(unix)]
const MAX_FILE_SIZE: usize = 10 << 20;
#[cfg(unix)]
const MAX_READ: u64 = MAX_FILE_SIZE as u64 + 1;

/// The directories Go looks a zone name up in, in order
/// (`platformZoneSources`, `time/zoneinfo_unix.go:21-26`).
#[cfg(unix)]
const PLATFORM_ZONE_SOURCES: [&[u8]; 4] = [
    b"/usr/share/zoneinfo/",
    b"/usr/share/lib/zoneinfo/",
    b"/usr/lib/locale/TZ/",
    b"/etc/zoneinfo",
];

/// One kind of local time a zone keeps (Go's `zone`, less its name).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Zone {
    /// Seconds east of UTC.
    offset: i64,
    is_dst: bool,
}

/// A transition (Go's `zoneTrans`, less the two flags it ignores).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ZoneTrans {
    /// The instant, in Unix seconds.
    when: i64,
    /// The index of the zone in effect from then on.
    index: u8,
}

/// What [`Location::lookup`] gives for an instant: the offset east of
/// UTC in effect, the start and end of the span Go reports it for, and
/// whether it is daylight saving time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Lookup {
    pub(crate) offset: i64,
    pub(crate) start: i64,
    pub(crate) end: i64,
    pub(crate) is_dst: bool,
}

/// A time zone: Go's `Location` (`time/zoneinfo.go:23-47`) without the
/// name and the abbreviations, the one-entry cache for the span holding
/// the moment it was read included, since that cache decides some
/// lookups.  A location with no zones is UTC.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Location {
    zone: Vec<Zone>,
    tx: Vec<ZoneTrans>,
    /// The POSIX `TZ`-style rule a TZif file ends with, for instants
    /// past its last transition; empty for none.
    extend: Vec<u8>,
    cache_start: i64,
    cache_end: i64,
    cache_zone: Option<Zone>,
}

impl Location {
    /// UTC, a location with no zones: what Go's `time.Local` is when
    /// `initLocal` falls back.
    pub(crate) fn utc() -> Location {
        Location::default()
    }

    /// The offset east of UTC, in seconds, in effect at a Unix second.
    pub(crate) fn offset(&self, sec: i64) -> i64 {
        self.lookup(sec).offset
    }

    /// The zone in effect at a Unix second, as Go's `lookup` finds it
    /// (`time/zoneinfo.go:149-216`).
    pub(crate) fn lookup(&self, sec: i64) -> Lookup {
        let utc = Lookup {
            offset: 0,
            start: ALPHA,
            end: OMEGA,
            is_dst: false,
        };
        let found = |z: &Zone, start: i64, end: i64| Lookup {
            offset: z.offset,
            start,
            end,
            is_dst: z.is_dst,
        };
        if self.zone.is_empty() {
            return utc;
        }
        if let Some(z) = &self.cache_zone
            && self.cache_start <= sec
            && sec < self.cache_end
        {
            return found(z, self.cache_start, self.cache_end);
        }
        let Some(first) = self.tx.first().filter(|first| sec >= first.when) else {
            let end = self.tx.first().map_or(OMEGA, |first| first.when);
            return self
                .zone
                .get(self.lookup_first_zone())
                .map_or(utc, |z| found(z, ALPHA, end));
        };

        // The last transition at or before sec.
        let mut end = OMEGA;
        let mut lo = 0;
        let mut hi = self.tx.len();
        while hi.wrapping_sub(lo) > 1 {
            let m = lo.midpoint(hi);
            let lim = self.tx.get(m).map_or(OMEGA, |t| t.when);
            if sec < lim {
                end = lim;
                hi = m;
            } else {
                lo = m;
            }
        }
        let t = self.tx.get(lo).copied().unwrap_or(*first);
        let Some(z) = self.zone.get(usize::from(t.index)) else {
            return utc;
        };
        let start = t.when;

        // Past the last transition the footer's rule decides, when it
        // parses.
        if lo == self.tx.len().wrapping_sub(1)
            && !self.extend.is_empty()
            && let Some(rule) = tzset(&self.extend, start, sec)
        {
            return rule;
        }
        found(z, start, end)
    }

    /// The zone for instants before the first transition, or for all of
    /// them when there is none (`lookupFirstZone`,
    /// `time/zoneinfo.go:218-257`).
    fn lookup_first_zone(&self) -> usize {
        // The first zone, when no transition uses it (`firstZoneUsed`,
        // `:259-268`).
        if !self.tx.iter().any(|t| t.index == 0) {
            return 0;
        }
        // The last standard zone ahead of the first transition's, when
        // that one is daylight saving.
        if let Some(first) = self.tx.first()
            && self
                .zone
                .get(usize::from(first.index))
                .is_some_and(|z| z.is_dst)
            && let Some(zi) = (0..usize::from(first.index))
                .rev()
                .find(|&zi| self.zone.get(zi).is_some_and(|z| !z.is_dst))
        {
            return zi;
        }
        // The first standard zone, or else the first.
        self.zone.iter().position(|z| !z.is_dst).unwrap_or(0)
    }
}

/// Go's `LoadLocationFromTZData` and the reader under it.  On Windows,
/// where Go asks the system for the zone, only the tests reach them.
#[cfg_attr(not(unix), allow(dead_code))]
mod tzif {
    use std::fmt;

    use super::{ALPHA, Location, OMEGA, Zone, ZoneTrans, tzset};

    /// Go's `errBadData`: the data is not a TZif file Go would take.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct BadData;

    impl fmt::Display for BadData {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("malformed time zone information")
        }
    }

    /// Go's `dataIO` (`time/zoneinfo_read.go:52-102`): a reader over the
    /// file's bytes.  Go reads on after a short read and then checks; every
    /// short read ends in `errBadData` either way, so this stops at once.
    struct DataIo<'a> {
        p: &'a [u8],
    }

    impl<'a> DataIo<'a> {
        fn read(&mut self, n: usize) -> Result<&'a [u8], BadData> {
            match self.p.split_at_checked(n) {
                Some((head, rest)) => {
                    self.p = rest;
                    Ok(head)
                }
                None => Err(BadData),
            }
        }

        fn big4(&mut self) -> Result<u32, BadData> {
            let p = self.read(4)?;
            Ok(u32::from_be_bytes([p[0], p[1], p[2], p[3]]))
        }

        fn big8(&mut self) -> Result<u64, BadData> {
            let hi = self.big4()?;
            let lo = self.big4()?;
            Ok(u64::from(hi) << 32 | u64::from(lo))
        }

        fn byte(&mut self) -> Result<u8, BadData> {
            Ok(self.read(1)?[0])
        }

        /// The six counts of a TZif header.
        fn counts(&mut self) -> Result<[usize; 6], BadData> {
            let mut n = [0; 6];
            for count in &mut n {
                *count = usize::try_from(self.big4()?).map_err(|_| BadData)?;
            }
            Ok(n)
        }
    }

    /// The header counts, in their order (`time/zoneinfo_read.go:151-158`).
    const N_UTC_LOCAL: usize = 0;
    const N_STD_WALL: usize = 1;
    const N_LEAP: usize = 2;
    const N_TIME: usize = 3;
    const N_ZONE: usize = 4;
    const N_CHAR: usize = 5;

    /// `a * b`, failing as a short read would when it does not fit.
    fn times(a: usize, b: usize) -> Result<usize, BadData> {
        a.checked_mul(b).ok_or(BadData)
    }

    impl Location {
        /// The location a TZif file describes, as Go's
        /// `LoadLocationFromTZData` reads it (`time/zoneinfo_read.go:118-354`),
        /// with `now` the Unix second Go fills its cache for.
        pub(crate) fn from_tzdata(data: &[u8], now: i64) -> Result<Location, BadData> {
            let mut d = DataIo { p: data };
            if d.read(4)? != b"TZif" {
                return Err(BadData);
            }
            let version = match d.read(16)?[0] {
                0 => 1,
                b'2' => 2,
                b'3' => 3,
                _ => return Err(BadData),
            };
            let mut n = d.counts()?;

            // Versions 2 and 3 repeat the data with 64-bit times after the
            // 32-bit data and a second header; Go skips to that.
            let is64 = version > 1;
            if is64 {
                let skip = [
                    times(n[N_TIME], 5)?,
                    times(n[N_ZONE], 6)?,
                    n[N_CHAR],
                    times(n[N_LEAP], 8)?,
                    n[N_STD_WALL],
                    n[N_UTC_LOCAL],
                    4 + 16,
                ]
                .into_iter()
                .try_fold(0usize, |sum, part| sum.checked_add(part))
                .ok_or(BadData)?;
                d.read(skip)?;
                n = d.counts()?;
            }
            let size = if is64 { 8 } else { 4 };

            let mut txtimes = DataIo {
                p: d.read(times(n[N_TIME], size)?)?,
            };
            let txzones = d.read(n[N_TIME])?;
            let mut zonedata = DataIo {
                p: d.read(times(n[N_ZONE], 6)?)?,
            };
            let abbrev = d.read(n[N_CHAR])?;
            d.read(times(n[N_LEAP], size.checked_add(4).ok_or(BadData)?)?)?;
            d.read(n[N_STD_WALL])?;
            d.read(n[N_UTC_LOCAL])?;

            // The footer: a POSIX rule between newlines.
            let rest = d.p;
            let extend = match rest {
                [b'\n', rule @ .., b'\n'] if !rule.is_empty() => rule.to_vec(),
                _ => Vec::new(),
            };

            if n[N_ZONE] == 0 {
                return Err(BadData);
            }
            let mut zone = Vec::with_capacity(n[N_ZONE]);
            for _ in 0..n[N_ZONE] {
                // Go's int(int32(n)): the four bytes are a signed offset.
                let offset = i64::from(zonedata.big4()? as i32);
                let is_dst = zonedata.byte()? != 0;
                if usize::from(zonedata.byte()?) >= abbrev.len() {
                    return Err(BadData);
                }
                zone.push(Zone { offset, is_dst });
            }

            let mut tx = Vec::with_capacity(n[N_TIME].max(1));
            for &index in txzones {
                let when = if is64 {
                    txtimes.big8()? as i64
                } else {
                    i64::from(txtimes.big4()? as i32)
                };
                if usize::from(index) >= zone.len() {
                    return Err(BadData);
                }
                tx.push(ZoneTrans { when, index });
            }
            if tx.is_empty() {
                // A fixed zone such as Etc/GMT0: one transition at the start
                // of time.
                tx.push(ZoneTrans {
                    when: ALPHA,
                    index: 0,
                });
            }

            let mut l = Location {
                zone,
                tx,
                extend,
                ..Location::default()
            };
            l.fill_cache(now);
            Ok(l)
        }

        /// Go's cache of the span holding `now`
        /// (`time/zoneinfo_read.go:321-351`).
        fn fill_cache(&mut self, now: i64) {
            let found = self.tx.iter().enumerate().find(|(i, t)| {
                t.when <= now
                    && self
                        .tx
                        .get(i.wrapping_add(1))
                        .is_none_or(|next| now < next.when)
            });
            let Some((i, t)) = found else {
                return;
            };
            self.cache_start = t.when;
            self.cache_end = OMEGA;
            self.cache_zone = self.zone.get(usize::from(t.index)).copied();
            if let Some(next) = self.tx.get(i.wrapping_add(1)) {
                self.cache_end = next.when;
            } else if !self.extend.is_empty()
                && let Some(rule) = tzset(&self.extend, self.cache_start, now)
            {
                self.cache_start = rule.start;
                self.cache_end = rule.end;
                self.cache_zone = Some(Zone {
                    offset: rule.offset,
                    is_dst: rule.is_dst,
                });
            }
        }
    }
}

/// The kinds of rule a POSIX `TZ` string has (`ruleKind`,
/// `time/zoneinfo.go:452-459`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuleKind {
    /// `Jn`: day n of 365, February 29 never counted.
    Julian,
    /// `n`: day n from 0, February 29 counted.
    Doy,
    /// `Mm.w.d`: weekday d of week w of month m.
    MonthWeekDay,
}

/// A rule from a POSIX `TZ` string (`rule`, `time/zoneinfo.go:461-468`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Rule {
    kind: RuleKind,
    day: i64,
    week: i64,
    mon: i64,
    /// The transition's local time of day, in seconds.
    time: i64,
}

/// The zone a POSIX `TZ` string gives at a Unix second, after a last
/// transition at `last_tx_sec`; `None` where the string does not parse
/// (Go's `tzset`, `time/zoneinfo.go:276-364`).
fn tzset(s: &[u8], last_tx_sec: i64, sec: i64) -> Option<Lookup> {
    let s = tzset_name(s)?;
    let (std_offset, s) = tzset_offset(s)?;
    // The string's offsets are added to local time to get UTC.
    let mut std_offset = std_offset.wrapping_neg();

    if s.first().is_none_or(|&c| c == b',') {
        // No daylight saving.
        return Some(Lookup {
            offset: std_offset,
            start: last_tx_sec,
            end: OMEGA,
            is_dst: false,
        });
    }

    let s = tzset_name(s)?;
    let (mut dst_offset, mut s) = if s.first().is_none_or(|&c| c == b',') {
        (std_offset.wrapping_add(SECONDS_PER_HOUR), s)
    } else {
        let (offset, s) = tzset_offset(s)?;
        (offset.wrapping_neg(), s)
    };

    if s.is_empty() {
        // tzcode's default rules.
        s = b",M3.2.0,M11.1.0";
    }
    // The TZ definition does not mention ';' here but tzcode accepts it.
    let (&sep, s) = s.split_first()?;
    if sep != b',' && sep != b';' {
        return None;
    }
    let (start_rule, s) = tzset_rule(s)?;
    let s = s.strip_prefix(b",")?;
    let (end_rule, s) = tzset_rule(s)?;
    if !s.is_empty() {
        return None;
    }

    // The start of sec's year, and how far into it sec is.  Go's `%`
    // truncates, as Rust's does.
    let (year, yday) = year_yday(sec);
    let ysec = yday
        .wrapping_sub(1)
        .wrapping_mul(SECONDS_PER_DAY)
        .wrapping_add(sec.wrapping_rem(SECONDS_PER_DAY));
    let ystart = sec.wrapping_sub(ysec);

    let mut start_sec = tzrule_time(year, &start_rule, std_offset);
    let mut end_sec = tzrule_time(year, &end_rule, dst_offset);
    let (mut dst_is_dst, mut std_is_dst) = (true, false);
    // A southern-hemisphere rule: daylight saving spans the new year,
    // so the labels swap.
    if end_sec < start_sec {
        std::mem::swap(&mut start_sec, &mut end_sec);
        std::mem::swap(&mut std_offset, &mut dst_offset);
        std::mem::swap(&mut std_is_dst, &mut dst_is_dst);
    }

    Some(if ysec < start_sec {
        Lookup {
            offset: std_offset,
            start: ystart,
            end: start_sec.wrapping_add(ystart),
            is_dst: std_is_dst,
        }
    } else if ysec >= end_sec {
        Lookup {
            offset: std_offset,
            start: end_sec.wrapping_add(ystart),
            end: ystart.wrapping_add(365 * SECONDS_PER_DAY),
            is_dst: std_is_dst,
        }
    } else {
        Lookup {
            offset: dst_offset,
            start: start_sec.wrapping_add(ystart),
            end: end_sec.wrapping_add(ystart),
            is_dst: dst_is_dst,
        }
    })
}

/// The rest of a POSIX `TZ` string after the zone name it starts with
/// (Go's `tzsetName`, `time/zoneinfo.go:366-394`, which also returns
/// the name).  Go walks the string by rune; every byte it compares is
/// ASCII, which no byte of a longer UTF-8 sequence is, so a walk by
/// byte stops where Go's does.
fn tzset_name(s: &[u8]) -> Option<&[u8]> {
    match s.split_first() {
        None => None,
        Some((b'<', _)) => {
            let i = s.iter().position(|&c| c == b'>')?;
            s.get(i.wrapping_add(1)..)
        }
        Some(_) => match s
            .iter()
            .position(|c| matches!(c, b'0'..=b'9' | b',' | b'-' | b'+'))
        {
            Some(i) if i < 3 => None,
            Some(i) => s.get(i..),
            None if s.len() < 3 => None,
            None => Some(&[]),
        },
    }
}

/// A `[+-]hh[:mm[:ss]]` offset at the start of a POSIX `TZ` string, in
/// seconds, and the rest (Go's `tzsetOffset`,
/// `time/zoneinfo.go:396-450`).
fn tzset_offset(s: &[u8]) -> Option<(i64, &[u8])> {
    let (neg, s) = match s.split_first()? {
        (b'+', rest) => (false, rest),
        (b'-', rest) => (true, rest),
        _ => (false, s),
    };
    let sign = |off: i64| if neg { off.wrapping_neg() } else { off };

    // tzdata allows hours up to 24 * 7, though POSIX does not.
    let (hours, s) = tzset_num(s, 0, 24 * 7)?;
    let mut off = hours.wrapping_mul(SECONDS_PER_HOUR);
    let Some(s) = s.strip_prefix(b":") else {
        return Some((sign(off), s));
    };
    let (mins, s) = tzset_num(s, 0, 59)?;
    off = off.wrapping_add(mins.wrapping_mul(SECONDS_PER_MINUTE));
    let Some(s) = s.strip_prefix(b":") else {
        return Some((sign(off), s));
    };
    let (secs, s) = tzset_num(s, 0, 59)?;
    off = off.wrapping_add(secs);
    Some((sign(off), s))
}

/// A transition rule, `Jn`, `n` or `Mm.w.d`, with an optional `/time`,
/// at the start of a POSIX `TZ` string, and the rest (Go's
/// `tzsetRule`, `time/zoneinfo.go:470-529`).
fn tzset_rule(s: &[u8]) -> Option<(Rule, &[u8])> {
    let mut r = Rule {
        kind: RuleKind::Doy,
        day: 0,
        week: 0,
        mon: 0,
        time: 0,
    };
    let s = match s.split_first()? {
        (b'J', rest) => {
            let (jday, s) = tzset_num(rest, 1, 365)?;
            r.kind = RuleKind::Julian;
            r.day = jday;
            s
        }
        (b'M', rest) => {
            let (mon, s) = tzset_num(rest, 1, 12)?;
            let (week, s) = tzset_num(s.strip_prefix(b".")?, 1, 5)?;
            let (day, s) = tzset_num(s.strip_prefix(b".")?, 0, 6)?;
            r.kind = RuleKind::MonthWeekDay;
            r.day = day;
            r.week = week;
            r.mon = mon;
            s
        }
        _ => {
            let (day, s) = tzset_num(s, 0, 365)?;
            r.kind = RuleKind::Doy;
            r.day = day;
            s
        }
    };
    let Some(s) = s.strip_prefix(b"/") else {
        // 2am is the default.
        r.time = 2 * SECONDS_PER_HOUR;
        return Some((r, s));
    };
    let (offset, s) = tzset_offset(s)?;
    r.time = offset;
    Some((r, s))
}

/// A number from `min` to `max` at the start of a POSIX `TZ` string,
/// and the rest (Go's `tzsetNum`, `time/zoneinfo.go:531-556`).
fn tzset_num(s: &[u8], min: i64, max: i64) -> Option<(i64, &[u8])> {
    if s.is_empty() {
        return None;
    }
    let mut num: i64 = 0;
    for (i, &c) in s.iter().enumerate() {
        if !c.is_ascii_digit() {
            if i == 0 || num < min {
                return None;
            }
            return Some((num, s.get(i..)?));
        }
        num = num
            .wrapping_mul(10)
            .wrapping_add(i64::from(c.wrapping_sub(b'0')));
        if num > max {
            return None;
        }
    }
    if num < min {
        return None;
    }
    Some((num, &[]))
}

/// The seconds from the start of `year` to the moment a rule takes
/// effect, in a zone `off` seconds east of UTC (Go's `tzruleTime`,
/// `time/zoneinfo.go:558-604`).
fn tzrule_time(year: i64, r: &Rule, off: i64) -> i64 {
    let s = match r.kind {
        RuleKind::Julian => {
            let mut s = r.day.wrapping_sub(1).wrapping_mul(SECONDS_PER_DAY);
            if is_leap(year) && r.day >= 60 {
                s = s.wrapping_add(SECONDS_PER_DAY);
            }
            s
        }
        RuleKind::Doy => r.day.wrapping_mul(SECONDS_PER_DAY),
        RuleKind::MonthWeekDay => {
            // Zeller's Congruence, with Go's truncating division.
            let m1 = r.mon.wrapping_add(9).wrapping_rem(12).wrapping_add(1);
            let yy0 = if r.mon <= 2 {
                year.wrapping_sub(1)
            } else {
                year
            };
            let yy1 = yy0.wrapping_div(100);
            let yy2 = yy0.wrapping_rem(100);
            let mut dow = (26i64.wrapping_mul(m1).wrapping_sub(2))
                .wrapping_div(10)
                .wrapping_add(1)
                .wrapping_add(yy2)
                .wrapping_add(yy2.wrapping_div(4))
                .wrapping_add(yy1.wrapping_div(4))
                .wrapping_sub(yy1.wrapping_mul(2))
                .wrapping_rem(7);
            if dow < 0 {
                dow = dow.wrapping_add(7);
            }
            // dow is the weekday of the month's first day; d becomes the
            // day of the month, from 0, of its first r.day weekday.
            let mut d = r.day.wrapping_sub(dow);
            if d < 0 {
                d = d.wrapping_add(7);
            }
            for _ in 1..r.week {
                if d.wrapping_add(7) >= days_in(r.mon, year) {
                    break;
                }
                d = d.wrapping_add(7);
            }
            d = d.wrapping_add(days_before(r.mon));
            if is_leap(year) && r.mon > 2 {
                d = d.wrapping_add(1);
            }
            d.wrapping_mul(SECONDS_PER_DAY)
        }
    };
    s.wrapping_add(r.time).wrapping_sub(off)
}

/// The year and 1-based day of the year of a Unix second, by Go's
/// absolute calendar: `absSeconds(...).days().yearYday()`
/// (`time/time.go:638-640`, `:643-678`, `:701-708`, `:717-744`,
/// `:757-763`), its unsigned arithmetic and all.
fn year_yday(sec: i64) -> (i64, i64) {
    let days = (sec.wrapping_add(UNIX_TO_ABSOLUTE) as u64) / ABS_SECONDS_PER_DAY;
    // absDays.split
    let d = days.wrapping_mul(4).wrapping_add(3);
    let century = d / 146_097;
    let cd = ((d % 146_097) as u32) | 3;
    let prod = 2_939_745u64.wrapping_mul(u64::from(cd));
    let cyear = i64::from((prod >> 32) as u32);
    let ayday = i64::from(prod as u32 / 2_939_745 / 4);
    let jan_feb = i64::from(ayday >= i64::from(MARCH_THRU_DECEMBER));
    let year = (century.wrapping_mul(100).wrapping_sub(ABSOLUTE_YEARS) as i64)
        .wrapping_add(cyear)
        .wrapping_add(jan_feb);
    let leap =
        i64::from(cyear % 4 == 0) & (i64::from(cyear != 0) | i64::from(century.is_multiple_of(4)));
    let yday = ayday
        .wrapping_add(1 + 31 + 28)
        .wrapping_add(leap & !jan_feb)
        .wrapping_sub(jan_feb.wrapping_mul(365));
    (year, yday)
}

/// Go's `isLeap` (`time/time.go:1686-1696`).
fn is_leap(year: i64) -> bool {
    let mask = if year.wrapping_rem(25) != 0 { 3 } else { 15 };
    year & mask == 0
}

/// The days in month `m` of `year`, for any `m` Go's `daysIn` is given
/// (`time/time.go:1289-1301`).
fn days_in(m: i64, year: i64) -> i64 {
    if m == 2 {
        return if is_leap(year) { 29 } else { 28 };
    }
    30i64.wrapping_add(m.wrapping_add(m >> 3) & 1)
}

/// The days before month `m` in a year that is not a leap year (Go's
/// `daysBefore`, `time/time.go:1270-1287`).
fn days_before(m: i64) -> i64 {
    let adj = if m >= 3 { -2 } else { 0 };
    214i64
        .wrapping_mul(m)
        .wrapping_sub(211)
        .wrapping_div(7)
        .wrapping_add(adj)
}

/// Why the local zone could not be read: the first failure Go's
/// `loadLocation` keeps (`time/zoneinfo_read.go:531-569`), which it
/// then falls back to UTC over without a word.
#[derive(Debug)]
#[cfg_attr(not(unix), allow(dead_code))]
enum Unread {
    /// No source had the zone, and none failed otherwise.
    Unknown(String),
    /// `/etc/localtime`, read for an unset `TZ`, is missing.
    NoLocaltime,
    /// A file could not be read.
    Io(String, std::io::Error),
    /// A file was over Go's 10 MiB cap.
    TooLarge(String),
    /// A file was not a TZif file Go would take.
    BadData(String),
}

impl Unread {
    #[cfg_attr(not(unix), allow(dead_code))]
    fn is_not_found(&self) -> bool {
        matches!(self, Unread::Io(_, e) if e.kind() == std::io::ErrorKind::NotFound)
    }
}

impl fmt::Display for Unread {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unread::Unknown(name) => write!(f, "unknown time zone {name}"),
            Unread::NoLocaltime => write!(f, "/etc/localtime: not found"),
            Unread::Io(path, e) => write!(f, "{path}: {e}"),
            Unread::TooLarge(path) => write!(f, "{path}: file is too large"),
            Unread::BadData(path) => write!(f, "{path}: {}", tzif::BadData),
        }
    }
}

/// A file's contents, refused past Go's 10 MiB cap (Go's `readFile`,
/// `time/zoneinfo_read.go:575-599`).
#[cfg(unix)]
fn read_file(name: &OsStr) -> Result<Vec<u8>, Unread> {
    let shown = || name.to_string_lossy().into_owned();
    use std::io::Read;

    let file = std::fs::File::open(name).map_err(|e| Unread::Io(shown(), e))?;
    let mut data = Vec::new();
    file.take(MAX_READ)
        .read_to_end(&mut data)
        .map_err(|e| Unread::Io(shown(), e))?;
    if data.len() > MAX_FILE_SIZE {
        return Err(Unread::TooLarge(shown()));
    }
    Ok(data)
}

/// The first of `sources` holding a zone `name` that parses, as Go's
/// `loadLocation` finds it (`time/zoneinfo_read.go:531-569`, with
/// `loadTzinfoFromDirOrZip` at `:365-375`): an empty source takes the
/// name as a path, and any other has `/` and the name appended, so a
/// name may climb out of it with `..`.  The error is the first that is
/// not a missing file, or else that the zone is unknown.
#[cfg(unix)]
fn load_location(name: &[u8], sources: &[&[u8]], now: i64) -> Result<Location, Unread> {
    use std::os::unix::ffi::OsStrExt;

    let mut first: Option<Unread> = None;
    for source in sources {
        let mut path = OsString::new();
        if !source.is_empty() {
            path.push(OsStr::from_bytes(source));
            path.push("/");
        }
        path.push(OsStr::from_bytes(name));
        let err = match read_file(&path) {
            Ok(data) => match Location::from_tzdata(&data, now) {
                Ok(l) => return Ok(l),
                Err(tzif::BadData) => Unread::BadData(path.to_string_lossy().into_owned()),
            },
            Err(e) => e,
        };
        if first.is_none() && !err.is_not_found() {
            first = Some(err);
        }
    }
    Err(first.unwrap_or_else(|| Unread::Unknown(String::from_utf8_lossy(name).into_owned())))
}

/// The process's local zone: the location, Go's name for it (`Local`,
/// the `TZ` value that named it, or `UTC`), and, when it fell back to
/// UTC because the zone could not be read, why.
#[derive(Debug)]
pub(crate) struct LocalZone {
    pub(crate) name: String,
    pub(crate) location: Location,
    pub(crate) unread: Option<String>,
}

impl LocalZone {
    /// UTC by Go's fallback, with the reason when there is one.
    fn utc(unread: Option<String>) -> LocalZone {
        LocalZone {
            name: "UTC".to_owned(),
            location: Location::utc(),
            unread,
        }
    }
}

/// The local zone as Go's Unix `initLocal` chooses it for a value of
/// `TZ` (`time/zoneinfo_unix.go:28-69`), `None` for an unset one, with
/// `now` the Unix second the location's cache is filled for:
///
/// - `TZ` unset: `/etc/localtime`;
/// - `TZ=""`: UTC;
/// - a leading `:` is dropped;
/// - an absolute path: that file;
/// - `UTC`: UTC;
/// - anything else: that name in each of [`PLATFORM_ZONE_SOURCES`],
///   compared as the file system compares it, so a POSIX rule such as
///   `EST5` is a name no directory holds;
/// - and UTC when the file is missing or not a TZif file Go takes.
///
/// `TZDIR` and `ZONEINFO` play no part, as in Go.
#[cfg(unix)]
pub(crate) fn init_local(tz: Option<&OsStr>, now: i64) -> LocalZone {
    use std::os::unix::ffi::OsStrExt;

    let found = |name: &[u8], location| LocalZone {
        name: String::from_utf8_lossy(name).into_owned(),
        location,
        unread: None,
    };
    let unread = match tz.map(OsStr::as_bytes) {
        None => match load_location(b"localtime", &[b"/etc"], now) {
            Ok(z) => return found(b"Local", z),
            Err(e) => Some(localtime_unread(e)),
        },
        Some(tz) => {
            let tz = tz.strip_prefix(b":").unwrap_or(tz);
            if tz.first() == Some(&b'/') {
                match load_location(tz, &[b""], now) {
                    Ok(z) if tz == b"/etc/localtime" => return found(b"Local", z),
                    Ok(z) => return found(tz, z),
                    Err(e) => Some(e),
                }
            } else if !tz.is_empty() && tz != b"UTC" {
                match load_location(tz, &PLATFORM_ZONE_SOURCES, now) {
                    Ok(z) => return found(tz, z),
                    Err(e) => Some(e),
                }
            } else {
                None
            }
        }
    };
    LocalZone::utc(unread.map(|e| e.to_string()))
}

/// Why `/etc/localtime` was not read, for the banner.  Go's error for a
/// missing file is that the zone `localtime` is unknown, which would
/// read as though `TZ` had named it; Go never shows it, so the banner
/// says the file is missing instead.
#[cfg(unix)]
fn localtime_unread(e: Unread) -> Unread {
    match e {
        Unread::Unknown(_) => Unread::NoLocaltime,
        e => e,
    }
}

/// The process's local zone, read now as Go reads `time.Local`: on Unix
/// from `TZ` or `/etc/localtime`, on Windows from
/// `GetTimeZoneInformation`.
pub(crate) fn local(now: i64) -> LocalZone {
    #[cfg(unix)]
    {
        init_local(std::env::var_os("TZ").as_deref(), now)
    }
    #[cfg(windows)]
    {
        match dcroxide_winsvc::time_zone_information() {
            Ok(i) => LocalZone {
                name: "Local".to_owned(),
                location: Location::from_windows(&WindowsZone::from(i), now),
                unread: None,
            },
            Err(e) => LocalZone::utc(Some(format!("GetTimeZoneInformation: {e}"))),
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = now;
        LocalZone::utc(Some("no time zone source on this platform".to_owned()))
    }
}

/// A transition date as Windows gives it (Go's `syscall.Systemtime`,
/// the fields its zone code reads).
#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct WindowsDate {
    pub(crate) month: u16,
    pub(crate) day_of_week: u16,
    pub(crate) day: u16,
    pub(crate) hour: u16,
    pub(crate) minute: u16,
    pub(crate) second: u16,
}

/// The time zone settings Windows gives (Go's
/// `syscall.Timezoneinformation`, the fields its zone code reads).
#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct WindowsZone {
    pub(crate) bias: i32,
    pub(crate) standard_date: WindowsDate,
    pub(crate) standard_bias: i32,
    pub(crate) daylight_date: WindowsDate,
    pub(crate) daylight_bias: i32,
}

#[cfg(windows)]
impl From<dcroxide_winsvc::TimeZoneInformation> for WindowsZone {
    fn from(i: dcroxide_winsvc::TimeZoneInformation) -> WindowsZone {
        let date = |d: dcroxide_winsvc::ZoneDate| WindowsDate {
            month: d.month,
            day_of_week: d.day_of_week,
            day: d.day,
            hour: d.hour,
            minute: d.minute,
            second: d.second,
        };
        WindowsZone {
            bias: i.bias,
            standard_date: date(i.standard_date),
            standard_bias: i.standard_bias,
            daylight_date: date(i.daylight_date),
            daylight_bias: i.daylight_bias,
        }
    }
}

#[cfg(any(windows, test))]
impl Location {
    /// The zone Go's `initLocalFromTZI` builds from Windows' settings
    /// (`time/zoneinfo_windows.go:137-202`): one fixed zone when there
    /// is no daylight saving, and otherwise this year's two transition
    /// rules applied to each of the hundred years either side of the
    /// year `now` falls in.  The return code of
    /// `GetTimeZoneInformation`, which says which bias holds now, plays
    /// no part, as in Go.
    pub(crate) fn from_windows(i: &WindowsZone, now: i64) -> Location {
        if i.standard_date.month == 0 {
            let std = Zone {
                offset: i64::from(i.bias).wrapping_neg().wrapping_mul(60),
                is_dst: false,
            };
            return Location {
                zone: vec![std],
                tx: vec![ZoneTrans {
                    when: ALPHA,
                    index: 0,
                }],
                extend: Vec::new(),
                cache_start: ALPHA,
                cache_end: OMEGA,
                cache_zone: Some(std),
            };
        }
        // Go sums the biases as int32, then widens.
        let zone = vec![
            Zone {
                offset: i64::from(i.bias.wrapping_add(i.standard_bias))
                    .wrapping_neg()
                    .wrapping_mul(60),
                is_dst: false,
            },
            Zone {
                offset: i64::from(i.bias.wrapping_add(i.daylight_bias))
                    .wrapping_neg()
                    .wrapping_mul(60),
                is_dst: true,
            },
        ];
        // d0 is the first transition of the year and i0 the zone after
        // it, d1 and i1 the second.
        let (mut d0, mut d1, mut i0, mut i1) = (&i.standard_date, &i.daylight_date, 0u8, 1u8);
        if d0.month > d1.month {
            std::mem::swap(&mut d0, &mut d1);
            std::mem::swap(&mut i0, &mut i1);
        }
        let offset = |index: u8| zone.get(usize::from(index)).map_or(0, |z| z.offset);
        let (year, _) = year_yday(now);
        let mut tx = Vec::with_capacity(400);
        let mut y = year.wrapping_sub(100);
        while y < year.wrapping_add(100) {
            tx.push(ZoneTrans {
                when: pseudo_unix(y, d0).wrapping_sub(offset(i1)),
                index: i0,
            });
            tx.push(ZoneTrans {
                when: pseudo_unix(y, d1).wrapping_sub(offset(i0)),
                index: i1,
            });
            y = y.wrapping_add(1);
        }
        Location {
            zone,
            tx,
            ..Location::default()
        }
    }
}

/// The local time a Windows transition date names in `year`, as seconds
/// since 1970-01-01 local time (Go's `pseudoUnix`,
/// `time/zoneinfo_windows.go:109-135`).
#[cfg(any(windows, test))]
fn pseudo_unix(year: i64, d: &WindowsDate) -> i64 {
    let mut day: i64 = 1;
    let t = date_unix(
        year,
        i64::from(d.month),
        day,
        i64::from(d.hour),
        i64::from(d.minute),
        i64::from(d.second),
    );
    let mut i = i64::from(d.day_of_week).wrapping_sub(weekday(t));
    if i < 0 {
        i = i.wrapping_add(7);
    }
    day = day.wrapping_add(i);
    let week = i64::from(d.day).wrapping_sub(1);
    if week < 4 {
        day = day.wrapping_add(week.wrapping_mul(7));
    } else {
        // The last such weekday of the month.
        day = day.wrapping_add(4 * 7);
        if day > days_in(i64::from(d.month), year) {
            day = day.wrapping_sub(7);
        }
    }
    t.wrapping_add(day.wrapping_sub(1).wrapping_mul(SECONDS_PER_DAY))
}

/// Go's `norm` (`time/time.go:1702-1714`): `hi` and `lo` with `lo`
/// brought into `[0, base)`.
#[cfg(any(windows, test))]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "base is 12, 60 or 24, never zero or -1"
)]
fn norm(mut hi: i64, mut lo: i64, base: i64) -> (i64, i64) {
    if lo < 0 {
        let n = lo
            .wrapping_neg()
            .wrapping_sub(1)
            .wrapping_div(base)
            .wrapping_add(1);
        hi = hi.wrapping_sub(n);
        lo = lo.wrapping_add(n.wrapping_mul(base));
    }
    if lo >= base {
        let n = lo.wrapping_div(base);
        hi = hi.wrapping_add(n);
        lo = lo.wrapping_sub(n.wrapping_mul(base));
    }
    (hi, lo)
}

/// The Unix second of a UTC date and time, any field out of range
/// carried over as Go's `Date` carries it (`time/time.go:1734-1773`, in
/// UTC, where it looks no offset up).
#[cfg(any(windows, test))]
fn date_unix(year: i64, month: i64, day: i64, hour: i64, min: i64, sec: i64) -> i64 {
    let (year, m) = norm(year, month.wrapping_sub(1), 12);
    let month = m.wrapping_add(1);
    let (min, sec) = norm(min, sec, 60);
    let (hour, min) = norm(hour, min, 60);
    let (day, hour) = norm(day, hour, 24);
    (date_to_abs_days(year, month, day) as i64)
        .wrapping_mul(SECONDS_PER_DAY)
        .wrapping_add(
            hour.wrapping_mul(SECONDS_PER_HOUR)
                .wrapping_add(min.wrapping_mul(SECONDS_PER_MINUTE))
                .wrapping_add(sec),
        )
        .wrapping_add(ABSOLUTE_TO_UNIX)
}

/// Go's `dateToAbsDays` (`time/time.go:599-635`): days from the
/// absolute epoch to a date.
#[cfg(any(windows, test))]
fn date_to_abs_days(year: i64, month: i64, day: i64) -> u64 {
    let mut amonth = month as u32;
    let jan_feb = u32::from(amonth < 3);
    amonth = amonth.wrapping_add(jan_feb.wrapping_mul(12));
    let y = (year as u64)
        .wrapping_sub(u64::from(jan_feb))
        .wrapping_add(ABSOLUTE_YEARS);
    let ayday = 979u32.wrapping_mul(amonth).wrapping_sub(2919) >> 5;
    let century = y / 100;
    let cyear = (y % 100) as u32;
    let cday = 1461u32.wrapping_mul(cyear) / 4;
    let centurydays = 146_097u64.wrapping_mul(century) / 4;
    centurydays.wrapping_add(
        i64::from(cday.wrapping_add(ayday))
            .wrapping_add(day)
            .wrapping_sub(1) as u64,
    )
}

/// The weekday of a Unix second in UTC, Sunday 0 (Go's
/// `Time.Weekday` through `absDays.weekday`, `time/time.go:838-846`).
#[cfg(any(windows, test))]
fn weekday(sec: i64) -> i64 {
    let days = (sec.wrapping_add(UNIX_TO_ABSOLUTE) as u64) / ABS_SECONDS_PER_DAY;
    // March 1 of the absolute year was a Wednesday.
    (days.wrapping_add(3) % 7) as i64
}

/// A TZif file, for tests: `version` (0 for version 1), transitions as
/// (instant, zone index), zones as (offset, daylight saving), and the
/// bytes after the data, the footer's newlines included.  A version 2 or
/// 3 file carries its data in the 64-bit block alone, after an empty
/// 32-bit one, which Go skips either way.
#[cfg(test)]
pub(crate) fn tzif_file(
    version: u8,
    tx: &[(i64, u8)],
    zones: &[(i32, bool)],
    footer: &[u8],
) -> Vec<u8> {
    let count = |n: usize| u32::try_from(n).expect("count fits").to_be_bytes();
    let block = |out: &mut Vec<u8>, tx: &[(i64, u8)], wide: bool| {
        out.extend_from_slice(b"TZif");
        out.push(version);
        out.extend_from_slice(&[0; 15]);
        for n in [0, 0, 0, tx.len(), zones.len(), 8] {
            out.extend_from_slice(&count(n));
        }
        for (when, _) in tx {
            if wide {
                out.extend_from_slice(&when.to_be_bytes());
            } else {
                let narrow = i32::try_from(*when).expect("a version 1 time fits 32 bits");
                out.extend_from_slice(&narrow.to_be_bytes());
            }
        }
        out.extend(tx.iter().map(|(_, index)| index));
        for (offset, is_dst) in zones {
            out.extend_from_slice(&offset.to_be_bytes());
            out.push(u8::from(*is_dst));
            out.push(if *is_dst { 4 } else { 0 });
        }
        out.extend_from_slice(b"STD\0DST\0");
    };
    let mut out = Vec::new();
    if version == 0 {
        block(&mut out, tx, false);
    } else {
        block(&mut out, &[], false);
        block(&mut out, tx, true);
    }
    out.extend_from_slice(footer);
    out
}

/// A zone with no transitions, one standard zone of `offset`, and a
/// footer rule, as Go's slim TZif files are past their last transition.
#[cfg(test)]
pub(crate) fn footer_zone(offset: i32, rule: &str) -> Location {
    let data = tzif_file(
        b'2',
        &[],
        &[(offset, false)],
        format!("\n{rule}\n").as_bytes(),
    );
    Location::from_tzdata(&data, crate::timefmt::now().0).expect("a well-formed file")
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests;
