// SPDX-License-Identifier: ISC
//! Tests of the zone port: the POSIX rule evaluator, the TZif reader and
//! the Windows zone on known cases; Unix's choice of zone over a matrix
//! of `TZ` values; and both, through the oracle, against Go's own
//! `time.Local` and `LoadLocationFromTZData`.

use super::*;

/// Instants every zone is probed at: mid-January and mid-July of 2020,
/// whose offsets no tzdata release will move, then instants around New
/// York's changes of 2026 (its spring change among them) and out to
/// 2100, the epoch, and a second in 1938.
const INSTANTS: [i64; 12] = [
    1_579_089_600,
    1_594_814_400,
    1_768_478_400,
    1_772_953_199,
    1_772_953_200,
    1_782_907_200,
    1_794_916_800,
    2_224_756_800,
    4_103_697_600,
    4_119_336_000,
    0,
    -1_000_000_000,
];

fn now() -> i64 {
    crate::timefmt::now().0
}

/// The offsets a location gives at each instant.
fn offsets(l: &Location, instants: &[i64]) -> Vec<i64> {
    instants.iter().map(|&s| l.offset(s)).collect()
}

#[test]
fn utc_has_no_offset() {
    let utc = Location::utc();
    for s in [i64::MIN, -1, 0, 1, i64::MAX] {
        assert_eq!(
            utc.lookup(s),
            Lookup {
                offset: 0,
                start: ALPHA,
                end: OMEGA,
                is_dst: false
            }
        );
    }
}

/// Rules evaluated by hand: New York's, a southern-hemisphere one whose
/// daylight saving spans the new year, Julian and zero-based days, a
/// quarter-hour zone, and tzcode's default dates for a rule naming none.
#[test]
fn posix_rules_give_the_offsets_they_name() {
    let at = |rule: &str, sec: i64| tzset(rule.as_bytes(), ALPHA, sec).map(|l| l.offset);
    // New York: 2026-03-08 07:00 UTC and 2026-11-01 06:00 UTC.
    for rule in [
        "EST5EDT,M3.2.0,M11.1.0",
        "EST5EDT",
        "EST+5EDT4,M3.2.0/2,M11.1.0/02:00:00",
    ] {
        assert_eq!(at(rule, 1_772_953_199), Some(-18_000), "{rule}");
        assert_eq!(at(rule, 1_772_953_200), Some(-14_400), "{rule}");
        assert_eq!(at(rule, 1_793_512_799), Some(-14_400), "{rule}");
        assert_eq!(at(rule, 1_793_512_800), Some(-18_000), "{rule}");
    }
    // Sydney: daylight saving from the first Sunday of October 02:00
    // AEST to the first Sunday of April 03:00 AEDT; in 2026 that is
    // 2026-04-04 16:00 UTC and 2026-10-03 16:00 UTC.
    let sydney = "AEST-10AEDT,M10.1.0,M4.1.0/3";
    assert_eq!(at(sydney, 1_768_478_400), Some(39_600));
    assert_eq!(at(sydney, 1_775_318_399), Some(39_600));
    assert_eq!(at(sydney, 1_775_318_400), Some(36_000));
    assert_eq!(at(sydney, 1_791_043_199), Some(36_000));
    assert_eq!(at(sydney, 1_791_043_200), Some(39_600));
    // Day 60 is March 1 for `J60` in every year, and March 1 or
    // February 29 for zero-based `59`.
    let julian = "AAA0BBB,J60/0,J300/0";
    assert_eq!(at(julian, 951_868_799), Some(0)); // 2000-02-29 23:59:59
    assert_eq!(at(julian, 951_868_800), Some(3600)); // 2000-03-01
    let zero_based = "AAA0BBB,59/0,300/0";
    assert_eq!(at(zero_based, 951_782_399), Some(0)); // 2000-02-28 23:59:59
    assert_eq!(at(zero_based, 951_782_400), Some(3600)); // 2000-02-29
    // No daylight saving: the offset alone, past the last transition.
    assert_eq!(
        tzset(b"<+0545>-5:45", 7, 1_000),
        Some(Lookup {
            offset: 20_700,
            start: 7,
            end: OMEGA,
            is_dst: false
        })
    );
    assert_eq!(at("<-0330>3:30", 0), Some(-12_600));
    assert_eq!(at("XXX-24:59:59", 0), Some(89_999));
    assert_eq!(at("XXX167", 0), Some(-601_200));
    // The daylight name ending the string, a comma after the standard
    // offset, and tzcode's ';', which Go takes only after a daylight
    // offset.
    assert_eq!(at("CET-1CEST", 1_594_814_400), Some(7200));
    assert_eq!(at("CET-1,M3.5.0,M10.5.0/3", 1_594_814_400), Some(3600));
    assert_eq!(
        at("CET-1CEST-2;M3.5.0,M10.5.0/3", 1_594_814_400),
        Some(7200)
    );
}

/// Strings Go's `tzset` does not parse, which leave the last
/// transition's zone in force.  The cases here and above were checked
/// against Go's `LoadLocationFromTZData` with each as a footer.
#[test]
fn malformed_posix_rules_do_not_parse() {
    for rule in [
        "",
        "ES5",
        "EST",
        "<EST5",
        "EST5ED",
        "EST5EDT,",
        "EST5EDT,M3.2.0",
        "EST5EDT,M3.2.0,",
        "EST5EDT,M3.2.0,M11.1.0,",
        "EST5EDT,M13.2.0,M11.1.0",
        "EST5EDT,M3.6.0,M11.1.0",
        "EST5EDT,M3.2.7,M11.1.0",
        "EST5EDT,M3.2,M11.1.0",
        "EST5EDT,J0,J100",
        "EST5EDT,J366,J100",
        "EST5EDT,366,100",
        "EST169",
        "EST5:60",
        "EST5:00:60",
        "EST5EDT:M3.2.0,M11.1.0",
        "EST5EDT,M3.2.0/x,M11.1.0",
        "EST5EDT4x,M3.2.0,M11.1.0",
        "CET-1CEST;M3.5.0,M10.5.0/3",
    ] {
        assert_eq!(tzset(rule.as_bytes(), 0, 1_594_814_400), None, "{rule:?}");
    }
}

/// The year and day of the year by Go's absolute calendar against the
/// proleptic Gregorian calendar the certificate generator uses.
#[test]
fn absolute_calendar_matches_the_civil_one() {
    let mut s: i64 = -62_135_596_800; // 0001-01-01
    while s < 253_402_300_800 {
        let (year, month, day, ..) = dcroxide_certgen::civil_from_unix(s);
        let (y, yday) = year_yday(s);
        assert_eq!(y, year, "{s}");
        let before: i64 = (1..month).map(|m| days_in(i64::from(m), year)).sum::<i64>();
        assert_eq!(yday, before + i64::from(day), "{s}");
        assert_eq!(
            date_unix(year, i64::from(month), i64::from(day), 0, 0, 0),
            s.div_euclid(SECONDS_PER_DAY) * SECONDS_PER_DAY,
            "{s}"
        );
        assert_eq!(
            weekday(s),
            (s.div_euclid(SECONDS_PER_DAY) + 4).rem_euclid(7),
            "{s}"
        );
        s += 86_400 * 37 + 3_601;
    }
    for (year, leap) in [
        (1900, false),
        (2000, true),
        (2024, true),
        (2100, false),
        (-4, true),
    ] {
        assert_eq!(is_leap(year), leap, "{year}");
    }
    assert_eq!(
        (1..=13).map(days_before).collect::<Vec<_>>(),
        [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365]
    );
    // Go's Date carries months and hours over.
    assert_eq!(date_unix(2025, 13, 1, 0, 0, 0), 1_767_225_600); // 2026-01-01
    assert_eq!(date_unix(2026, 0, 1, 0, 0, 0), 1_764_547_200); // 2025-12-01
    assert_eq!(date_unix(2026, 1, 1, 25, 0, 0), 1_767_315_600); // 01-02 01:00
}

/// A file with transitions and zones of every kind it can hold.
fn new_york_fat(footer: &[u8]) -> Vec<u8> {
    // EST and EDT, transitions in 2025 and 2026, and LMT first, which no
    // transition uses.
    tzif_file(
        b'2',
        &[
            (1_741_503_600, 2), // 2025-03-09 07:00 UTC, to EDT
            (1_762_063_200, 1), // 2025-11-02 06:00 UTC, to EST
            (1_772_953_200, 2), // 2026-03-08 07:00 UTC, to EDT
        ],
        &[(-17_762, false), (-18_000, false), (-14_400, true)],
        footer,
    )
}

#[test]
fn tzif_versions_one_to_three_read_and_others_do_not() {
    let zones = [(3600, false)];
    for version in [0, b'2', b'3'] {
        let l = Location::from_tzdata(&tzif_file(version, &[(0, 0)], &zones, b""), now())
            .unwrap_or_else(|_| panic!("version {version}"));
        assert_eq!(l.offset(1), 3600);
    }
    for version in [b'1', b'4', b' ', 0xff] {
        assert_eq!(
            Location::from_tzdata(&tzif_file(version, &[(0, 0)], &zones, b""), now()),
            Err(tzif::BadData),
            "version {version}"
        );
    }
}

/// Every way a file can fail that Go refuses it for.
#[test]
fn malformed_tzif_files_are_refused() {
    let good = tzif_file(b'2', &[(0, 0)], &[(3600, false)], b"");
    assert!(Location::from_tzdata(&good, now()).is_ok());
    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("magic", [b"TZjf".as_slice(), &good[4..]].concat()),
        ("no zones", tzif_file(b'2', &[], &[], b"")),
        (
            "transition to a missing zone",
            tzif_file(b'2', &[(0, 1)], &[(0, false)], b""),
        ),
        (
            "version 1, transition to a missing zone",
            tzif_file(0, &[(0, 1)], &[(0, false)], b""),
        ),
    ];
    for cut in [5, 20, 44, good.len() / 2, good.len() - 1] {
        cases.push(("short", good[..cut].to_vec()));
    }
    // A zone whose abbreviation index is past the abbreviations.
    let mut bad_abbrev = good.clone();
    let at = bad_abbrev.len() - 8 - 1;
    bad_abbrev[at] = 8;
    cases.push(("abbreviation index", bad_abbrev));
    for (what, data) in cases {
        assert_eq!(
            Location::from_tzdata(&data, now()),
            Err(tzif::BadData),
            "{what}"
        );
    }
}

/// Past the last transition a footer that parses decides, and one that
/// is missing, empty, unparseable or at odds with the data is passed
/// over, the last transition's zone staying in force, as in Go.
#[test]
fn footers_decide_past_the_last_transition_or_are_passed_over() {
    let july_2027 = 1_814_443_200;
    let jan_2027 = 1_799_668_800;
    let read = |footer: &[u8]| {
        Location::from_tzdata(&new_york_fat(footer), now()).expect("well-formed data")
    };
    let ny = read(b"\nEST5EDT,M3.2.0,M11.1.0\n");
    assert_eq!(offsets(&ny, &[jan_2027, july_2027]), [-18_000, -14_400]);
    for footer in [
        b"".as_slice(),
        b"\n",
        b"\n\n",
        b"\nEST5EDT,M3.2.0,M11.1.0",
        b"EST5EDT,M3.2.0,M11.1.0\n",
        b"\nEST5EDT,M3.2.0,M11.1.x\n",
    ] {
        assert_eq!(
            offsets(&read(footer), &[jan_2027, july_2027]),
            [-14_400, -14_400],
            "{footer:?}"
        );
    }
    // A footer at odds with the data still decides past the end.
    assert_eq!(
        offsets(&read(b"\nCST6CDT,M3.2.0,M11.1.0\n"), &[jan_2027, july_2027]),
        [-21_600, -18_000]
    );
    // Before the first transition the first zone no transition uses.
    assert_eq!(ny.offset(0), -17_762);
    // Version 1 data has no 64-bit block, and Go reads a footer there
    // too.
    let v1 = Location::from_tzdata(
        &tzif_file(0, &[(0, 0)], &[(-18_000, false)], b"\nEST5EDT\n"),
        now(),
    )
    .expect("version 1");
    assert_eq!(offsets(&v1, &[jan_2027, july_2027]), [-18_000, -14_400]);
}

/// The zone before the first transition, by the four cases of Go's
/// `lookupFirstZone`.
#[test]
fn the_first_zone_follows_go() {
    let first = |tx: &[(i64, u8)], zones: &[(i32, bool)]| {
        Location::from_tzdata(&tzif_file(b'2', tx, zones, b""), now())
            .expect("well-formed")
            .offset(-1_000)
    };
    // 1: the first zone, unused by any transition.
    assert_eq!(first(&[(0, 1)], &[(1, false), (2, false)]), 1);
    // 2: the first transition is to daylight saving: the standard zone
    // closest before it.
    assert_eq!(
        first(
            &[(0, 3), (5, 0)],
            &[(1, false), (2, false), (3, true), (4, true)]
        ),
        2
    );
    // 3: otherwise the first standard zone.
    assert_eq!(
        first(&[(0, 0), (5, 2)], &[(1, true), (2, true), (3, false)]),
        3
    );
    assert_eq!(first(&[(0, 0), (5, 1)], &[(1, true), (2, false)]), 2);
    // 4: otherwise the first zone.
    assert_eq!(first(&[(0, 0), (5, 1)], &[(1, true), (2, true)]), 1);
}

/// The span holding the moment of reading is cached as Go caches it.
/// The cache can change what a lookup gives (see the next test), but
/// on this data, whose cached spans are the transitions' own, lookups
/// agree with and without it.
#[test]
fn the_cache_holds_the_span_of_the_reading() {
    let data = new_york_fat(b"\nEST5EDT,M3.2.0,M11.1.0\n");
    // Read between the 2025 transitions: the cache is that span.
    let l = Location::from_tzdata(&data, 1_750_000_000).expect("read");
    assert_eq!(
        (l.cache_start, l.cache_end, l.cache_zone.map(|z| z.offset)),
        (1_741_503_600, 1_762_063_200, Some(-14_400))
    );
    // Read past the last transition: the footer's span.
    let l = Location::from_tzdata(&data, 1_794_916_800).expect("read");
    assert_eq!(
        (l.cache_start, l.cache_end, l.cache_zone.map(|z| z.offset)),
        (1_793_512_800, 1_798_761_600, Some(-18_000))
    );
    // Read before the first: no cache.
    let l = Location::from_tzdata(&data, 0).expect("read");
    assert_eq!(l.cache_zone, None);
    let uncached = Location {
        cache_zone: None,
        ..l.clone()
    };
    for read_at in [0, 1_750_000_000, 1_794_916_800] {
        let l = Location::from_tzdata(&data, read_at).expect("read");
        for s in INSTANTS {
            assert_eq!(l.lookup(s), uncached.lookup(s), "read at {read_at}, {s}");
        }
    }
}

/// A missing `/etc/localtime` is named as such in the banner's reason,
/// not as Go's unknown zone `localtime`; other reasons pass through.
#[cfg(unix)]
#[test]
fn a_missing_localtime_says_so() {
    assert_eq!(
        localtime_unread(Unread::Unknown("localtime".to_owned())).to_string(),
        "/etc/localtime: not found"
    );
    assert_eq!(
        localtime_unread(Unread::BadData("/etc/localtime".to_owned())).to_string(),
        "/etc/localtime: malformed time zone information"
    );
}

/// A file with a transition to `+07:00` ten days before `last`, one to
/// `+00:00` at `last`, and `footer`, a rule whose standard time is
/// `+00:00`.  Read after `last`, in a span of the footer's that starts
/// before it, the file caches that span, which reaches back before the
/// last transition; there the cache decides, as Go's does, giving the
/// footer's zone where the transitions alone give `+07:00`.
fn reaching_back_file(footer: &[u8], last: i64) -> Vec<u8> {
    tzif_file(
        b'2',
        &[(last - 10 * 86_400, 0), (last, 1)],
        &[(25_200, false), (0, false)],
        footer,
    )
}

/// Daylight saving on January 1 from 00:00 to 23:00 UTC, and standard
/// time from then to 365 days after the start of the year: the end of
/// the year, or 00:00 UTC on December 31 in a leap year
/// (`time/zoneinfo.go:359-360`).
const DST_ON_JANUARY_1: &[u8] = b"\nAAA0BBB,J1/0,J2/0\n";

/// Daylight saving on June 29 from 00:00 to 23:00 UTC, and standard
/// time from the start of the year to then.
const DST_ON_JUNE_29: &[u8] = b"\nAAA0BBB,J180/0,J181/0\n";

/// How near the turn of a UTC year, either side, no file whose cache
/// reaches back is written, in seconds.
const YEAR_TURN_MARGIN: i64 = 600;

/// A file of `reaching_back_file`'s for a reading at `now`, with the
/// start of the span its cache should hold and its last transition.
struct ReachingBack {
    data: Vec<u8>,
    start: i64,
    last: i64,
}

/// The file whose cache reaches back, for a reading at `now`, chosen
/// from the calendar alone, never from what the port caches.  Go's
/// `tzset` bounds its spans by the calendar year
/// (`time/zoneinfo.go:353-363`), so from January 2 the footer is
/// [`DST_ON_JANUARY_1`], whose standard time starts at 23:00 UTC on
/// January 1, and on January 1 it is [`DST_ON_JUNE_29`], whose standard
/// time starts with the year.  The last transition falls halfway
/// between that start and `now`.  On December 31 of a leap year Go's
/// standard span ends 365 days into the year, at 00:00 UTC that day,
/// and no longer holds `now`; it is still the span cached, and still
/// reaches back before the last transition, in the summer.
///
/// `None` within [`YEAR_TURN_MARGIN`] of the turn of a UTC year.
/// Before it, Go and this port, reading the file some seconds after it
/// was written, may read it in the next year and cache that year's
/// span, which starts after the last transition.  After it no such race
/// arises, since the file's span starts with the year, and
/// `start < last` needs only two seconds; the margin is kept on that
/// side only to make the skip symmetric.  Go's clock cannot be set, so
/// Go reads the file only at the real moment of a run; the unit test
/// below pins dates of every kind against the port.
fn cache_reaching_back(now: i64) -> Option<ReachingBack> {
    let year = dcroxide_certgen::civil_from_unix(now).0;
    let year_start = date_unix(year, 1, 1, 0, 0, 0);
    let next_year = date_unix(year + 1, 1, 1, 0, 0, 0);
    if now - year_start < YEAR_TURN_MARGIN || next_year - now <= YEAR_TURN_MARGIN {
        return None;
    }
    let (footer, start) = if now - year_start < 86_400 {
        (DST_ON_JUNE_29, year_start)
    } else {
        (DST_ON_JANUARY_1, year_start + 23 * 3600)
    };
    let last = start + (now - start) / 2;
    Some(ReachingBack {
        data: reaching_back_file(footer, last),
        start,
        last,
    })
}

/// Read on 2026-11-17, a day after the last transition, the cache is
/// the footer's standard time from 23:00 UTC on January 1 to the end of
/// the year, and gives `+00:00` before the last transition, as Go does,
/// where the transitions alone give `+07:00`.
#[test]
fn the_cache_decides_lookups_it_covers() {
    let now = 1_794_916_800;
    let last = now - 86_400;
    let l = Location::from_tzdata(&reaching_back_file(DST_ON_JANUARY_1, last), now).expect("read");
    // 2026-01-01 23:00 UTC, when the footer's daylight saving ends, to
    // 2027-01-01 00:00 UTC.
    assert_eq!(
        (l.cache_start, l.cache_end, l.cache_zone.map(|z| z.offset)),
        (1_767_308_400, 1_798_761_600, Some(0))
    );
    let instants = [last - 11 * 86_400, last - 86_400, last - 1, last, now];
    assert_eq!(offsets(&l, &instants), [0; 5]);
    let uncached = Location {
        cache_zone: None,
        ..l
    };
    assert_eq!(
        offsets(&uncached, &instants),
        [25_200, 25_200, 25_200, 0, 0]
    );
}

/// The file whose cache reaches back, for readings across the year:
/// skipped within [`YEAR_TURN_MARGIN`] of the turn of a UTC year and
/// written at every other moment, its cache then holding the span Go's
/// `tzset` gives (each span confirmed with go1.27.3's `ZoneBounds`) and
/// deciding the lookups it covers before the last transition.
#[test]
fn the_reaching_back_file_follows_the_calendar() {
    // The spans: 2027-01-01 00:00 UTC to 2027-06-29 00:00 UTC, 2027-01-01
    // 23:00 UTC to 2028-01-01 00:00 UTC, 2028-01-01 00:00 UTC to
    // 2028-06-29 00:00 UTC, 2028-01-01 23:00 UTC to 2028-12-31 00:00
    // UTC, 2029-01-01 00:00 UTC to 2029-06-29 00:00 UTC, 2029-01-01
    // 23:00 UTC to 2030-01-01 00:00 UTC, and 2026-01-01 23:00 UTC to
    // 2027-01-01 00:00 UTC.  The June-29 rule is chosen only on
    // January 1, so the late-June readings test the January-1 rule in
    // the middle of the year, not either side of the June-29 rule's
    // daylight saving.
    let june_2027 = Some((1_798_761_600, 1_814_227_200));
    let year_2027 = Some((1_798_844_400, 1_830_297_600));
    let june_2028 = Some((1_830_297_600, 1_845_849_600));
    let year_2028 = Some((1_830_380_400, 1_861_833_600));
    let june_2029 = Some((1_861_920_000, 1_877_385_600));
    let year_2029 = Some((1_862_002_800, 1_893_456_000));
    let year_2026 = Some((1_767_308_400, 1_798_761_600));
    for (now, want) in [
        (1_798_762_199, None),      // 2027-01-01 00:09:59
        (1_798_762_200, june_2027), // 2027-01-01 00:10:00
        (1_798_763_400, june_2027), // 2027-01-01 00:30
        (1_798_840_800, june_2027), // 2027-01-01 22:00
        (1_798_847_999, june_2027), // 2027-01-01 23:59:59
        (1_798_848_000, year_2027), // 2027-01-02 00:00
        (1_798_977_600, year_2027), // 2027-01-03 12:00
        (1_814_184_000, year_2027), // 2027-06-28 12:00
        (1_814_356_800, year_2027), // 2027-06-30 12:00
        (1_830_168_000, year_2027), // 2027-12-30 12:00
        (1_830_254_400, year_2027), // 2027-12-31 12:00
        (1_830_296_400, year_2027), // 2027-12-31 23:40
        (1_830_296_999, year_2027), // 2027-12-31 23:49:59
        (1_830_297_000, None),      // 2027-12-31 23:50:00
        (1_830_297_599, None),      // 2027-12-31 23:59:59
        (1_830_297_600, None),      // 2028-01-01 00:00
        (1_830_299_400, june_2028), // 2028-01-01 00:30
        (1_845_806_400, year_2028), // 2028-06-28 12:00
        (1_845_892_800, year_2028), // 2028-06-29 12:00
        (1_861_747_200, year_2028), // 2028-12-30 00:00
        (1_861_876_800, year_2028), // 2028-12-31 12:00
        (1_861_919_399, year_2028), // 2028-12-31 23:49:59
        (1_861_919_400, None),      // 2028-12-31 23:50:00
        (1_861_921_800, june_2029), // 2029-01-01 00:30
        (1_862_006_400, year_2029), // 2029-01-02 00:00
        (1_794_916_800, year_2026), // 2026-11-17 12:00
    ] {
        let case = cache_reaching_back(now);
        assert_eq!(case.as_ref().map(|c| c.start), want.map(|w| w.0), "{now}");
        let Some(case) = case else {
            continue;
        };
        let (start, last) = (case.start, case.last);
        assert!(start < last && last < now, "{now}");
        let l = Location::from_tzdata(&case.data, now).expect("read");
        assert_eq!(
            (l.cache_start, l.cache_end, l.cache_zone.map(|z| z.offset)),
            (start, want.expect("a span").1, Some(0)),
            "{now}"
        );
        let uncached = Location {
            cache_zone: None,
            ..l.clone()
        };
        let before = [start, start + (last - start) / 2, last - 1];
        assert_eq!(offsets(&l, &before), [0; 3], "{now}");
        assert_eq!(offsets(&uncached, &before), [25_200; 3], "{now}");
        assert_eq!(offsets(&l, &[last, now]), [0; 2], "{now}");
        assert_eq!(offsets(&uncached, &[last, now]), [0; 2], "{now}");
    }
}

/// Go's own Windows test zones, US Pacific and eastern Australia
/// (`time/zoneinfo_windows.go:204-228`), and one without daylight
/// saving, read in 2026.
#[test]
fn windows_zones_follow_their_rules() {
    let date = |month, day, hour| WindowsDate {
        month,
        day,
        hour,
        ..WindowsDate::default()
    };
    let pacific = WindowsZone {
        bias: 8 * 60,
        standard_date: date(11, 1, 2),
        daylight_date: date(3, 2, 2),
        daylight_bias: -60,
        ..WindowsZone::default()
    };
    let l = Location::from_windows(&pacific, 1_794_916_800);
    assert_eq!(l.tx.len(), 400);
    // 2026-03-08 10:00 UTC and 2026-11-01 09:00 UTC.
    assert_eq!(
        offsets(
            &l,
            &[1_772_963_999, 1_772_964_000, 1_793_523_599, 1_793_523_600]
        ),
        [-28_800, -25_200, -25_200, -28_800]
    );
    let aus = WindowsZone {
        bias: -10 * 60,
        standard_date: date(4, 1, 3),
        daylight_date: date(10, 1, 2),
        daylight_bias: -60,
        ..WindowsZone::default()
    };
    let l = Location::from_windows(&aus, 1_794_916_800);
    // 2026-04-04 16:00 UTC and 2026-10-03 16:00 UTC.
    assert_eq!(
        offsets(
            &l,
            &[1_775_318_399, 1_775_318_400, 1_791_043_199, 1_791_043_200]
        ),
        [39_600, 36_000, 36_000, 39_600]
    );
    // No daylight saving: the bias alone, the others ignored.
    let fixed = WindowsZone {
        bias: -330,
        standard_bias: 7,
        daylight_bias: -60,
        daylight_date: date(3, 2, 2),
        ..WindowsZone::default()
    };
    let l = Location::from_windows(&fixed, 1_794_916_800);
    assert_eq!(offsets(&l, &INSTANTS), [19_800; 12]);
    // The biases are summed as Go sums them, in 32 bits.
    let wrapped = WindowsZone {
        bias: i32::MAX,
        standard_bias: 1,
        standard_date: date(11, 1, 2),
        daylight_date: date(3, 2, 2),
        ..WindowsZone::default()
    };
    let l = Location::from_windows(&wrapped, 1_794_916_800);
    assert_eq!(l.zone[0].offset, i64::from(i32::MIN) * -60);
}

/// The Windows rules' weeks, `5` the last, and a weekday past the
/// first of the month, against dates read off a calendar.
#[test]
fn windows_dates_name_the_right_day() {
    let d = |month, day_of_week, day, hour| WindowsDate {
        month,
        day_of_week,
        day,
        hour,
        ..WindowsDate::default()
    };
    // Last Sunday of October 2026 (the 25th), 03:00; of March 2026 (the
    // 29th); first Monday of June 2026 (the 1st); fourth Friday of
    // February 2024 (the 23rd); fifth of a month that has only four
    // Fridays: February 2026's last is the 27th.
    for (year, date, want) in [
        (2026, d(10, 0, 5, 3), 1_792_897_200),
        (2026, d(3, 0, 5, 1), 1_774_746_000),
        (2026, d(6, 1, 1, 0), 1_780_272_000),
        (2024, d(2, 5, 4, 0), 1_708_646_400),
        (2026, d(2, 5, 5, 0), 1_772_150_400),
    ] {
        assert_eq!(pseudo_unix(year, &date), want, "{year} {date:?}");
    }
}

/// A zone file written into `dir` under `name`, its directories made.
#[cfg(unix)]
fn write_zone(dir: &std::path::Path, name: &str, data: &[u8]) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
    std::fs::write(&path, data).expect("write the zone file");
    path
}

/// The synthetic zone files the matrix and the oracle comparison share:
/// slim files whose footers alone carry the rules, as Go's own zip holds
/// them, one with another zone's data under New York's name, the
/// malformed footers, a version Go refuses, a file over the cap, and,
/// except within [`YEAR_TURN_MARGIN`] of the turn of a UTC year, a file
/// whose cached span reaches back before its last transition, written
/// for the moment of the run.
#[cfg(unix)]
fn synthetic_zones(dir: &std::path::Path) -> Vec<(&'static str, std::path::PathBuf)> {
    let slim = |offset: i32, rule: &str| {
        tzif_file(
            b'2',
            &[],
            &[(offset, false)],
            format!("\n{rule}\n").as_bytes(),
        )
    };
    let lord_howe = slim(37_800, "<+1030>-10:30<+11>-11,M10.1.0,M4.1.0");
    let mut too_large = slim(0, "UTC0");
    too_large.resize(MAX_FILE_SIZE + 1, 0);
    let mut at_the_cap = slim(3600, "CET-1");
    at_the_cap.resize(MAX_FILE_SIZE, 0);
    let mut files: Vec<(&str, &str, Vec<u8>)> = vec![
        (
            "slim New York",
            "slim/America/New_York",
            slim(-18_000, "EST5EDT,M3.2.0,M11.1.0"),
        ),
        (
            "slim Lord Howe",
            "slim/Australia/Lord_Howe",
            lord_howe.clone(),
        ),
        (
            "slim Chatham",
            "slim/Pacific/Chatham",
            slim(45_900, "<+1245>-12:45<+1345>,M9.5.0/2:45,M4.1.0/3:45"),
        ),
        (
            "slim Dublin",
            "slim/Europe/Dublin",
            slim(3600, "IST-1GMT0,M10.5.0,M3.5.0/1"),
        ),
        (
            "slim Sao Paulo",
            "slim/America/Sao_Paulo",
            slim(-10_800, "<-03>3"),
        ),
        (
            "another zone's data",
            "custom/zoneinfo/America/New_York",
            lord_howe,
        ),
        (
            "footer unparseable",
            "bad/unparseable",
            new_york_fat(b"\nEST5EDT,M3.2.0,M11.1.x\n"),
        ),
        (
            "footer inconsistent",
            "bad/inconsistent",
            new_york_fat(b"\nCST6CDT,M3.2.0,M11.1.0\n"),
        ),
        ("no footer", "bad/nofooter", new_york_fat(b"")),
        ("empty footer", "bad/emptyfooter", new_york_fat(b"\n\n")),
        (
            "version 4",
            "bad/version4",
            tzif_file(b'4', &[], &[(3600, false)], b"\nCET-1\n"),
        ),
        ("too large", "bad/toolarge", too_large),
        ("at the cap", "big/atthecap", at_the_cap),
        (
            "in the working directory",
            "cwd/Nowhere_Bogus",
            slim(20_700, "<+0545>-5:45"),
        ),
    ];
    // Within YEAR_TURN_MARGIN of the turn of a UTC year no such file is
    // written (see cache_reaching_back).
    match cache_reaching_back(now()) {
        Some(case) => files.push(("cache reaching back", "cache/reaching_back", case.data)),
        None => eprintln!(
            "skipping the file whose cache reaches back: within {YEAR_TURN_MARGIN} s of the turn of a UTC year"
        ),
    }
    files
        .into_iter()
        .map(|(what, name, data)| (what, write_zone(dir, name, &data)))
        .collect()
}

/// What a `TZ` value should give: a zone read, under Go's name for it,
/// with its offsets at the two 2020 instants; UTC by Go's rule; or UTC
/// because nothing could be read, with the start of the reason.
#[cfg(unix)]
enum Expect {
    Zone(String, [i64; 2]),
    Utc,
    Unread(String),
}

/// A matrix of `TZ` values covering each of Go's rules.  The
/// two that set `TZDIR` and the one with a zone file of the name in the
/// working directory are in the oracle comparison below, since they
/// change the environment or the directory, which neither Go nor this
/// port consults for them; so are `localtime` and `:localtime`, whose
/// answer depends on whether the host's zone directory has such a link.
/// A case naming a system zone file is skipped where the host has none.
#[cfg(unix)]
#[test]
fn the_tz_matrix_follows_go() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let synthetic = synthetic_zones(dir.path());
    let path = |what: &str| {
        let (_, p) = synthetic
            .iter()
            .find(|(w, _)| *w == what)
            .expect("a synthetic zone");
        p.to_str().expect("a UTF-8 temporary path").to_owned()
    };
    let zone = |name: &str, jan, jul| Expect::Zone(name.to_owned(), [jan, jul]);
    let sys = "/usr/share/zoneinfo";
    let lower_found = std::path::Path::new(sys).join("america/new_york").is_file();

    let mut cases: Vec<(String, Option<&str>, Expect)> = vec![
        (String::new(), None, Expect::Utc),
        (":".into(), None, Expect::Utc),
        ("UTC".into(), None, Expect::Utc),
        (":UTC".into(), None, Expect::Utc),
        (
            "America/New_York".into(),
            Some("America/New_York"),
            zone("America/New_York", -18_000, -14_400),
        ),
        (
            ":America/New_York".into(),
            Some("America/New_York"),
            zone("America/New_York", -18_000, -14_400),
        ),
        (
            format!("{sys}/Europe/Berlin"),
            Some("Europe/Berlin"),
            zone(&format!("{sys}/Europe/Berlin"), 3600, 7200),
        ),
        (
            format!(":{sys}/Asia/Kolkata"),
            Some("Asia/Kolkata"),
            zone(&format!("{sys}/Asia/Kolkata"), 19_800, 19_800),
        ),
        (
            "Asia/Kathmandu".into(),
            Some("Asia/Kathmandu"),
            zone("Asia/Kathmandu", 20_700, 20_700),
        ),
        (
            "Australia/Lord_Howe".into(),
            Some("Australia/Lord_Howe"),
            zone("Australia/Lord_Howe", 39_600, 37_800),
        ),
        (
            "Europe/Dublin".into(),
            Some("Europe/Dublin"),
            zone("Europe/Dublin", 0, 3600),
        ),
        (
            "america/new_york".into(),
            Some("America/New_York"),
            if lower_found {
                zone("america/new_york", -18_000, -14_400)
            } else {
                Expect::Unread("unknown time zone america/new_york".into())
            },
        ),
        (
            "Nowhere/Bogus".into(),
            None,
            Expect::Unread("unknown time zone Nowhere/Bogus".into()),
        ),
        (
            "Nowhere_Bogus".into(),
            None,
            Expect::Unread("unknown time zone Nowhere_Bogus".into()),
        ),
        (
            "JST-9".into(),
            None,
            Expect::Unread("unknown time zone JST-9".into()),
        ),
        (
            "EST5EDT,M3.2.0,M11.1.0".into(),
            None,
            Expect::Unread("unknown time zone EST5EDT,M3.2.0,M11.1.0".into()),
        ),
        (
            "EST5EDT".into(),
            Some("EST5EDT"),
            zone("EST5EDT", -18_000, -14_400),
        ),
        (
            "UTC0".into(),
            None,
            Expect::Unread("unknown time zone UTC0".into()),
        ),
        ("GMT0".into(), Some("GMT0"), zone("GMT0", 0, 0)),
        (
            "<+0330>-3:30".into(),
            None,
            Expect::Unread("unknown time zone <+0330>-3:30".into()),
        ),
        (
            "posix/Europe/Paris".into(),
            Some("posix/Europe/Paris"),
            zone("posix/Europe/Paris", 3600, 7200),
        ),
        (
            "right/Europe/Paris".into(),
            Some("right/Europe/Paris"),
            zone("right/Europe/Paris", 3600, 7200),
        ),
        (
            // Climbs out of the first directory and back, which needs it
            // to be a real directory: the kernel resolves the `..`.
            "../../../usr/share/zoneinfo/Asia/Tokyo".into(),
            Some("../../../usr/share/zoneinfo/Asia/Tokyo"),
            zone("../../../usr/share/zoneinfo/Asia/Tokyo", 32_400, 32_400),
        ),
        (
            "Asia/Tokyo".into(),
            Some("Asia/Tokyo"),
            zone("Asia/Tokyo", 32_400, 32_400),
        ),
        // A missing file is not an error Go keeps, so the zone is
        // merely unknown.
        (
            "/nonexistent/zone".into(),
            None,
            Expect::Unread("unknown time zone /nonexistent/zone".into()),
        ),
        (sys.into(), Some(""), Expect::Unread(format!("{sys}: "))),
        (
            "/dev/zero".into(),
            None,
            Expect::Unread("/dev/zero: file is too large".into()),
        ),
    ];
    let synthetic_cases = [
        ("slim New York", ":", -18_000, -14_400),
        ("slim Lord Howe", "", 39_600, 37_800),
        ("slim Chatham", "", 49_500, 45_900),
        ("slim Dublin", "", 0, 3600),
        ("slim Sao Paulo", "", -10_800, -10_800),
        ("another zone's data", "", 39_600, 37_800),
        ("footer unparseable", "", -14_400, -14_400),
        ("footer inconsistent", "", -21_600, -18_000),
        ("no footer", "", -14_400, -14_400),
        ("empty footer", "", -14_400, -14_400),
        ("at the cap", "", 3600, 3600),
    ];
    // The malformed footers pass the 2020 instants, before the data's
    // transitions, to the first zone no transition uses (LMT here); the
    // footer decides only past the last.
    for (what, prefix, jan, jul) in synthetic_cases {
        let p = path(what);
        let (jan, jul) = if what.starts_with("footer") || what.ends_with("footer") {
            (-17_762, -17_762)
        } else {
            (jan, jul)
        };
        cases.push((format!("{prefix}{p}"), None, zone(&p, jan, jul)));
    }
    for (what, reason) in [
        ("version 4", "malformed time zone information"),
        ("too large", "file is too large"),
    ] {
        let p = path(what);
        cases.push((p.clone(), None, Expect::Unread(format!("{p}: {reason}"))));
    }

    let now = now();
    let instants = [INSTANTS[0], INSTANTS[1]];
    for (tz, needs, expect) in cases {
        if let Some(needs) = needs
            && !std::path::Path::new(sys).join(needs).exists()
        {
            eprintln!("skipping TZ={tz:?}: the host has no {sys}/{needs}");
            continue;
        }
        let os_tz = OsString::from_vec(tz.clone().into_bytes());
        let got = init_local(Some(&os_tz), now);
        match expect {
            Expect::Zone(name, want) => {
                assert_eq!(got.unread, None, "TZ={tz:?}");
                assert_eq!(got.name, name, "TZ={tz:?}");
                assert_eq!(offsets(&got.location, &instants), want, "TZ={tz:?}");
            }
            Expect::Utc => {
                assert_eq!(
                    (got.name.as_str(), &got.unread),
                    ("UTC", &None),
                    "TZ={tz:?}"
                );
                assert_eq!(got.location, Location::utc(), "TZ={tz:?}");
            }
            Expect::Unread(reason) => {
                assert_eq!(got.name, "UTC", "TZ={tz:?}");
                assert_eq!(got.location, Location::utc(), "TZ={tz:?}");
                let why = got.unread.unwrap_or_default();
                assert!(why.starts_with(&reason), "TZ={tz:?}: {why:?}");
            }
        }
    }

    // TZ unset reads /etc/localtime, under the name Local, as TZ naming
    // it does.
    let unset = init_local(None, now);
    let named = init_local(Some(std::ffi::OsStr::new("/etc/localtime")), now);
    assert_eq!(unset.name, named.name);
    assert_eq!(unset.location, named.location);
    assert_eq!(unset.unread.is_some(), named.unread.is_some());
    if unset.unread.is_none() {
        assert_eq!(unset.name, "Local");
    } else {
        assert_eq!(unset.name, "UTC");
    }
}

/// The oracle, spawned with `TZ` set to `tz` or removed, `TZDIR` and the
/// working directory as given, and `GOROOT` naming a directory with no
/// `lib/time/zoneinfo.zip`, so Go looks where this port looks.
#[cfg(unix)]
fn oracle_with_tz(
    bin: &std::path::Path,
    no_goroot: &std::path::Path,
    tz: Option<&std::ffi::OsStr>,
    tzdir: Option<&std::path::Path>,
    cwd: Option<&std::path::Path>,
) -> dcroxide_testutil::Oracle {
    let mut cmd = std::process::Command::new(bin);
    cmd.env("GOROOT", no_goroot);
    match tz {
        Some(tz) => cmd.env("TZ", tz),
        None => cmd.env_remove("TZ"),
    };
    match tzdir {
        Some(tzdir) => cmd.env("TZDIR", tzdir),
        None => cmd.env_remove("TZDIR"),
    };
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    dcroxide_testutil::Oracle::from_command(&mut cmd)
}

/// Every `TZ` value of the matrix, and the synthetic zones, against Go's
/// own `time.Local` in an oracle spawned with it: Go's name for the zone
/// and its offset at every probe instant, byte for byte.
#[cfg(unix)]
#[test]
fn local_offsets_match_go() {
    let Some(bin) = dcroxide_testutil::oracle_bin_or_skip() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let synthetic = synthetic_zones(dir.path());
    let no_goroot = dir.path().join("no-goroot");
    std::fs::create_dir_all(&no_goroot).expect("mkdir");
    let sys = "/usr/share/zoneinfo";
    let now = now();
    let mut instants = INSTANTS.to_vec();
    instants.extend([now - 86_400 * 200, now, now + 86_400 * 200]);
    // The first second of the span the reaching-back file caches, where
    // its cache decides, on any day it is written.
    instants.extend(cache_reaching_back(now).map(|c| c.start));
    let request: Vec<u8> = instants.iter().flat_map(|s| s.to_be_bytes()).collect();

    let mut tzs: Vec<Option<String>> = vec![None];
    for tz in [
        "",
        ":",
        "UTC",
        ":UTC",
        "America/New_York",
        ":America/New_York",
        "/usr/share/zoneinfo/Europe/Berlin",
        ":/usr/share/zoneinfo/Asia/Kolkata",
        "Asia/Kathmandu",
        "Australia/Lord_Howe",
        "Europe/Dublin",
        "america/new_york",
        "Nowhere/Bogus",
        "Nowhere_Bogus",
        "JST-9",
        "EST5EDT,M3.2.0,M11.1.0",
        "EST5EDT",
        "UTC0",
        "GMT0",
        "<+0330>-3:30",
        "/etc/localtime",
        "posix/Europe/Paris",
        "right/Europe/Paris",
        "../../../usr/share/zoneinfo/Asia/Tokyo",
        "Asia/Tokyo",
        "localtime",
        ":localtime",
        "/nonexistent/zone",
        sys,
        "/dev/zero",
        "Etc/GMT+5",
        "Factory",
        "/usr/share/zoneinfo/",
        "America/New_York/",
        "./America/New_York",
    ] {
        tzs.push(Some(tz.to_owned()));
    }
    for (_, p) in &synthetic {
        let p = p.to_str().expect("a UTF-8 temporary path");
        tzs.push(Some(p.to_owned()));
        tzs.push(Some(format!(":{p}")));
    }
    let custom = dir.path().join("custom/zoneinfo");
    let cwd = dir.path().join("cwd");
    let mut cases: Vec<(
        Option<String>,
        Option<&std::path::Path>,
        Option<&std::path::Path>,
    )> = tzs.into_iter().map(|tz| (tz, None, None)).collect();
    // TZDIR, which Go ignores for Local, and a file of the name in the
    // working directory, which it never reads.
    cases.extend([
        (
            Some("Asia/Tokyo".to_owned()),
            Some(std::path::Path::new("/nonexistent")),
            None,
        ),
        (None, Some(std::path::Path::new("/nonexistent")), None),
        (
            Some("America/New_York".to_owned()),
            Some(custom.as_path()),
            None,
        ),
        (None, Some(custom.as_path()), None),
        (Some("Nowhere_Bogus".to_owned()), None, Some(cwd.as_path())),
    ]);

    let mut compared = 0;
    for (tz, tzdir, cwd) in cases {
        let os_tz = tz.as_deref().map(std::ffi::OsStr::new);
        let mut oracle = oracle_with_tz(&bin, &no_goroot, os_tz, tzdir, cwd);
        let go = oracle.call_ok("local_offsets", &request);
        let ours = init_local(os_tz, now);
        let joined: Vec<String> = offsets(&ours.location, &instants)
            .iter()
            .map(i64::to_string)
            .collect();
        let ours = format!("{} {}", ours.name, joined.join(","));
        assert_eq!(ours, go, "TZ={tz:?} TZDIR={tzdir:?} cwd={cwd:?}");
        compared += 1;
    }
    eprintln!(
        "{compared} zones agree with Go at {} instants each",
        instants.len()
    );
}

/// The instants a file is probed at: the fixed ones, every transition
/// and the seconds either side of it, and the same for the first spans
/// its footer gives past the last transition.
fn probe_instants(data: &[u8], now: i64) -> Vec<i64> {
    let mut out = INSTANTS.to_vec();
    let Ok(l) = Location::from_tzdata(data, now) else {
        return out;
    };
    let mut edge = |s: i64| out.extend([s.wrapping_sub(1), s, s.wrapping_add(1)]);
    for t in &l.tx {
        edge(t.when);
    }
    let mut s = l.tx.last().map_or(0, |t| t.when).max(-(1 << 31));
    for _ in 0..24 {
        let span = l.lookup(s);
        if span.end == OMEGA || span.end <= s {
            break;
        }
        edge(span.end);
        s = span.end;
    }
    out
}

/// Every file under `dir`, symbolic links to files included, in order.
fn files_under(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            files_under(&path, out);
        } else if path.is_file() {
            out.push(path);
        }
    }
}

/// Go's `LoadLocationFromTZData` against this reader on every file of
/// the host's zone database, where it has one, and on the synthetic
/// zones: the offsets at every transition, a second either side, and
/// the footer's first spans, or the error, byte for byte.
#[test]
fn tzif_offsets_match_go() {
    let Some(mut oracle) = dcroxide_testutil::oracle_or_skip() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    #[cfg(unix)]
    files.extend(synthetic_zones(dir.path()).into_iter().map(|(_, p)| p));
    #[cfg(not(unix))]
    {
        let p = dir.path().join("slim");
        std::fs::write(&p, tzif_file(b'2', &[], &[(0, false)], b"\nEST5EDT\n")).expect("write");
        files.push(p);
    }
    let sys = std::path::Path::new("/usr/share/zoneinfo");
    let mut system = Vec::new();
    files_under(sys, &mut system);
    system.sort();
    if system.is_empty() {
        eprintln!(
            "skipping the system zone files: {} holds none on this host",
            sys.display()
        );
    }
    files.extend(system);

    let now = now();
    let mut mismatches = Vec::new();
    let mut probed = 0;
    for path in &files {
        let data = std::fs::read(path).expect("read a zone file");
        let instants = probe_instants(&data, now);
        let mut request = Vec::with_capacity(4 + data.len() + 8 * instants.len());
        request.extend_from_slice(&u32::try_from(data.len()).expect("fits").to_be_bytes());
        request.extend_from_slice(&data);
        for s in &instants {
            request.extend_from_slice(&s.to_be_bytes());
        }
        let go = oracle.call_ok("tzif_offsets", &request);
        let ours = match Location::from_tzdata(&data, now) {
            Ok(l) => offsets(&l, &instants)
                .iter()
                .map(i64::to_string)
                .collect::<Vec<_>>()
                .join(","),
            Err(e) => format!("err {e}"),
        };
        if ours != go {
            mismatches.push(path.display().to_string());
        }
        probed += instants.len();
    }
    eprintln!(
        "{} zone files compared with Go at {probed} instants",
        files.len()
    );
    assert!(
        mismatches.is_empty(),
        "{} of {} files differ from Go: {:?}",
        mismatches.len(),
        files.len(),
        &mismatches[..mismatches.len().min(20)]
    );
}
