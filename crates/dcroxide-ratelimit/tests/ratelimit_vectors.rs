// SPDX-License-Identifier: ISC
//! Differential replay of dcrd `internal/ratelimit` behavior vectors.
//!
//! The vectors were dumped by a throwaway exporter test run inside
//! the dcrd clone at master 452c1a6c (the 2.2 parity target) with a
//! scripted `nowFn`; every row records dcrd's exact result — token
//! counts as raw `f64` bits — so the replay asserts bit-for-bit
//! parity of the bucket arithmetic, including the accumulated
//! rounding drift and the `UntilNextAllowed` overflow guard.

use dcroxide_ratelimit::{FOREVER, Limiter};

#[test]
fn dcrd_ratelimit_vectors() {
    let data = include_str!("data/ratelimit_vectors.txt");

    let mut limiter: Option<Limiter> = None;
    let mut scenario = String::new();
    let mut rows = 0usize;
    for (lineno, line) in data.lines().enumerate() {
        let lineno = lineno + 1;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split('|').collect();
        match fields[0] {
            "scenario" => {
                scenario = fields[1].to_string();
                let rate = f64::from_bits(u64::from_str_radix(fields[2], 16).expect("rate bits"));
                let burst: u32 = fields[3].parse().expect("burst");
                limiter = Some(Limiter::new(rate, burst));
            }
            "burstv" => {
                let want: u32 = fields[2].parse().expect("burst value");
                let l = limiter.as_ref().expect("scenario first");
                assert_eq!(l.burst(), want, "{scenario} line {lineno}: burst");
            }
            "tokens" => {
                let now: i64 = fields[1].parse().expect("now");
                let want = u64::from_str_radix(fields[2], 16).expect("tokens bits");
                let l = limiter.as_ref().expect("scenario first");
                let got = l.tokens(now).to_bits();
                assert_eq!(
                    got, want,
                    "{scenario} line {lineno}: tokens({now}) bits \
                     {got:016x} != {want:016x}"
                );
                rows += 1;
            }
            "allow" => {
                let now: i64 = fields[1].parse().expect("now");
                let want: bool = fields[2].parse().expect("allow result");
                let want_tokens = u64::from_str_radix(fields[3], 16).expect("state bits");
                let want_updated = fields[4];
                let l = limiter.as_mut().expect("scenario first");
                let got = l.allow(now);
                assert_eq!(got, want, "{scenario} line {lineno}: allow({now})");
                let (tokens, updated) = l.tokens_updated_snapshot();
                assert_eq!(
                    tokens.to_bits(),
                    want_tokens,
                    "{scenario} line {lineno}: post-allow tokens"
                );
                match want_updated {
                    "zero" => assert_eq!(
                        updated,
                        i64::MIN,
                        "{scenario} line {lineno}: updated still zero"
                    ),
                    ns => assert_eq!(
                        updated,
                        ns.parse::<i64>().expect("updated ns"),
                        "{scenario} line {lineno}: updated"
                    ),
                }
                rows += 1;
            }
            "until" => {
                let now: i64 = fields[1].parse().expect("now");
                let want: i64 = fields[2].parse().expect("until");
                let l = limiter.as_ref().expect("scenario first");
                let got = l.until_next_allowed(now);
                assert_eq!(
                    got, want,
                    "{scenario} line {lineno}: until_next_allowed({now})"
                );
                rows += 1;
            }
            other => panic!("line {lineno}: unknown op {other}"),
        }
    }
    assert!(rows > 100, "suspiciously few vector rows: {rows}");
}

/// The `FOREVER` sentinel matches dcrd's `Forever` (`math.MaxInt64`).
#[test]
fn forever_is_max_int64() {
    assert_eq!(FOREVER, i64::MAX);
    assert_eq!(FOREVER, 9223372036854775807);
}

/// The zero-time sentinel stays saturated even when an `allow` at the
/// sentinel value itself stores it as a real stamp, and even for
/// clock values before the epoch.
///
/// The scripted-clock exporter cannot reach this corner (Go's zero
/// `time.Time` is ~year 1, outside any base + `i64` nanosecond
/// offset), so the expected bits come from probing dcrd's package
/// directly on the oracle platform: `Allow` with `nowFn` pinned to
/// the zero `time.Time` — which Go cannot distinguish from the
/// never-updated state — followed by `Tokens` at one second short of
/// `math.MinInt64` nanoseconds before the wall base, yielding
/// 1.9223372036854776 (`0x3ffec1e4a7db6956`): the `maxDuration`
/// refill on a bucket holding burst−1.
#[test]
fn sentinel_saturates_after_allow_at_sentinel() {
    let mut l = Limiter::new(1e-10, 2);
    assert!(l.allow(i64::MIN));
    let (tokens, updated) = l.tokens_updated_snapshot();
    assert_eq!(tokens.to_bits(), 1.0f64.to_bits());
    assert_eq!(updated, i64::MIN);
    let got = l.tokens(-1_000_000_000_000_000_000);
    assert_eq!(got.to_bits(), 0x3ffec1e4a7db6956);
    assert_eq!(got, 1.9223372036854776);

    // A fresh limiter's pre-epoch reads stay capped at the burst.
    let l = Limiter::new(1e-10, 2);
    assert_eq!(l.tokens(-5).to_bits(), 2.0f64.to_bits());
    assert_eq!(
        l.tokens(-1_000_000_000_000_000_000).to_bits(),
        2.0f64.to_bits()
    );
}
