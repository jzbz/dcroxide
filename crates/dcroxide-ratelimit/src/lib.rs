// SPDX-License-Identifier: ISC
//! Token bucket rate limiter mirroring dcrd's `internal/ratelimit`
//! (new in dcrd 2.2, consumed by the connection manager's inbound
//! anti-flood machinery).
//!
//! The bucket starts with `burst` tokens and refills at `rate` tokens
//! per second; an event is allowed while at least one token remains
//! at the time of the event.  All bucket arithmetic is `f64` and
//! reproduces dcrd's operations in dcrd's order — including
//! `time.Duration.Seconds()`'s whole-second/nanosecond split — so the
//! token counts drift bit-for-bit with dcrd's (the differential
//! vectors pin cases where accumulated rounding error denies an event
//! dcrd's documented average rate would allow).
//!
//! Divergences from dcrd, per the port's conventions:
//!
//! - dcrd reads `time.Now` through a struct-embedded `nowFn`; the
//!   port takes an explicit monotonic `now_nanos` argument on every
//!   time-dependent call, like the rest of the workspace.
//! - dcrd guards the limiter with an embedded mutex; the port is a
//!   plain single-threaded core and consumers that share a limiter
//!   across threads wrap it themselves.
//! - dcrd's zero-value `updated` is Go's zero `time.Time`, whose
//!   refill interval saturates at `math.MaxInt64` nanoseconds for
//!   every time representable in the port's nanosecond domain; the
//!   port seeds `updated` with an `i64::MIN` sentinel and yields
//!   that saturated interval whenever the sentinel is in place —
//!   including after an `allow` at the sentinel value itself, which
//!   dcrd likewise cannot distinguish from the initial state.
//! - dcrd's overflow guard converts the candidate duration with Go's
//!   platform-defined `uint64(float64)`; the port pins the behavior
//!   of the oracle platform (amd64) — finite candidates truncate
//!   identically, and `+Inf` and NaN candidates (from subnormal,
//!   infinite, or NaN rates) return [`FOREVER`] as dcrd on amd64
//!   does.  dcrd on arm64 returns 0 for the NaN case; Go itself is
//!   split by platform there.

/// An infinite duration in nanoseconds (dcrd `ratelimit.Forever`).
pub const FOREVER: i64 = i64::MAX;

/// The number of tokens that refill over `d` nanoseconds at `rate`
/// tokens per second (dcrd `durationToTokens`), computed with Go's
/// `Duration.Seconds()` split of whole seconds and remainder
/// nanoseconds.
fn duration_to_tokens(d: i64, rate: f64) -> f64 {
    if rate <= 0.0 {
        return 0.0;
    }
    let sec = d / 1_000_000_000;
    let nsec = d % 1_000_000_000;
    (sec as f64 + nsec as f64 / 1e9) * rate
}

/// The duration the provided number of tokens takes to refill at
/// `rate` tokens per second (dcrd `tokensToDuration`), [`FOREVER`]
/// when the rate is non-positive or the result overflows an `i64`
/// nanosecond count.
fn tokens_to_duration(tokens: f64, rate: f64) -> i64 {
    if rate <= 0.0 {
        return FOREVER;
    }
    let duration = (tokens / rate) * 1e9;
    // Go's `uint64(duration)` here is platform-defined for NaN: amd64
    // yields 2^63 and fires the guard, arm64 yields 0 and falls
    // through to a zero duration.  The port pins the oracle platform
    // (amd64), so a NaN candidate returns [`FOREVER`].
    if duration.is_nan() || duration as u64 >= i64::MAX as u64 {
        return FOREVER;
    }
    duration as i64
}

/// A token bucket rate limiter (dcrd `ratelimit.Limiter`).
///
/// The limiter is aimed at callers that drop events exceeding the
/// rate: process the event when [`Limiter::allow`] reports true and
/// drop it otherwise.  Callers that wish to wait instead can use
/// [`Limiter::until_next_allowed`] to learn how long.
#[derive(Debug, Clone)]
pub struct Limiter {
    /// The number of events to allow per second.
    rate: f64,
    /// The maximum amount of tokens, permitting rapid bursts.
    burst: f64,
    /// The remaining tokens; events are permitted while it is
    /// greater than zero.
    tokens: f64,
    /// The monotonic nanosecond time `tokens` was last updated;
    /// `i64::MIN` stands in for dcrd's zero `time.Time`.
    updated: i64,
}

impl Limiter {
    /// A limiter allowing events up to `rate` events per second with
    /// bursts up to `burst` events (dcrd `ratelimit.New`).
    ///
    /// To rate limit events to every X seconds (versus X events per
    /// second), scale the rate by 1/X: 15 events per minute is a rate
    /// of 0.25, and 450 events every 2 hours is 450/(2*3600) = 0.0625.
    pub fn new(rate: f64, burst: u32) -> Limiter {
        Limiter {
            rate,
            burst: f64::from(burst),
            tokens: f64::from(burst),
            updated: i64::MIN,
        }
    }

    /// The burst size the limiter was created with (dcrd
    /// `Limiter.Burst`).
    pub fn burst(&self) -> u32 {
        self.burst as u32
    }

    /// The number of available tokens at time `t`, capped at the
    /// burst size; times prior to the last update return the current
    /// token count unchanged (dcrd `Limiter.tokensAt`).
    fn tokens_at(&self, t: i64) -> f64 {
        let mut updated = self.updated;
        if t < updated {
            updated = t;
        }
        // dcrd's zero-`time.Time` stamp is ~2026 years before any
        // representable `t`, so its interval is Go's saturated
        // `maxDuration` for every `t`; the sentinel reproduces that
        // unconditionally (plain saturating subtraction would compute
        // an exact — unsaturated — interval for negative `t`).
        let elapsed = if updated == i64::MIN {
            i64::MAX
        } else {
            t.saturating_sub(updated)
        };
        let delta = duration_to_tokens(elapsed, self.rate);
        let mut num_tokens = self.tokens + delta;
        if num_tokens > self.burst {
            num_tokens = self.burst;
        }
        num_tokens
    }

    /// The number of available tokens at `now_nanos` (dcrd
    /// `Limiter.Tokens`).
    pub fn tokens(&self, now_nanos: i64) -> f64 {
        self.tokens_at(now_nanos)
    }

    /// Whether an event is allowed at `now_nanos`, consuming a token
    /// when it is (dcrd `Limiter.Allow`).
    pub fn allow(&mut self, now_nanos: i64) -> bool {
        let mut tokens = self.tokens_at(now_nanos);
        tokens -= 1.0;

        if tokens >= 0.0 && tokens <= self.burst {
            self.updated = now_nanos;
            self.tokens = tokens;
            return true;
        }
        false
    }

    /// The duration in nanoseconds until the next event is allowed,
    /// [`FOREVER`] when no more events ever will be — such as a
    /// non-positive rate with an empty bucket or a burst size of zero
    /// (dcrd `Limiter.UntilNextAllowed`).
    pub fn until_next_allowed(&self, now_nanos: i64) -> i64 {
        // Events are never allowed with a burst size of 0.
        if self.burst == 0.0 {
            return FOREVER;
        }
        let tokens = self.tokens_at(now_nanos);

        // The next event is not allowed until there is at least one
        // token, so determine how much is needed to reach one.
        let needed = 1.0 - tokens;
        if needed <= 0.0 {
            // There is already one or more tokens available.
            return 0;
        }

        // Convert the needed tokens into a duration based on the rate.
        tokens_to_duration(needed, self.rate)
    }

    /// The raw `(tokens, updated)` state, for differential tests.
    #[doc(hidden)]
    pub fn tokens_updated_snapshot(&self) -> (f64, i64) {
        (self.tokens, self.updated)
    }
}
