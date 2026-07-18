// SPDX-License-Identifier: ISC
//! Inbound connection rate limiting with flood detection (dcrd
//! `internal/connmgr` `inboundRateLimiter`, new in dcrd 2.2's
//! connection manager rewrite).
//!
//! The first line of defense against inbound attacks: a token bucket
//! per inbound network group (individual IPv4 addresses and typical
//! residential IPv6 blocks under normal conditions, dynamically
//! coarsened to /24 and /56 while flooding is active), a sliding
//! one-minute window of allowed attempts driving the flood state, an
//! S-curve probabilistic drop under active flooding, and rate-limited
//! logging of dropped connections.
//!
//! Divergences per the port's conventions: the wall clock is an
//! explicit argument (dcrd reads `time.Now`), dcrd's mutexes are
//! omitted (the manager serializes access), the `time.AfterFunc`
//! scheduling the suppression summary becomes a timer request the
//! daemon drives ([`LogDropsOutcome::SuppressionStarted`] →
//! [`InboundRateLimiter::finish_suppression`]), and dcrd's shared
//! `*ratelimit.Limiter` values become by-value entries mutated
//! between the LRU get and the unconditional TTL-refreshing put —
//! the same recency operations and post-`Allow` stored state as
//! dcrd's get-put-allow order over a shared pointer.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use dcroxide_addrmgr::{NetAddress, NetAddressType};
use dcroxide_containers::lru;
use dcroxide_ratelimit::Limiter;

use crate::csprng::Csprng;

/// The maximum number of inbound group limiters to cache (dcrd
/// `maxGroupLimiters`).
pub const MAX_GROUP_LIMITERS: u32 = 10000;

/// The time to keep each inbound rate limiter in the cache without
/// access before expiry, in nanoseconds (dcrd `maxPerGroupTTL`).
pub const MAX_PER_GROUP_TTL: i64 = 20 * 60 * 1_000_000_000;

/// The inbound rate limit per network group (dcrd `groupRateLimit`):
/// an average of one connection per five seconds.
pub const GROUP_RATE_LIMIT: f64 = 0.2;

/// The burst size for the per-group limiters (dcrd
/// `groupBurstLimit`).
pub const GROUP_BURST_LIMIT: u32 = 3;

/// The dropped-connection log rate (dcrd `dropLogRateLimit`): an
/// average of one per minute.
pub const DROP_LOG_RATE_LIMIT: f64 = 1.0 / 60.0;

/// The dropped-connection log burst size (dcrd `dropLogBurstLimit`).
pub const DROP_LOG_BURST_LIMIT: u32 = 4;

/// The allowed connection attempts in the last minute that constitute
/// active low-intensity flooding (dcrd `floodLow`).
pub const FLOOD_LOW: u64 = 5 * 60;

/// The multiple of [`FLOOD_LOW`] setting the width of the ramp over
/// which the drop probability scales (dcrd `floodHighFactor`).
pub const FLOOD_HIGH_FACTOR: u64 = 3;

/// The minimum probability of dropping a connection during active
/// flooding (dcrd `floodMinDropProb`).
pub const FLOOD_MIN_DROP_PROB: f64 = 0.2;

/// The maximum probability of dropping a connection during active
/// flooding (dcrd `floodMaxDropProb`).
pub const FLOOD_MAX_DROP_PROB: f64 = 0.85;

/// The normalized intensity to start rapid growth of the drop
/// probability (dcrd `floodRamp`).
pub const FLOOD_RAMP: f64 = 0.1;

/// An inbound network group key (dcrd `inboundGroupKey`): the
/// SipHash-2-4 128-bit digest of the group preimage under the
/// instance key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InboundGroupKey {
    /// The first digest half (dcrd `hash0`).
    pub hash0: u64,
    /// The second digest half (dcrd `hash1`).
    pub hash1: u64,
}

/// The outcome of [`InboundRateLimiter::log_drops`], carrying what
/// dcrd logs directly and the timer dcrd schedules via
/// `time.AfterFunc`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogDropsOutcome {
    /// Log the drop: dcrd `"Dropped connection from %v: %v"` with the
    /// address and reason.
    Logged,
    /// The log rate was just exceeded: dcrd logs `"Dropped connection
    /// from %v: %v -- suppressing drop logs for %v"` with the wait
    /// rounded to the nearest second, and schedules
    /// [`InboundRateLimiter::finish_suppression`] after the
    /// unrounded wait.
    SuppressionStarted {
        /// Nanoseconds until logging is allowed again (the timer the
        /// daemon must arm).
        reset_after_nanos: i64,
    },
    /// The drop was tallied while suppression is active; nothing is
    /// logged.
    Suppressed,
}

/// State related to rate limiting inbound connections and flood
/// detection (dcrd `inboundRateLimiter`).
pub struct InboundRateLimiter {
    /// The max burst size for the group rate limiters (dcrd
    /// `burstLimit`).
    burst_limit: u32,
    /// The per-instance SipHash key for group derivation (dcrd
    /// `key`).
    key: [u64; 2],
    /// Distinct rate limiters per inbound group up to the LRU
    /// capacity (dcrd `groupLimiters`).
    group_limiters: lru::Map<InboundGroupKey, Limiter>,
    /// The nanosecond clock cell driving the LRU's TTL expiry,
    /// refreshed from the explicit clock arguments.
    lru_clock: Arc<AtomicI64>,
    /// A sliding window of the allowed connections per second over
    /// the previous minute, as a ring buffer (dcrd `attempts`).
    attempts: [u32; 60],
    /// The unix time of the head of the ring buffer (dcrd
    /// `attemptsStart`).
    attempts_start: i64,
    /// The sum of all attempts in the window (dcrd `totalAttempts`).
    total_attempts: u64,
    /// Whether flooding mode is active (dcrd `flooding`).
    flooding: bool,
    /// Rate limiting for logging of dropped connections (dcrd
    /// `logLimiter`).
    log_limiter: Limiter,
    /// The number of dropped connections tallied during log
    /// suppression (dcrd `droppedLogs`).
    dropped_logs: u64,
}

impl InboundRateLimiter {
    /// An initialized instance keyed from the provided CSPRNG (dcrd
    /// `newInboundRateLimiter`).
    pub fn new(csprng: &mut dyn Csprng) -> InboundRateLimiter {
        InboundRateLimiter::with_key_and_capacity(
            [csprng.uint64(), csprng.uint64()],
            MAX_GROUP_LIMITERS,
        )
    }

    /// An instance with an explicit key and LRU capacity, for the
    /// differential tests (eviction is only reachable with a lowered
    /// capacity).
    #[doc(hidden)]
    pub fn with_key_and_capacity(key: [u64; 2], capacity: u32) -> InboundRateLimiter {
        let lru_clock = Arc::new(AtomicI64::new(0));
        let clock = Arc::clone(&lru_clock);
        InboundRateLimiter {
            burst_limit: GROUP_BURST_LIMIT,
            key,
            group_limiters: lru::Map::new_with_default_ttl_and_clock(
                capacity,
                MAX_PER_GROUP_TTL,
                Arc::new(move || clock.load(Ordering::Relaxed)),
            ),
            lru_clock,
            attempts: [0; 60],
            attempts_start: 0,
            total_attempts: 0,
            flooding: false,
            log_limiter: Limiter::new(DROP_LOG_RATE_LIMIT, DROP_LOG_BURST_LIMIT),
            dropped_logs: 0,
        }
    }

    /// The inbound network group key for the address (dcrd
    /// `inboundRateLimiter.GroupKey`): the SipHash-2-4 128 of the
    /// prefix-based preimage — full-address groups normally,
    /// coarsened to /24 (IPv4) and /56 (IPv6) while flooding.
    pub fn group_key(&self, addr: &NetAddress) -> InboundGroupKey {
        let mut preimage_buf = [0u8; 16];
        let preimage: &[u8] = match addr.addr_type {
            NetAddressType::IPv4 => {
                let bits = if self.flooding { 24 } else { 32 };
                preimage_buf[..4].copy_from_slice(&addr.ip[..4]);
                mask_prefix(&mut preimage_buf[..4], bits);
                &preimage_buf[..4]
            }
            NetAddressType::IPv6 => {
                let bits = if self.flooding { 56 } else { 64 };
                preimage_buf.copy_from_slice(&addr.ip[..16]);
                mask_prefix(&mut preimage_buf, bits);
                &preimage_buf
            }
            // Remote addresses for inbound connections are never Tor
            // addresses, but dcrd treats them all as a single group
            // anyway, and groups unknown or future types together.
            NetAddressType::TorV3 => b"tor",
            NetAddressType::Unknown => b"unknown",
        };
        use std::hash::Hasher;
        let mut hasher = siphasher::sip128::SipHasher24::new_with_keys(self.key[0], self.key[1]);
        hasher.write(preimage);
        let digest = siphasher::sip128::Hasher128::finish128(&hasher);
        InboundGroupKey {
            hash0: digest.h1,
            hash1: digest.h2,
        }
    }

    /// Decay stale flood-window data and record attempts that were
    /// not rate limited by prefix (dcrd `recordAttempt`); the flood
    /// window is a one-minute sliding window over one-second buckets.
    #[allow(clippy::arithmetic_side_effects)]
    fn record_attempt(&mut self, rate_limited: bool, now_unix: i64) {
        const BUCKETS: i64 = 60;

        let idx = usize::try_from(now_unix % BUCKETS).expect("pre-epoch clock");

        // Advance the sliding window to the current time; a backwards
        // clock (negative expiry) intentionally only moves the head.
        if self.attempts_start != now_unix {
            let num_expired = now_unix - self.attempts_start;
            if num_expired >= BUCKETS {
                self.attempts = [0; 60];
                self.total_attempts = 0;
            } else if num_expired > 0 {
                let tail = self.attempts_start + 1;
                for i in 0..num_expired {
                    let old_idx = usize::try_from((tail + i) % BUCKETS).expect("pre-epoch clock");
                    self.total_attempts = self
                        .total_attempts
                        .wrapping_sub(u64::from(self.attempts[old_idx]));
                    self.attempts[old_idx] = 0;
                }
            }
            self.attempts_start = now_unix;
        }

        // Record allowed attempts.
        if !rate_limited {
            self.attempts[idx] = self.attempts[idx].wrapping_add(1);
            self.total_attempts = self.total_attempts.wrapping_add(1);
        }

        // Activate flooding mode if there have been enough recent
        // allowed attempts in the last minute; deactivate otherwise.
        self.flooding = self.total_attempts > FLOOD_LOW;
    }

    /// Whether an inbound connection from the address is permitted at
    /// the current time, updating the per-group limiter and the flood
    /// state (dcrd `inboundRateLimiter.Allow`).  `now_unix` is the
    /// wall clock in seconds and `now_nanos` the same instant in
    /// nanoseconds (dcrd reads `time.Now` for both).
    pub fn allow(&mut self, addr: &NetAddress, now_unix: i64, now_nanos: i64) -> bool {
        self.lru_clock.store(now_nanos, Ordering::Relaxed);

        // Either get an existing rate limiter or create a new one,
        // consume from it, and put it back unconditionally so its TTL
        // is updated.  Adding a new entry may evict another limiter
        // when at max capacity.
        let group_key = self.group_key(addr);
        let mut limiter = match self.group_limiters.get(&group_key) {
            Some(limiter) => limiter,
            None => Limiter::new(GROUP_RATE_LIMIT, self.burst_limit),
        };
        let allowed = limiter.allow(now_nanos);
        self.group_limiters.put(group_key, limiter);

        // Tally attempts that were not rate limited and periodically
        // update the state related to detecting active flooding.
        self.record_attempt(!allowed, now_unix);

        allowed
    }

    /// Whether a connection should be probabilistically dropped (dcrd
    /// `ShouldDropProbabilistic`): nothing is dropped unless active
    /// flooding is detected, and the drop probability scales with the
    /// flood intensity per a quadratic rational S-curve.
    pub fn should_drop_probabilistic(&self, csprng: &mut dyn Csprng) -> bool {
        if !self.flooding {
            return false;
        }
        let total_attempts = self.total_attempts;

        // P(x) = minP + (1+r)*(maxP-minP)*x^2 / (r+x^2) with x the
        // normalized flood intensity in [0, 1] and r the normalized
        // intensity to start rapid growth.
        //
        // dcrd folds (1+floodRamp)*(floodMaxDropProb-floodMinDropProb)
        // as an untyped Go constant in exact arithmetic — 1.1 * 0.65
        // = 0.715 — so the port uses the folded literal rather than
        // trusting runtime f64 rounding to coincide.
        const FACTOR: f64 = 0.715;
        const RAMP_WIDTH: u64 = FLOOD_LOW * FLOOD_HIGH_FACTOR;
        let mut norm =
            (total_attempts.max(FLOOD_LOW).wrapping_sub(FLOOD_LOW)) as f64 / RAMP_WIDTH as f64;
        norm = norm.min(1.0);
        let n_squared = norm * norm;
        let prob = FLOOD_MIN_DROP_PROB + FACTOR * n_squared / (FLOOD_RAMP + n_squared);

        csprng.float64() < prob
    }

    /// Record a dropped connection for logging with throttling (dcrd
    /// `LogDrops`): the caller logs per the returned outcome and arms
    /// the suppression-reset timer when one starts.
    pub fn log_drops(&mut self, now_nanos: i64) -> LogDropsOutcome {
        if !self.log_limiter.allow(now_nanos) {
            let outcome = if self.dropped_logs == 0 {
                LogDropsOutcome::SuppressionStarted {
                    reset_after_nanos: self.log_limiter.until_next_allowed(now_nanos),
                }
            } else {
                LogDropsOutcome::Suppressed
            };
            self.dropped_logs = self.dropped_logs.wrapping_add(1);
            return outcome;
        }
        LogDropsOutcome::Logged
    }

    /// Reset the suppression state when the daemon's reset timer
    /// fires (the body of dcrd's `time.AfterFunc` callback),
    /// returning the count to summarize — dcrd logs `"Dropped %d
    /// connection(s) while suppressed"` when it is nonzero, after
    /// discounting the initial message that triggered suppression.
    pub fn finish_suppression(&mut self) -> Option<u64> {
        let dropped = self.dropped_logs;
        self.dropped_logs = 0;
        if dropped > 1 {
            return Some(dropped.wrapping_sub(1));
        }
        None
    }

    /// Whether flooding mode is currently active.
    pub fn flooding(&self) -> bool {
        self.flooding
    }

    /// Force the flood-window state, for the differential tests.
    #[doc(hidden)]
    pub fn force_flood_state(
        &mut self,
        attempts_start: i64,
        entries: &[(usize, u32)],
        total: u64,
        flooding: bool,
    ) {
        self.attempts = [0; 60];
        for &(idx, val) in entries {
            self.attempts[idx] = val;
        }
        self.attempts_start = attempts_start;
        self.total_attempts = total;
        self.flooding = flooding;
    }

    /// Drive `record_attempt` directly, for the differential tests.
    #[doc(hidden)]
    pub fn record_attempt_probe(&mut self, rate_limited: bool, now_unix: i64) {
        self.record_attempt(rate_limited, now_unix);
    }

    /// The nonzero window buckets with the head time, total, and
    /// flood flag, for the differential tests.
    #[doc(hidden)]
    pub fn window_snapshot(&self) -> (i64, Vec<(usize, u32)>, u64, bool) {
        let nonzero: Vec<(usize, u32)> = self
            .attempts
            .iter()
            .enumerate()
            .filter(|(_, v)| **v != 0)
            .map(|(i, v)| (i, *v))
            .collect();
        (
            self.attempts_start,
            nonzero,
            self.total_attempts,
            self.flooding,
        )
    }

    /// The `(attempts_start, total_attempts, flooding, group count)`
    /// state, for the differential tests.
    #[doc(hidden)]
    pub fn flood_state_snapshot(&self) -> (i64, u64, bool, u32) {
        (
            self.attempts_start,
            self.total_attempts,
            self.flooding,
            self.group_limiters.len(),
        )
    }
}

/// Zero every bit past the leading `bits` in place (the masking Go
/// performs via `netip.Addr.Prefix`).
// `partial` is in [1, 7] where used, so the shift and the +1 offset
// cannot overflow.
#[allow(clippy::arithmetic_side_effects)]
fn mask_prefix(bytes: &mut [u8], bits: usize) {
    let full = bits / 8;
    let partial = bits % 8;
    if full < bytes.len() && partial != 0 {
        bytes[full] &= 0xffu8 << (8 - partial);
    }
    let start = full + usize::from(partial != 0);
    for b in bytes.iter_mut().skip(start) {
        *b = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The prefix masks dcrd derives via `netip.Addr.Prefix`.
    #[test]
    fn mask_prefix_matches_netip() {
        let mut v4 = [203, 0, 113, 77];
        mask_prefix(&mut v4, 32);
        assert_eq!(v4, [203, 0, 113, 77]);
        let mut v4 = [203, 0, 113, 77];
        mask_prefix(&mut v4, 24);
        assert_eq!(v4, [203, 0, 113, 0]);
        let mut v6 = [
            0x20, 0x01, 0x0d, 0xb8, 0xaa, 0xbb, 0xcc, 0xdd, 1, 2, 3, 4, 5, 6, 7, 8,
        ];
        mask_prefix(&mut v6, 64);
        assert_eq!(
            v6,
            [
                0x20, 0x01, 0x0d, 0xb8, 0xaa, 0xbb, 0xcc, 0xdd, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
        let mut v6 = [
            0x20, 0x01, 0x0d, 0xb8, 0xaa, 0xbb, 0xcc, 0xdd, 1, 2, 3, 4, 5, 6, 7, 8,
        ];
        mask_prefix(&mut v6, 56);
        assert_eq!(
            v6,
            [
                0x20, 0x01, 0x0d, 0xb8, 0xaa, 0xbb, 0xcc, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
        // Non-byte-aligned widths mask the partial byte's low bits.
        let mut v4 = [0xff, 0xff, 0xff, 0xff];
        mask_prefix(&mut v4, 21);
        assert_eq!(v4, [0xff, 0xff, 0xf8, 0x00]);
    }

    /// The flood threshold is strictly greater-than (dcrd
    /// `totalAttempts > floodLow`).
    #[test]
    fn flood_threshold_edge() {
        let mut l = InboundRateLimiter::with_key_and_capacity([1, 2], 16);
        l.attempts_start = 1_700_000_000;
        l.total_attempts = FLOOD_LOW;
        l.record_attempt(true, 1_700_000_000);
        assert!(!l.flooding, "at the threshold is not flooding");
        l.record_attempt(false, 1_700_000_000);
        assert!(l.flooding, "one past the threshold floods");
    }

    /// The S-curve factor literal is the f64 nearest Go's exact
    /// constant folding of 1.1 * 0.65 = 0.715.
    #[test]
    fn s_curve_factor_is_go_const_folded() {
        assert_eq!(0.715f64.to_bits(), 0x3fe6e147ae147ae1);
    }
}
