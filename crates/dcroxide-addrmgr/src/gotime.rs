// SPDX-License-Identifier: ISC
//! Go's `time.Time` as the address manager's attempt and success times
//! and the outbound pick's recency test use it: a wall-clock reading
//! and, for a time `time.Now` took in this process, the monotonic
//! reading Go attaches to it.
//!
//! dcrd stamps `lastattempt` and `lastsuccess` with `time.Now()` and
//! tests them against `time.Now()` (`time.Since`, `After` over
//! `now.Add`, `lastTry.Add(10*time.Minute).After(now)` in
//! `pickOutboundAddr`).  Go compares and subtracts two times by their
//! monotonic readings when both carry one, so for an address attempted
//! in this process those tests measure running time, and a wall-clock
//! step moves none of them.  A time loaded from `peers.json`
//! (`time.Unix`) has no monotonic reading and is tested on the wall
//! clock, in dcrd as here.

/// A reading of the process's monotonic clock in nanoseconds, the
/// reading Go's `time.Now` attaches.  The origin is this function's
/// first call: only differences between its values mean anything, and
/// they never mix with wall-clock nanoseconds.  `dcroxide-connmgr`'s
/// `monotonic_nanos` is this clock, so the two crates' readings share
/// one origin.
pub fn monotonic_nanos() -> i64 {
    static ORIGIN: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let origin = *ORIGIN.get_or_init(std::time::Instant::now);
    i64::try_from(origin.elapsed().as_nanos()).unwrap_or(i64::MAX)
}

/// A Go `time.Time`: Unix nanoseconds, and the monotonic reading
/// ([`monotonic_nanos`]) when `time.Now` took it in this process.  The
/// default is the port's rendering of Go's zero time for an address
/// that was never attempted: the wall clock's 0 with no monotonic
/// reading, which every recency test finds long past, as it finds the
/// zero time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GoTime {
    /// The wall-clock reading in Unix nanoseconds.
    pub wall: i64,
    /// The monotonic reading, which only a time taken in this process
    /// carries.
    pub mono: Option<i64>,
}

impl GoTime {
    /// A time with only a wall-clock reading (Go's `time.Unix`).
    pub fn wall(wall: i64) -> GoTime {
        GoTime { wall, mono: None }
    }

    /// The current time with both readings (Go's `time.Now`).
    pub fn now() -> GoTime {
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or_default();
        GoTime {
            wall,
            mono: Some(monotonic_nanos()),
        }
    }

    /// The time plus `nanos` (Go's `Time.Add`), dropping the monotonic
    /// reading where Go does, when adding to it would overflow.
    pub fn add_nanos(self, nanos: i64) -> GoTime {
        GoTime {
            wall: self.wall.saturating_add(nanos),
            mono: self.mono.and_then(|mono| mono.checked_add(nanos)),
        }
    }

    /// Whether the time is after `u` (Go's `Time.After`): by the
    /// monotonic readings when both have one, otherwise by the wall
    /// clock.
    pub fn after(self, u: GoTime) -> bool {
        match (self.mono, u.mono) {
            (Some(t), Some(u)) => t > u,
            _ => self.wall > u.wall,
        }
    }

    /// The duration `self - u` in nanoseconds (Go's `Time.Sub`), by the
    /// monotonic readings when both have one, otherwise by the wall
    /// clock; saturating, as Go's is.
    pub fn duration_since(self, u: GoTime) -> i64 {
        match (self.mono, u.mono) {
            (Some(t), Some(u)) => t.saturating_sub(u),
            _ => self.wall.saturating_sub(u.wall),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two readings `time.Now` took compare by their monotonic parts, so
    /// a wall-clock step between them changes nothing; a wall-only time
    /// on either side falls back to the wall clock.
    #[test]
    fn go_time_compares_as_go_does() {
        let earlier = GoTime {
            wall: 1_000,
            mono: Some(10),
        };
        // The wall clock stepped back between the two readings.
        let later = GoTime {
            wall: 500,
            mono: Some(20),
        };
        assert!(later.after(earlier));
        assert_eq!(later.duration_since(earlier), 10);
        assert!(!GoTime::wall(later.wall).after(earlier));
        assert_eq!(GoTime::wall(later.wall).duration_since(earlier), -500);
        assert_eq!(later.add_nanos(-15).mono, Some(5));
        assert_eq!(later.add_nanos(-15).wall, 485);
        assert_eq!(
            GoTime {
                wall: 0,
                mono: Some(i64::MAX)
            }
            .add_nanos(1)
            .mono,
            None
        );
        assert_eq!(GoTime::default(), GoTime::wall(0));
    }

    #[test]
    fn monotonic_nanos_is_nondecreasing() {
        let a = monotonic_nanos();
        let b = monotonic_nanos();
        assert!(a >= 0 && b >= a);
    }
}
