// SPDX-License-Identifier: ISC
//! The median-adjusted network time (dcrd
//! `internal/blockchain/mediantime.go`): the clock offset taken from the
//! timestamps connected peers report in their version messages, which
//! dcrd's consensus and sync checks read through `AdjustedTime`.
//!
//! dcrd builds one `blockchain.NewMedianTime()` per server
//! (`server.timeSource`), feeds it from `serverPeer.OnVersion`, and hands
//! the same source to the chain, the sync manager, the template
//! generator, and the RPC server.  The daemon is one server per process,
//! so the source is a process-wide instance ([`server_time_source`])
//! that every adjusted-time seam reads.

use std::collections::{HashSet, VecDeque};
use std::sync::{LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// The maximum number of seconds in either direction that the local
/// clock is adjusted; a network median outside this range applies no
/// offset (dcrd `maxAllowedOffsetSecs`).
pub const MAX_ALLOWED_OFFSET_SECS: i64 = 70 * 60;

/// The number of seconds in either direction from the local clock
/// within which a sample shows the local clock is probably right,
/// silencing the invalid-clock warning (dcrd `similarTimeSecs`).
pub const SIMILAR_TIME_SECS: i64 = 5 * 60;

/// The maximum number of samples kept (dcrd `maxMedianTimeEntries`).
pub const MAX_MEDIAN_TIME_ENTRIES: usize = 200;

/// The largest offset, in whole seconds, Go's `time.Time.Sub` can
/// express before it saturates at the maximum `time.Duration`
/// (`int64(maxDuration.Seconds())`).  Version timestamps reach far past
/// it, since the wire accepts any value up to `MaxInt64 -
/// unixToInternal`.
const MAX_DURATION_SECS: i64 = i64::MAX / 1_000_000_000;

/// The state dcrd's `medianTime` guards with its mutex.
struct MedianTimeState {
    /// The sources already sampled; each contributes at most once.
    known_ids: HashSet<String>,
    /// The sampled offsets in arrival order, oldest first.
    offsets: VecDeque<i64>,
    /// The offset currently applied to the local clock, in seconds.
    offset_secs: i64,
    /// Whether the invalid-clock warning check already ran.
    invalid_time_checked: bool,
}

/// A median time source (dcrd `blockchain.MedianTimeSource`, the
/// `medianTime` implementation), including the Bitcoin Core bug dcrd
/// keeps because the result feeds consensus: the offset is only
/// updated when the number of samples is odd, and the sample cap is
/// even, so once the cap is reached the offset never moves again.
pub struct MedianTime {
    state: Mutex<MedianTimeState>,
    /// The sample cap; [`MAX_MEDIAN_TIME_ENTRIES`] outside the tests,
    /// which lower it exactly as dcrd's own test does.
    max_entries: usize,
}

impl Default for MedianTime {
    fn default() -> MedianTime {
        MedianTime::new()
    }
}

/// The current unix time truncated to whole seconds (dcrd's
/// `time.Unix(time.Now().Unix(), 0)`).
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl MedianTime {
    /// A source with no samples, so no offset (dcrd `NewMedianTime`).
    pub fn new() -> MedianTime {
        MedianTime::with_max_entries(MAX_MEDIAN_TIME_ENTRIES)
    }

    fn with_max_entries(max_entries: usize) -> MedianTime {
        MedianTime {
            state: Mutex::new(MedianTimeState {
                known_ids: HashSet::new(),
                offsets: VecDeque::with_capacity(max_entries),
                offset_secs: 0,
                invalid_time_checked: false,
            }),
            max_entries,
        }
    }

    /// The current unix time adjusted by the median offset, at one
    /// second precision (dcrd `AdjustedTime`).
    pub fn adjusted_time_unix(&self) -> i64 {
        let offset_secs = self.offset_secs();
        now_unix().saturating_add(offset_secs)
    }

    /// The offset applied to the local clock, in seconds (dcrd `Offset`,
    /// a whole number of seconds).
    pub fn offset_secs(&self) -> i64 {
        self.state
            .lock()
            .expect("median time mutex poisoned")
            .offset_secs
    }

    /// Add the time a source reported, as unix seconds, as a sample
    /// (dcrd `AddTimeSample`).  A source that already contributed is
    /// ignored.
    pub fn add_time_sample(&self, source_id: &str, time_unix: i64) {
        self.add_time_sample_at(source_id, time_unix, now_unix());
    }

    /// [`MedianTime::add_time_sample`] against the given local time.
    fn add_time_sample_at(&self, source_id: &str, time_unix: i64, now_unix: i64) {
        let mut m = self.state.lock().expect("median time mutex poisoned");

        // Don't add time data from the same source.
        if !m.known_ids.insert(source_id.to_string()) {
            return;
        }

        // Truncate the provided offset to seconds and append it to the
        // offsets while respecting the maximum number of allowed
        // entries by replacing the oldest entry with the new entry once
        // the maximum number of entries is reached.  Go's `Sub`
        // saturates at the maximum duration, whose whole seconds bound
        // the offset.
        let offset_secs = time_unix
            .saturating_sub(now_unix)
            .clamp(-MAX_DURATION_SECS, MAX_DURATION_SECS);
        if m.offsets.len() == self.max_entries && self.max_entries > 0 {
            m.offsets.pop_front();
        }
        m.offsets.push_back(offset_secs);
        let num_offsets = m.offsets.len();

        // Sort the offsets so the median can be obtained.
        let mut sorted_offsets: Vec<i64> = m.offsets.iter().copied().collect();
        sorted_offsets.sort_unstable();

        crate::logging::debug(
            "CHAN",
            &format!(
                "Added time sample of {} (total: {num_offsets})",
                crate::gostd::go_duration_string(offset_secs.saturating_mul(1_000_000_000))
            ),
        );

        // NOTE: This intentionally mirrors the buggy behavior in Bitcoin
        // Core, as dcrd does, since the median time is used in the
        // consensus rules: the offset is only updated when the number
        // of entries is odd, but the max number of entries is 200, an
        // even number, so the offset never changes again once the max
        // number of entries is reached.
        //
        // The median offset is only updated when there are enough
        // offsets and the number of offsets is odd so the middle value
        // is the true median.
        if num_offsets < 5 || num_offsets & 0x01 != 1 {
            return;
        }

        // The number of offsets is odd, so the middle value of the
        // sorted offsets is the median.
        let median = sorted_offsets[num_offsets / 2];

        // Set the new offset when the median offset is within the
        // allowed offset range.
        if median.unsigned_abs() < MAX_ALLOWED_OFFSET_SECS.unsigned_abs() {
            m.offset_secs = median;
        } else {
            // The median offset of all added time data is larger than
            // the maximum allowed offset, so don't use an offset.  This
            // effectively limits how far the local clock can be skewed.
            m.offset_secs = 0;

            if !m.invalid_time_checked {
                m.invalid_time_checked = true;

                // Warn if none of the time samples are close to the
                // local time.
                let remote_has_close_time = sorted_offsets
                    .iter()
                    .any(|offset| offset.unsigned_abs() < SIMILAR_TIME_SECS.unsigned_abs());
                if !remote_has_close_time {
                    crate::logging::warn(
                        "CHAN",
                        "Please check your date and time are correct!  dcrd will not work \
                         properly with an invalid time",
                    );
                }
            }
        }

        crate::logging::debug(
            "CHAN",
            &format!(
                "New time offset: {}",
                crate::gostd::go_duration_string(m.offset_secs.saturating_mul(1_000_000_000))
            ),
        );
    }
}

/// The server's median time source (dcrd `server.timeSource`), fed by
/// every handshaken peer's version timestamp and read wherever dcrd
/// reads `timeSource.AdjustedTime()` or `Offset()`.
static SERVER_TIME_SOURCE: LazyLock<MedianTime> = LazyLock::new(MedianTime::new);

/// The process-wide median time source.
pub fn server_time_source() -> &'static MedianTime {
    &SERVER_TIME_SOURCE
}

/// The median-adjusted current unix time (dcrd
/// `server.timeSource.AdjustedTime().Unix()`).
pub fn adjusted_time_unix() -> i64 {
    server_time_source().adjusted_time_unix()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// dcrd's `TestMedianTime` table, run against a fixed local clock so
    /// no fudge factor is needed.
    #[test]
    fn median_time_matches_dcrd() {
        struct Case {
            input: &'static [i64],
            want_offset: i64,
            use_dup_id: bool,
        }
        let case = |input, want_offset| Case {
            input,
            want_offset,
            use_dup_id: false,
        };
        let tests = [
            // Not enough samples must result in an offset of 0.
            case(&[1], 0),
            case(&[1, 2], 0),
            case(&[1, 2, 3], 0),
            case(&[1, 2, 3, 4], 0),
            // Various number of entries.  The expected offset is only
            // updated on odd number of elements.
            case(&[-13, 57, -4, -23, -12], -12),
            case(&[55, -13, 61, -52, 39, 55], 39),
            case(&[-62, -58, -30, -62, 51, -30, 15], -30),
            case(&[29, -47, 39, 54, 42, 41, 8, -33], 39),
            case(&[37, 54, 9, -21, -56, -36, 5, -11, -39], -11),
            case(&[57, -28, 25, -39, 9, 63, -16, 19, -60, 25], 9),
            Case {
                input: &[-5, -4, -3, -2, -1],
                want_offset: -3,
                use_dup_id: true,
            },
            // The offset stops being updated once the max number of
            // entries has been reached.
            case(&[-67, 67, -50, 24, 63, 17, 58, -14, 5, -32, -52], 17),
            case(&[-67, 67, -50, 24, 63, 17, 58, -14, 5, -32, -52, 45], 17),
            case(&[-67, 67, -50, 24, 63, 17, 58, -14, 5, -32, -52, 45, 4], 17),
            // Offsets that are too far away from the local time should
            // be ignored.
            case(&[-4201, 4202, -4203, 4204, -4205], 0),
            // The median is past the allowed adjustment, but one sample
            // is close enough to the local time to avoid the warning.
            case(&[4201, 4202, 4203, 4204, -299], 0),
        ];

        const NOW: i64 = 1_700_000_000;
        for (i, test) in tests.iter().enumerate() {
            // dcrd's test lowers the cap to 10 entries.
            let filter = MedianTime::with_max_entries(10);
            for (j, offset) in test.input.iter().enumerate() {
                let id = j.to_string();
                filter.add_time_sample_at(&id, NOW + offset, NOW);
                // Duplicate ids are ignored even when the sample would
                // move the median.
                if test.use_dup_id {
                    filter.add_time_sample_at(&id, NOW + 2 * offset, NOW);
                }
            }
            assert_eq!(filter.offset_secs(), test.want_offset, "offset #{i}");
        }
    }

    /// The adjusted time is the local clock moved by the offset.
    #[test]
    fn adjusted_time_applies_the_offset() {
        let filter = MedianTime::new();
        let now = now_unix();
        for (j, offset) in [600i64, 600, 600, 600, 600].iter().enumerate() {
            filter.add_time_sample_at(&j.to_string(), now + offset, now);
        }
        assert_eq!(filter.offset_secs(), 600);
        let adjusted = filter.adjusted_time_unix();
        let after = now_unix();
        assert!(
            (now + 600..=after + 600).contains(&adjusted),
            "adjusted {adjusted} not local time plus the 600 s offset"
        );
    }

    /// A timestamp past what Go's `time.Duration` can hold saturates the
    /// offset the way `Time.Sub` does, rather than wrapping.
    #[test]
    fn far_future_samples_saturate_like_go() {
        let filter = MedianTime::new();
        let far = i64::MAX - 62_135_596_800;
        for j in 0..5 {
            filter.add_time_sample_at(&j.to_string(), far, 1_700_000_000);
        }
        let m = filter.state.lock().expect("median time mutex poisoned");
        assert!(m.offsets.iter().all(|offset| *offset == 9_223_372_036));
        assert_eq!(m.offset_secs, 0, "far past the allowed adjustment");
    }
}
