// SPDX-License-Identifier: ISC
//! Periodic block progress logging for the long index phases (dcrd
//! `internal/blockchain/progresslog`'s `BlockProgressLogger`): the
//! catch-up creates one as `NewBlockProgressLogger("Indexed", log)`
//! (`indexsubscriber.go:260`) and the recovery as
//! `NewBlockProgressLogger("Recovered", log)` (`common.go:434`), and
//! each feeds it every block it handles.  At most one line is shown
//! every ten seconds:
//!
//! `{action} {n} block(s) in the last {duration} ({n} transaction(s),
//! height {h}, {block time})`
//!
//! The daemon keeps its own copies of the two Go renderers the line
//! needs (`dcroxide_node::gostd::go_duration_string` and the addblock
//! progress logger's block time), and this crate sits below it.

// Go's duration and civil-time arithmetic over non-negative values far
// from overflow: nanoseconds of a monotonic interval and a `u32` block
// timestamp.
#![allow(clippy::arithmetic_side_effects)]

use std::time::{Duration, Instant};

use dcroxide_wire::MsgBlock;

use crate::log::{LogLevel, LogSink, log_line};

/// The throttle between progress lines (dcrd's `time.Second*10` in
/// `LogBlockHeight`).
const LOG_INTERVAL: Duration = Duration::from_secs(10);

/// Periodic logging of progress through the blocks of some action,
/// such as indexing every block (dcrd `progresslog.BlockProgressLogger`;
/// its mutex is not needed, since each instance lives on the stack of
/// the one call that feeds it).
pub(crate) struct BlockProgressLogger {
    received_log_blocks: i64,
    received_log_tx: i64,
    last_block_log_time: Instant,

    subsystem_logger: Option<LogSink>,
    progress_action: &'static str,
}

impl BlockProgressLogger {
    /// A new block progress logger (dcrd `NewBlockProgressLogger`),
    /// timing its first interval from now.
    pub(crate) fn new(progress_message: &'static str, logger: Option<&LogSink>) -> Self {
        BlockProgressLogger {
            received_log_blocks: 0,
            received_log_tx: 0,
            last_block_log_time: Instant::now(),
            subsystem_logger: logger.cloned(),
            progress_action: progress_message,
        }
    }

    /// Count the block and log the progress line when ten seconds have
    /// passed since the last one (dcrd `LogBlockHeight`).
    pub(crate) fn log_block_height(&mut self, block: &MsgBlock) {
        self.log_block_height_at(block, Instant::now());
    }

    /// [`log_block_height`](Self::log_block_height) at a given instant.
    fn log_block_height_at(&mut self, block: &MsgBlock, now: Instant) {
        self.received_log_blocks = self.received_log_blocks.wrapping_add(1);
        self.received_log_tx = self
            .received_log_tx
            .wrapping_add(block.transactions.len() as i64)
            .wrapping_add(block.stransactions.len() as i64);

        let duration = now.saturating_duration_since(self.last_block_log_time);
        if duration < LOG_INTERVAL {
            return;
        }

        // Truncate the duration to 10s of milliseconds.
        let duration_millis = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        let t_duration_nanos = 10 * 1_000_000 * (duration_millis / 10);

        // Log information about new block height.
        let block_str = if self.received_log_blocks == 1 {
            "block"
        } else {
            "blocks"
        };
        let tx_str = if self.received_log_tx == 1 {
            "transaction"
        } else {
            "transactions"
        };
        log_line(
            self.subsystem_logger.as_ref(),
            LogLevel::Info,
            &format!(
                "{} {} {} in the last {} ({} {}, height {}, {})",
                self.progress_action,
                self.received_log_blocks,
                block_str,
                go_duration_string(t_duration_nanos),
                self.received_log_tx,
                tx_str,
                block.header.height,
                go_time_utc_string(block.header.timestamp),
            ),
        );

        self.received_log_blocks = 0;
        self.received_log_tx = 0;
        self.last_block_log_time = now;
    }
}

/// Format a non-negative nanosecond count like Go's
/// `time.Duration.String`: `0s`, `1.1µs`, `2.2ms`, `10.01s`, `4m5.01s`,
/// `5h6m0s`.
fn go_duration_string(nanos: u64) -> String {
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

/// Render a block timestamp the way Go's `%s` prints a whole-second
/// `time.Time` (`2006-01-02 15:04:05 +0000 UTC`).  dcrd's header times
/// come from `time.Unix` and so print in the host's local zone; the
/// port pins UTC, as the daemon's block import progress line does, so
/// the text does not depend on the host zone database.
fn go_time_utc_string(timestamp: u32) -> String {
    // Civil-from-unix over the proleptic Gregorian calendar, per Howard
    // Hinnant's algorithm (the same math Go's time package performs).
    let unix = i64::from(timestamp);
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (hh, mm, ss) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}:{ss:02} +0000 UTC")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use dcroxide_wire::{BlockHeader, MsgTx};

    /// A block at the height and time with the given transaction counts.
    fn block(height: u32, timestamp: u32, regular: usize, stake: usize) -> MsgBlock {
        let (mut header, _) = BlockHeader::from_bytes(&[0u8; 180]).expect("header");
        header.height = height;
        header.timestamp = timestamp;
        MsgBlock {
            header,
            transactions: vec![MsgTx::default(); regular],
            stransactions: vec![MsgTx::default(); stake],
        }
    }

    /// A logger whose lines land in the returned buffer, with its
    /// interval starting at `t0`.
    fn capturing(
        action: &'static str,
        t0: Instant,
    ) -> (BlockProgressLogger, Arc<Mutex<Vec<String>>>) {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let sink_lines = Arc::clone(&lines);
        let sink: LogSink = Arc::new(move |level, msg: &str| {
            assert_eq!(level, LogLevel::Info, "dcrd logs progress with Infof");
            sink_lines.lock().expect("lines").push(msg.to_string());
        });
        let mut logger = BlockProgressLogger::new(action, Some(&sink));
        logger.last_block_log_time = t0;
        (logger, lines)
    }

    /// Blocks inside the ten-second window only accumulate; the block
    /// that crosses it logs the totals with the duration truncated to
    /// 10ms, its own height and time, and dcrd's pluralization; the
    /// totals then start over.
    #[test]
    fn logs_every_ten_seconds_like_dcrd() {
        let t0 = Instant::now();
        let (mut logger, lines) = capturing("Indexed", t0);

        logger.log_block_height_at(&block(1, 1_454_954_400, 1, 0), t0 + Duration::from_secs(3));
        logger.log_block_height_at(
            &block(2, 1_454_954_700, 2, 3),
            t0 + Duration::from_millis(9_999),
        );
        assert!(lines.lock().expect("lines").is_empty(), "inside the window");

        logger.log_block_height_at(
            &block(3, 1_454_955_000, 1, 0),
            t0 + Duration::from_micros(10_019_999),
        );
        // A single block with a single transaction, over more than a
        // minute.
        logger.log_block_height_at(
            &block(4, 1_790_172_001, 1, 0),
            t0 + Duration::from_micros(10_019_999) + Duration::from_millis(65_432),
        );
        assert_eq!(
            *lines.lock().expect("lines"),
            [
                "Indexed 3 blocks in the last 10.01s (7 transactions, height 3, \
                 2016-02-08 18:10:00 +0000 UTC)",
                "Indexed 1 block in the last 1m5.43s (1 transaction, height 4, \
                 2026-09-23 14:00:01 +0000 UTC)",
            ]
        );
    }

    /// The window is measured from the last line shown, not the last
    /// block, and a logger without a sink stays silent.
    #[test]
    fn the_window_restarts_at_each_line() {
        let t0 = Instant::now();
        let (mut logger, lines) = capturing("Recovered", t0);
        logger.log_block_height_at(&block(9, 0, 0, 0), t0 + Duration::from_secs(10));
        logger.log_block_height_at(&block(8, 0, 0, 0), t0 + Duration::from_secs(19));
        logger.log_block_height_at(&block(7, 0, 0, 0), t0 + Duration::from_secs(20));
        assert_eq!(
            *lines.lock().expect("lines"),
            [
                "Recovered 1 block in the last 10s (0 transactions, height 9, \
                 1970-01-01 00:00:00 +0000 UTC)",
                "Recovered 2 blocks in the last 10s (0 transactions, height 7, \
                 1970-01-01 00:00:00 +0000 UTC)",
            ]
        );

        let mut silent = BlockProgressLogger::new("Indexed", None);
        silent.last_block_log_time = t0;
        silent.log_block_height_at(&block(1, 0, 1, 0), t0 + Duration::from_secs(11));
        assert_eq!(silent.received_log_blocks, 0, "the line was due and reset");
    }

    /// The values mirror Go's own `time.Duration.String` outputs (the
    /// daemon's copy pins the same table).
    #[test]
    fn durations_render_like_go() {
        for (nanos, s) in [
            (0u64, "0s"),
            (1, "1ns"),
            (1_100, "1.1µs"),
            (2_200_000, "2.2ms"),
            (1_000_000_000, "1s"),
            (10_010_000_000, "10.01s"),
            (120_000_000_000, "2m0s"),
            (245_010_000_000, "4m5.01s"),
            (18_000_000_000_000 + 360_000_000_000, "5h6m0s"),
        ] {
            assert_eq!(go_duration_string(nanos), s, "{nanos}");
        }
    }

    /// Whole-second times render as Go's default format in UTC.
    #[test]
    fn block_times_render_like_go_in_utc() {
        assert_eq!(go_time_utc_string(0), "1970-01-01 00:00:00 +0000 UTC");
        assert_eq!(
            go_time_utc_string(1_454_954_400),
            "2016-02-08 18:00:00 +0000 UTC"
        );
        assert_eq!(
            go_time_utc_string(u32::MAX),
            "2106-02-07 06:28:15 +0000 UTC"
        );
    }
}
