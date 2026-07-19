// SPDX-License-Identifier: ISC
//! Periodic sync progress logging (dcrd `internal/progresslog`): the
//! ten-second throttled reporter behind the `Processed N blocks in
//! the last …` and `Processed N headers in the last …` lines.  The
//! pure netsync manager emits accumulation actions carrying the
//! per-call facts (dcrd calls the logger directly); this logger owns
//! the clock, the running totals, and the exact line rendering.

use std::time::{Duration, Instant};

/// The throttle between periodic progress lines (dcrd hardcodes ten
/// seconds in `LogProgress`/`LogHeaderProgress`).
const LOG_INTERVAL: Duration = Duration::from_secs(10);

/// The singular or plural form of a noun depending on the count
/// (dcrd progresslog's `pickNoun`).
fn pick_noun<'a>(n: u64, singular: &'a str, plural: &'a str) -> &'a str {
    if n == 1 { singular } else { plural }
}

/// Periodic logging of progress towards some action such as syncing
/// the chain (dcrd `progresslog.Logger`; the daemon serializes access
/// behind a mutex where dcrd embeds one).
pub struct ProgressLogger {
    progress_action: &'static str,

    /// The last time a log statement was shown.
    last_log_time: Instant,

    // These fields accumulate information about blocks between log
    // statements.
    received_blocks: u64,
    received_txns: u64,
    received_votes: u64,
    received_revokes: u64,
    received_tickets: u64,

    // These fields accumulate information about headers between log
    // statements.
    received_headers: u64,
}

impl ProgressLogger {
    /// A new progress logger (dcrd `progresslog.New`).
    pub fn new(progress_action: &'static str) -> ProgressLogger {
        ProgressLogger {
            progress_action,
            last_log_time: Instant::now(),
            received_blocks: 0,
            received_txns: 0,
            received_votes: 0,
            received_revokes: 0,
            received_tickets: 0,
            received_headers: 0,
        }
    }

    /// Accumulate the provided block facts and return the information
    /// line to show once every ten seconds (dcrd `LogProgress`; the
    /// force flag bypasses the throttle).  The rendered line is
    /// dcrd's, byte for byte:
    ///
    /// `{action} {n} block(s) in the last {t}s ({n} transaction(s),
    /// {n} ticket(s), {n} vote(s), {n} revocation(s), height {h},
    /// progress {p}%)`
    #[allow(clippy::too_many_arguments)] // Mirrors the action's facts.
    pub fn log_block_progress_at(
        &mut self,
        num_txs: u64,
        num_tickets: u64,
        num_votes: u64,
        num_revocations: u64,
        height: u32,
        force: bool,
        verify_progress: f64,
        now: Instant,
    ) -> Option<String> {
        self.received_blocks = self.received_blocks.wrapping_add(1);
        self.received_txns = self.received_txns.wrapping_add(num_txs);
        self.received_votes = self.received_votes.wrapping_add(num_votes);
        self.received_revokes = self.received_revokes.wrapping_add(num_revocations);
        self.received_tickets = self.received_tickets.wrapping_add(num_tickets);
        let duration = now.saturating_duration_since(self.last_log_time);
        if !force && duration < LOG_INTERVAL {
            return None;
        }

        // Log information about chain progress.
        let line = format!(
            "{} {} {} in the last {:.2}s ({} {}, {} {}, {} {}, {} {}, height {}, progress {:.2}%)",
            self.progress_action,
            self.received_blocks,
            pick_noun(self.received_blocks, "block", "blocks"),
            duration.as_secs_f64(),
            self.received_txns,
            pick_noun(self.received_txns, "transaction", "transactions"),
            self.received_tickets,
            pick_noun(self.received_tickets, "ticket", "tickets"),
            self.received_votes,
            pick_noun(self.received_votes, "vote", "votes"),
            self.received_revokes,
            pick_noun(self.received_revokes, "revocation", "revocations"),
            height,
            verify_progress,
        );

        self.received_blocks = 0;
        self.received_txns = 0;
        self.received_votes = 0;
        self.received_tickets = 0;
        self.received_revokes = 0;
        self.last_log_time = now;
        Some(line)
    }

    /// Accumulate the provided number of processed headers and return
    /// the information line to show once every ten seconds (dcrd
    /// `LogHeaderProgress`):
    ///
    /// `{action} {n} header(s) in the last {t}s (progress {p}%)`
    pub fn log_header_progress_at(
        &mut self,
        processed_headers: u64,
        force: bool,
        progress: f64,
        now: Instant,
    ) -> Option<String> {
        self.received_headers = self.received_headers.wrapping_add(processed_headers);

        let duration = now.saturating_duration_since(self.last_log_time);
        if !force && duration < LOG_INTERVAL {
            return None;
        }

        // Log information about header progress.
        let line = format!(
            "{} {} {} in the last {:.2}s (progress {:.2}%)",
            self.progress_action,
            self.received_headers,
            pick_noun(self.received_headers, "header", "headers"),
            duration.as_secs_f64(),
            progress,
        );

        self.received_headers = 0;
        self.last_log_time = now;
        Some(line)
    }

    /// Update the last time data was logged (dcrd `SetLastLogTime`).
    pub fn set_last_log_time(&mut self, time: Instant) {
        self.last_log_time = time;
    }
}

impl Default for ProgressLogger {
    /// The daemon's only instance (dcrd `progresslog.New("Processed",
    /// log)` in the sync manager constructor).
    fn default() -> ProgressLogger {
        ProgressLogger::new("Processed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The throttle: accumulation without output inside the window,
    /// the accumulated line at the boundary, totals reset after.
    #[test]
    fn block_progress_throttles_and_accumulates() {
        let t0 = Instant::now();
        let mut logger = ProgressLogger::new("Processed");
        logger.set_last_log_time(t0);

        assert_eq!(
            logger.log_block_progress_at(3, 1, 5, 0, 100, false, 10.0, t0 + Duration::from_secs(4)),
            None
        );
        let line = logger
            .log_block_progress_at(
                2,
                0,
                5,
                1,
                101,
                false,
                12.5,
                t0 + Duration::from_millis(10_010),
            )
            .expect("line at the boundary");
        assert_eq!(
            line,
            "Processed 2 blocks in the last 10.01s (5 transactions, 1 ticket, \
             10 votes, 1 revocation, height 101, progress 12.50%)"
        );

        // The totals reset with the shown line.
        let line = logger
            .log_block_progress_at(
                1,
                0,
                0,
                0,
                102,
                true,
                100.0,
                t0 + Duration::from_millis(10_010) + Duration::from_secs(2),
            )
            .expect("forced");
        assert_eq!(
            line,
            "Processed 1 block in the last 2.00s (1 transaction, 0 tickets, \
             0 votes, 0 revocations, height 102, progress 100.00%)"
        );
    }

    /// The header variant with force bypassing the window, and the
    /// singular noun.
    #[test]
    fn header_progress_matches_dcrd_format() {
        let t0 = Instant::now();
        let mut logger = ProgressLogger::default();
        logger.set_last_log_time(t0);

        assert_eq!(
            logger.log_header_progress_at(2000, false, 3.25, t0 + Duration::from_secs(1)),
            None
        );
        let line = logger
            .log_header_progress_at(1, true, 3.75, t0 + Duration::from_millis(1_500))
            .expect("forced");
        assert_eq!(
            line,
            "Processed 2001 headers in the last 1.50s (progress 3.75%)"
        );

        let line = logger
            .log_header_progress_at(1, true, 100.0, t0 + Duration::from_millis(1_750))
            .expect("forced");
        assert_eq!(
            line,
            "Processed 1 header in the last 0.25s (progress 100.00%)"
        );
    }
}
