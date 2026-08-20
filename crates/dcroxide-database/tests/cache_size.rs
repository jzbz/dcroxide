// SPDX-License-Identifier: ISC
//! The redb page-cache size reaches the engine (see the test's own
//! documentation for the mechanism).
//!
//! This lives in its own integration test rather than alongside the
//! other database tests, and that placement is load-bearing.  The
//! measurement reads `/proc/self/io`, which is **process-wide**, while
//! `cargo test` runs the tests within one binary concurrently — so
//! sibling tests doing their own I/O land inside the measurement
//! window.  Sharing a binary with eight of them moved the small arm
//! from 96,293,184 bytes to ~166,500,000 and the ratio from 1.94 to
//! 1.76, and on a slower CI runner it reached 1.2479 against the 1.25
//! bar and failed.  One test per binary is one process per measurement.

use dcroxide_database::{Database, Options};
use tempfile::TempDir;

const NET: u32 = 0x12141c16; // simnet magic

/// The configured cache size must actually reach redb.
///
/// redb 4.1.0 takes one `set_cache_size` figure (`db.rs:1161`) and
/// partitions it dynamically: the write buffer never exceeds 50% of the
/// total (`cached_file.rs:205`) and the read cache may grow to 100% when
/// no write is in flight. When a commit's dirty set exceeds the write
/// buffer, redb spills those pages to the file, re-reads them to
/// finalize checksums, and writes the buffer again — so a too-small
/// buffer roughly doubles the bytes written per commit.
///
/// redb 2.6.3 cut the same figure 90/10 (`db.rs:1186-1187`), so the
/// small arm's buffer grew fivefold across the upgrade, from 6.4 MiB to
/// 32. The parameters below still clear it: measured after the upgrade,
/// the small arm writes 96,293,184 bytes against the large arm's
/// 49,754,432, a ratio of **1.935** against the 1.25 bar, byte-identical
/// across five runs. Deleting the `set_cache_size` call collapses it to
/// exactly 1.000.
///
/// That amplification is the observable this asserts. An `Options` field
/// that is never handed to `redb::Builder` would leave both runs on
/// redb's default and the two byte counts would match, which is the
/// ported-but-unwired failure this guards.
///
/// Real negative: drop `set_cache_size` from `redb_builder`, or restore
/// either open path to a bare `redb::Database::create`/`open`, and the
/// ratio collapses to ~1.0 and the assertion fails.
///
/// Linux only — it reads `/proc/self/io`. Elsewhere it skips, so the
/// wiring is unguarded on macOS and Windows CI.
#[test]
fn the_configured_cache_size_reaches_redb() {
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("skipped: /proc/self/io is Linux-only");
    }
    #[cfg(target_os = "linux")]
    {
        /// Bytes this process has passed to write syscalls.
        ///
        /// `wchar`, not `write_bytes`: the latter counts what reached the
        /// block layer, which the page cache absorbs, so it reads zero
        /// for a workload this size. The amplification being measured is
        /// at the syscall boundary, which is what `wchar` records.
        fn written() -> u64 {
            let io = std::fs::read_to_string("/proc/self/io").expect("/proc/self/io");
            for line in io.lines() {
                if let Some(v) = line.strip_prefix("wchar:") {
                    return v.trim().parse().expect("wchar");
                }
            }
            panic!("wchar missing from /proc/self/io");
        }

        // Enough distinct pages that the dirty set clears the small
        // write buffer but stays inside the large one. A 2048-byte value
        // under a 20-byte key cannot share a 4 KiB page with another, so
        // this dirties about 49 MiB: over the small arm's 32 MiB buffer,
        // well under the large arm's 512.
        const ROWS: usize = 12_000;
        const VALUE: usize = 2048;

        let run = |cache: usize| -> u64 {
            let dir = TempDir::new().expect("tempdir");
            let mut opts = Options::new(dir.path().join("db"), NET);
            opts.db_cache_bytes = cache;
            let db = Database::create(&opts).expect("create");
            {
                let tx = db.begin(true).expect("begin rw");
                tx.metadata().create_bucket(b"cache").expect("create");
                tx.commit().expect("commit");
            }
            db.flush().expect("flush the bucket");

            let value = vec![0x7Eu8; VALUE];
            let before = written();
            {
                let tx = db.begin(true).expect("begin rw");
                let meta = tx.metadata();
                let bucket = meta.bucket(b"cache").expect("bucket");
                for i in 0..ROWS {
                    // Scatter so the writes land on distinct pages.
                    let mut key = [0u8; 16];
                    let h = (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
                    key[..8].copy_from_slice(&h.to_be_bytes());
                    key[8..].copy_from_slice(&(i as u64).to_be_bytes());
                    bucket.put(&key, &value).expect("put");
                }
                tx.commit().expect("commit");
            }
            db.flush().expect("flush the rows");
            written().saturating_sub(before)
        };

        // 64 MiB -> a write buffer capped at 32 MiB, under the dirty set.
        let small = run(64 * 1024 * 1024);
        // 1 GiB -> capped at 512 MiB, comfortably over it.
        let large = run(1024 * 1024 * 1024);

        assert!(
            small > 0 && large > 0,
            "no writes were observed (small {small}, large {large}); /proc/self/io accounting \
             did not see this workload and the test proved nothing"
        );
        // Amplification is ~2x in principle; require a clear margin so
        // filesystem noise cannot manufacture a pass.
        assert!(
            small * 100 > large * 125,
            "a 64 MiB cache wrote {small} bytes and a 1 GiB cache wrote {large} — within 25%, so \
             the cache size is not reaching redb and both runs used its default"
        );
    }
}
