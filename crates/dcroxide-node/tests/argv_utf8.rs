// SPDX-License-Identifier: ISC
//! A non-UTF-8 command line argument is reported, not aborted on
//! (RVW-054).
//!
//! `std::env::args` panics on an argument that is not valid Unicode, and
//! the release profile sets `panic = "abort"`, so one bad byte in argv
//! killed the daemon before it could print anything — no usage, no error,
//! no log line.  Go strings are arbitrary bytes, so dcrd takes the
//! argument as given; on unix a path need not be UTF-8 at all.
//!
//! Reproducing that byte for byte would mean threading `OsStr` through
//! every option and value, so the port rejects instead — but it says so
//! and exits cleanly, which is the whole difference this pins.

#![cfg(unix)]

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::process::Command;

/// `--datadir=x\xff`: well-formed as an option, invalid as Unicode.
fn bad_arg() -> OsString {
    let mut raw = b"--datadir=x".to_vec();
    raw.push(0xff);
    OsString::from_vec(raw)
}

#[test]
fn the_daemon_reports_a_non_utf8_argument_instead_of_aborting() {
    let out = Command::new(env!("CARGO_BIN_EXE_dcroxide"))
        .arg(bad_arg())
        .output()
        .expect("spawn dcroxide");
    let stderr = String::from_utf8_lossy(&out.stderr);

    // Pre-fix this is a panic: no exit code at all under `panic = "abort"`,
    // and 101 where panics unwind.  Either way it is not a clean refusal.
    assert_eq!(
        out.status.code(),
        Some(1),
        "expected a clean failure exit; stderr was: {stderr}",
    );
    assert!(
        stderr.contains("invalid UTF-8 in command line argument"),
        "expected the argument to be named; stderr was: {stderr}",
    );
}

#[test]
fn the_helper_binaries_report_it_too() {
    for exe in [
        env!("CARGO_BIN_EXE_addblock"),
        env!("CARGO_BIN_EXE_gencerts"),
        env!("CARGO_BIN_EXE_promptsecret"),
    ] {
        let out = Command::new(exe).arg(bad_arg()).output().expect("spawn");
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout)
        );
        assert!(
            out.status.code().is_some(),
            "{exe} died on a signal instead of exiting; output was: {combined}",
        );
        assert!(
            combined.contains("invalid UTF-8 in command line argument"),
            "{exe} did not name the bad argument; output was: {combined}",
        );
    }
}
