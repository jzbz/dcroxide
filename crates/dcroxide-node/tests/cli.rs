// SPDX-License-Identifier: ISC
//! Integration checks for the dcroxide binary's configuration
//! front-end: the version, help, debug-level-show, and error command
//! line exits with dcrd's exit codes.  The successful startup path
//! idles on a shutdown signal and is exercised separately.

use std::process::Command;

fn run(args: &[&str]) -> (String, String, i32) {
    let out = Command::new(env!("CARGO_BIN_EXE_dcroxide"))
        .args(args)
        // Use an isolated home so the run neither reads nor writes the
        // real user configuration.
        .env("HOME", std::env::temp_dir())
        .env_remove("DCRD_APPDATA")
        .output()
        .expect("run dcroxide binary");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

#[test]
fn version_exits_zero_with_version() {
    let (stdout, _, code) = run(&["--version"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("dcroxide version"), "stdout: {stdout}");
    assert!(stdout.contains("2.1.5+release.local"), "stdout: {stdout}");
}

#[test]
fn help_exits_zero() {
    let (stdout, _, code) = run(&["-h"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("Usage: dcroxide"), "stdout: {stdout}");
}

#[test]
fn debuglevel_show_lists_subsystems() {
    let (stdout, _, code) = run(&["--debuglevel=show"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("Supported subsystems"), "stdout: {stdout}");
    // A couple of the known subsystem identifiers.
    assert!(stdout.contains("DCRD"), "stdout: {stdout}");
    assert!(stdout.contains("SRVR"), "stdout: {stdout}");
}

#[test]
fn unknown_flag_exits_one_with_error() {
    let (_, stderr, code) = run(&["--thisisnotaflag"]);
    assert_eq!(code, 1);
    assert!(stderr.contains("unknown flag"), "stderr: {stderr}");
    assert!(stderr.contains("Use dcroxide -h"), "stderr: {stderr}");
}
