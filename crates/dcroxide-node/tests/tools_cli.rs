// SPDX-License-Identifier: ISC
//! Command line integration checks for the tool binaries: addblock's
//! configuration exits with dcrd's codes and error texts (including
//! the help-exits-nonzero quirk) plus an end-to-end empty import over
//! a fresh mainnet database, and promptsecret's Go-flag exits with
//! the non-terminal read failure.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

/// A unique scratch directory under the system temp directory so
/// concurrent tests never share a datadir.
fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("dcroxide-tools-{tag}-{}-{seq}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

fn run_addblock(args: &[&str]) -> (String, String, i32) {
    let out = Command::new(env!("CARGO_BIN_EXE_addblock"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("run addblock binary");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

fn run_promptsecret(args: &[&str]) -> (String, String, i32) {
    let out = Command::new(env!("CARGO_BIN_EXE_promptsecret"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("run promptsecret binary");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

/// addblock --help prints the usage and exits 1 (dcrd's realMain
/// returns the go-flags help error to an os.Exit(1)).
#[test]
fn addblock_help_exits_one() {
    let (stdout, _, code) = run_addblock(&["--help"]);
    assert_eq!(code, 1);
    assert!(stdout.contains("Usage:"), "stdout: {stdout}");
    assert!(stdout.contains("--noexistsaddrindex"), "stdout: {stdout}");
}

/// Conflicting networks exit with dcrd's exact error text.
#[test]
fn addblock_refuses_conflicting_networks() {
    let (_, stderr, code) = run_addblock(&["--testnet", "--simnet"]);
    assert_eq!(code, 1);
    assert!(
        stderr
            .contains("loadConfig: the testnet, regtest, and simnet params can't be used together"),
        "stderr: {stderr}"
    );
}

/// An unknown flag surfaces go-flags' text and the help on stderr.
#[test]
fn addblock_refuses_unknown_flags() {
    let (_, stderr, code) = run_addblock(&["--bogus"]);
    assert_eq!(code, 1);
    assert!(stderr.contains("unknown flag `bogus'"), "stderr: {stderr}");
    assert!(stderr.contains("Usage:"), "stderr: {stderr}");
}

/// A bad database type and a missing input file exit with dcrd's
/// texts.
#[test]
fn addblock_validates_dbtype_and_infile() {
    let (_, stderr, code) = run_addblock(&["--dbtype", "leveldb"]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("the specified database type [leveldb] is invalid"),
        "stderr: {stderr}"
    );

    let (_, stderr, code) = run_addblock(&["-i", "/nonexistent/bootstrap.dat"]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("the specified block file [/nonexistent/bootstrap.dat] does not exist"),
        "stderr: {stderr}"
    );
}

/// An empty bootstrap file imports zero blocks end to end: the block
/// database is created, the genesis chain state loads, and the final
/// tally reports nothing processed.
#[test]
fn addblock_imports_an_empty_file() {
    let dir = scratch("empty-import");
    let infile = dir.join("bootstrap.dat");
    std::fs::write(&infile, b"").expect("write empty bootstrap");

    let (stdout, stderr, code) = run_addblock(&[
        "--datadir",
        dir.to_str().expect("utf8 path"),
        "-i",
        infile.to_str().expect("utf8 path"),
    ]);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("Block database loaded"), "stdout: {stdout}");
    assert!(
        stdout.contains("Processed a total of 0 blocks (0 imported, 0 already known) in "),
        "stdout: {stdout}"
    );
}

/// promptsecret without a terminal fails the read with Go's error
/// shape and exit code (on unix stty refuses the null stdin exactly
/// like Go's ReadPassword refuses a pipe).
#[test]
fn promptsecret_fails_without_a_terminal() {
    let (stdout, stderr, code) = run_promptsecret(&[]);
    assert_eq!(code, 1);
    assert!(stdout.is_empty(), "no secret may reach stdout: {stdout}");
    assert!(
        stderr.contains("unable to read secret: "),
        "stderr: {stderr}"
    );
}

/// The Go flag package exits: -h prints the usage and exits 0, a bad
/// value and an unknown flag print the message plus the usage and
/// exit 2.
#[test]
fn promptsecret_flag_exits() {
    let (_, stderr, code) = run_promptsecret(&["-h"]);
    assert_eq!(code, 0);
    assert!(
        stderr.contains("Usage of promptsecret:"),
        "stderr: {stderr}"
    );

    let (_, stderr, code) = run_promptsecret(&["-n", "abc"]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("invalid value \"abc\" for flag -n: parse error"),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("Usage of promptsecret:"),
        "stderr: {stderr}"
    );

    let (_, stderr, code) = run_promptsecret(&["-x"]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("flag provided but not defined: -x"),
        "stderr: {stderr}"
    );

    let (_, stderr, code) = run_promptsecret(&["-n"]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("flag needs an argument: -n"),
        "stderr: {stderr}"
    );
}
