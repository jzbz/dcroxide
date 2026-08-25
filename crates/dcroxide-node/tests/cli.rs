// SPDX-License-Identifier: ISC
//! Integration checks for the dcroxide binary's configuration
//! front-end: the version, help, debug-level-show, and error command
//! line exits with dcrd's exit codes, and the successful startup path
//! that opens the block database and loads the genesis chain state
//! before idling on a shutdown signal.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// A unique application data directory under the system temp directory,
/// so a spawned daemon neither reads nor writes the real user
/// configuration and concurrent tests never share a data directory (and
/// its exclusively locked block database).  This is passed as --appdata
/// rather than via $HOME because on Windows the data directory is
/// resolved from the OS-native location (%LOCALAPPDATA%), where $HOME is
/// ignored, so an $HOME override would not isolate the run at all.  The
/// process id alone is not unique enough — tests in one binary share it
/// — so a per-call sequence number is mixed in.
fn isolated_appdata(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("dcroxide-cli-{tag}-{}-{seq}", std::process::id()))
}

fn run(args: &[&str]) -> (String, String, i32) {
    let appdata = isolated_appdata("run");
    let out = Command::new(env!("CARGO_BIN_EXE_dcroxide"))
        .arg(format!("--appdata={}", appdata.display()))
        .args(args)
        .env_remove("DCRD_APPDATA")
        .output()
        .expect("run dcroxide binary");
    let _ = std::fs::remove_dir_all(&appdata);
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
    assert!(stdout.contains("2.2.0-pre"), "stdout: {stdout}");
}

#[test]
fn help_exits_zero_with_the_full_help() {
    let (stdout, _, code) = run(&["-h"]);
    assert_eq!(code, 0);
    // The full go-flags help, pinned byte-exact by the flags vectors;
    // here just the shape end to end through the binary.
    assert!(
        stdout.starts_with("Usage:\n  dcroxide [OPTIONS]"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("-V, --version               Display version information and exit"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("Help Options:"), "stdout: {stdout}");
}

#[test]
fn debuglevel_show_lists_subsystems() {
    let (stdout, stderr, code) = run(&["--debuglevel=show"]);
    assert_eq!(code, 0, "stderr: {stderr}");
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

/// Spawn the daemon with `args` (plus an isolated app data directory,
/// `--norpc` and `--noseeders`), then wait up to 20s for a stdout or
/// stderr line satisfying `wanted`, returning that line.  On timeout the
/// panic message includes every line the daemon printed, so a startup
/// failure on a CI platform that cannot be reproduced locally is still
/// diagnosable rather than a bare "line never appeared".
///
/// `--norpc` is supplied here rather than by each caller because it is
/// isolation, the same category as the unique app data directory above,
/// and it belongs wherever that does.  The RPC server binds the default
/// `rpclisten` port, which is fixed rather than per-process, so two
/// daemons alive at once — this binary's tests running in parallel, or
/// any other test in the workspace that starts one — collide on it.  The
/// daemon treats that bind failure as fatal, so the collision does not
/// surface as a port error but as the awaited line never arriving, which
/// reads exactly like the behaviour under test having broken.  No caller
/// here exercises RPC; one that needs to must pass its own
/// `--rpclisten=127.0.0.1:0` and not use this helper.
///
/// `--noseeders` is here for the same reason.  These tests run on
/// mainnet, so without it the daemon resolves the real DNS seeders and
/// dials whatever they return — four of them answered on a plain run
/// while this helper was being fixed.  A unit test of argument handling
/// and startup ordering has no business reaching the network: it makes
/// the suite depend on DNS, on the seeders being up, and on the machine
/// having a route, none of which the assertions are about.
fn wait_for_daemon_line(tag: &str, args: &[&str], wanted: impl Fn(&str) -> bool) -> String {
    let home = isolated_appdata(tag);
    let mut child = Command::new(env!("CARGO_BIN_EXE_dcroxide"))
        .args(args)
        .arg("--norpc")
        .arg("--noseeders")
        .arg(format!("--appdata={}", home.display()))
        .env_remove("DCRD_APPDATA")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dcroxide binary");

    // Drain stdout and stderr on their own threads onto one channel, so
    // startup progress and any error diagnostics are captured together
    // and the wait can be time-bounded.
    let (tx, rx) = mpsc::channel();
    for stream in [
        Box::new(child.stdout.take().expect("piped stdout")) as Box<dyn std::io::Read + Send>,
        Box::new(child.stderr.take().expect("piped stderr")),
    ] {
        let tx = tx.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stream).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
    }
    drop(tx);

    let mut seen = Vec::new();
    let mut found = None;
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(20) {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(line) if wanted(&line) => {
                found = Some(line);
                break;
            }
            Ok(line) => seen.push(line),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&home);

    found.unwrap_or_else(|| {
        panic!(
            "daemon did not print the expected startup line within 20s; captured output:\n{}",
            seen.join("\n")
        )
    })
}

#[test]
fn startup_opens_block_database_and_loads_genesis() {
    // --nolisten because this test is about the database, not the network.
    let loaded = wait_for_daemon_line("db", &["--nolisten"], |line| {
        line.contains("Block database loaded")
    });
    // A fresh database starts at the genesis block (height 0).
    assert!(
        loaded.contains("best block height 0"),
        "startup line: {loaded}"
    );
}

#[test]
fn startup_serves_peer_connections_on_a_listener() {
    // Bind an ephemeral loopback port rather than a fixed one, so two
    // daemons alive at once do not collide on the peer-to-peer listener.
    // The RPC listener and the seeders are handled by the helper, which
    // is what keeps this off the network — an earlier version of this
    // comment claimed the flag below did that, and it never did.  The
    // helper panics with the captured daemon output if the announcement
    // never arrives.
    wait_for_daemon_line("listen", &["--listen=127.0.0.1:0"], |line| {
        line.contains("Serving peer-to-peer connections on 127.0.0.1:")
    });
}

/// go-flags never lifts `--help` out of an argument position.
///
/// Help is an ordinary registered option on dcrd's help pre-parse
/// (`config.go:653-659`, `flags.HelpFlag`), so it is parsed in argument
/// order. After an option that takes a value, go-flags pops it as that
/// value and then rejects it in `isValidValue` because it looks like an
/// option -- `ErrExpectedArgument`, not `ErrHelp`, so the pre-parse
/// does not exit and the same error resurfaces from the final parse.
///
/// The port used to scan argv positionally for `-h`/`--help` before the
/// grammar ran, so these printed usage and exited 0: a command line
/// dcrd rejects, reported to a supervisor as a successful run.
#[test]
fn help_after_an_argument_taking_option_is_an_error() {
    for (tail, shown) in [("--help", "--help"), ("-h", "-h")] {
        let (stdout, stderr, code) = run(&["--rpcuser", tail]);
        assert_eq!(code, 1, "{tail}: stdout: {stdout}");
        assert!(
            stderr.contains(&format!(
                "expected argument for flag `-u, --rpcuser', but got option `{shown}'"
            )),
            "{tail}: stderr: {stderr}"
        );
        assert!(!stdout.contains("Usage:"), "{tail}: usage was printed");
    }
}

/// `-h` inside a short cluster is the help option, wherever it sits.
///
/// The positional prescan had no notion of clusters: `-Vh` printed the
/// version and `-hV` reported ``unknown flag `h'``, where go-flags
/// prints help and exits 0 for both.
#[test]
fn help_inside_a_short_cluster_requests_help() {
    for cluster in ["-Vh", "-hV"] {
        let (stdout, stderr, code) = run(&[cluster]);
        assert_eq!(code, 0, "{cluster}: stderr: {stderr}");
        assert!(stdout.contains("Usage:"), "{cluster}: stdout: {stdout}");
        assert!(
            !stdout.contains("dcroxide version"),
            "{cluster}: the version preempted help"
        );
    }
}

/// --dumpblockchain writes the flat file and refuses to start.
///
/// dcrd runs the dump inside `newServer`, after the index catch-up, and
/// returns an error either way -- so nothing binds a listener and the
/// exit is non-zero even when the dump succeeded
/// (`server.go:4149-4157`). The option parsed and appeared in --help
/// here while nothing read it, so asking for a one-shot offline dump
/// started a normal node that dialled the network instead.
///
/// Bounded rather than using `run`, because the failure mode being
/// guarded against is a daemon that ignores the flag and idles: a
/// regression must fail here, not hang.
///
/// A fresh database is genesis-only and dcrd's loop starts at height 1,
/// so the file is created and left empty.
#[test]
fn dumpblockchain_writes_the_file_and_refuses_to_start() {
    let home = isolated_appdata("dumpchain");
    let file = home.join("blocks.dat");
    std::fs::create_dir_all(&home).expect("appdata");

    let mut child = Command::new(env!("CARGO_BIN_EXE_dcroxide"))
        .args(["--simnet", "--nolisten", "--norpc"])
        .arg(format!("--appdata={}", home.display()))
        .arg(format!("--dumpblockchain={}", file.display()))
        .env_remove("DCRD_APPDATA")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dcroxide binary");

    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        match child.try_wait().expect("wait") {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = std::fs::remove_dir_all(&home);
                panic!("the daemon kept running instead of dumping and exiting");
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    };

    let out = child.wait_with_output().expect("output");
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let dumped = std::fs::metadata(&file).map(|m| m.len());
    let _ = std::fs::remove_dir_all(&home);

    assert_eq!(status.code(), Some(1), "log: {log}");
    assert!(
        log.contains("Successfully dumped the blockchain (0 blocks)"),
        "log: {log}"
    );
    assert!(
        log.contains("Unable to start server: closing after dumping blockchain"),
        "log: {log}"
    );
    assert_eq!(
        dumped.expect("the dump file must exist"),
        0,
        "a genesis-only chain dumps no records"
    );
}
