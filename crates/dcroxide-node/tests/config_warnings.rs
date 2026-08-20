// SPDX-License-Identifier: ISC
//! Configuration warnings reach the operator (RVW-052, RVW-053).
//!
//! dcrd writes its deprecation and Tor-isolation notices to stderr as it
//! parses (`config.go:818-824`) and logs the missing-config-file notice
//! after everything else succeeds (`:1348-1352`). The port collected all
//! of them into a field with eight producers and no readers, so
//! `dcroxide --configfile=/typo.conf` started on full defaults and said
//! nothing at all.
//!
//! Separately, the config file was read with `read_to_string`, so one
//! non-UTF-8 byte produced an `InvalidData` error that the
//! missing-file arm swallowed. The dangerous case is not `rpcuser`,
//! which fails closed -- it is `testnet=1`: an operator who believes
//! they are on testnet comes up on mainnet, silently.

#![cfg(unix)]
// Test-harness arithmetic over a fixed deadline.
#![allow(clippy::arithmetic_side_effects)]

use std::io::Write;
use std::process::Command;

/// Start the daemon, collect stderr until `want` appears or the
/// deadline passes, then stop it.
///
/// `--version` cannot be used: it returns before the config file is read
/// and before any of these warnings are produced, in this port and in
/// dcrd alike. The daemon has to actually come up.
fn stderr_until(args: &[String], want: &str, wait: std::time::Duration) -> String {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut child = Command::new(env!("CARGO_BIN_EXE_dcroxide"))
        .args(args)
        .arg("--simnet")
        .arg("--norpc")
        .arg("--nolisten")
        .arg("--noseeders")
        .arg(format!("--datadir={}", dir.path().display()))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn dcroxide");

    let mut err = child.stderr.take().expect("stderr pipe");
    let collected = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let sink = std::sync::Arc::clone(&collected);
    std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = [0u8; 4096];
        while let Ok(n) = err.read(&mut buf) {
            if n == 0 {
                break;
            }
            sink.lock()
                .expect("sink")
                .push_str(&String::from_utf8_lossy(&buf[..n]));
        }
    });

    let deadline = std::time::Instant::now() + wait;
    loop {
        if collected.lock().expect("sink").contains(want) || std::time::Instant::now() > deadline {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    collected.lock().expect("sink").clone()
}

/// A deprecated option must say so, which is the whole point of the
/// warnings the parser collects.
#[test]
fn a_deprecated_option_warns_on_stderr() {
    let stderr = stderr_until(
        &["--nodnsseed".to_string()],
        "is deprecated",
        std::time::Duration::from_secs(20),
    );
    assert!(
        stderr.contains("--nodnsseed option is deprecated"),
        "the deprecation notice never reached the operator; stderr was: {stderr}",
    );
}

/// An option that is not deprecated must not warn, so the assertion
/// above is about this option rather than about any run at all.
#[test]
fn an_ordinary_run_warns_about_nothing() {
    let stderr = stderr_until(
        &[],
        "is deprecated",
        // Nothing to wait for; just long enough for the daemon to have
        // printed anything it was going to.
        std::time::Duration::from_secs(3),
    );
    assert!(
        !stderr.contains("is deprecated"),
        "nothing deprecated was used; stderr was: {stderr}",
    );
}

/// A config file whose bytes are not valid UTF-8 must still be read.
/// Before the fix the whole file was discarded as though it were
/// missing, so every setting in it silently reverted to its default.
#[test]
fn a_non_utf8_config_file_is_still_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("dcroxide.conf");
    let mut f = std::fs::File::create(&path).expect("create config");
    // A comment carrying one invalid byte, then a real setting whose
    // effect is observable on stderr.
    f.write_all(b"# note \xff\nnodnsseed=1\n")
        .expect("write config");
    drop(f);

    let stderr = stderr_until(
        &[format!("--configfile={}", path.display())],
        "is deprecated",
        std::time::Duration::from_secs(20),
    );
    assert!(
        stderr.contains("--nodnsseed option is deprecated"),
        "the setting after the invalid byte never took effect, so the file was \
         discarded; stderr was: {stderr}",
    );
}
